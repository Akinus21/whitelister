import os
import ipaddress
import json
import subprocess
import toml
from flask import Flask, request, jsonify
import duo_client

app = Flask(__name__)

STATE_FILE = "/config/whitelist-users.toml"
STATIC_IPS = ["178.105.18.55", "167.233.135.235"]
CONTAINER_NAME = "crowdsec"
ALLOWLIST_NAME = "self-whitelist"

DUO_IKEY = os.environ["DUO_IKEY"]
DUO_SKEY = os.environ["DUO_SKEY"]
DUO_HOST = os.environ["DUO_HOST"]

duo_auth = duo_client.Auth(ikey=DUO_IKEY, skey=DUO_SKEY, host=DUO_HOST)


def load_state():
    if os.path.exists(STATE_FILE):
        return toml.load(STATE_FILE)
    return {}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        toml.dump(state, f)


def ensure_allowlist_exists():
    result = subprocess.run(
        ["docker", "exec", CONTAINER_NAME, "cscli", "allowlists", "inspect", ALLOWLIST_NAME],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "cscli", "allowlists", "create",
             ALLOWLIST_NAME, "-d", "whitelist-updater managed"],
            capture_output=True, text=True,
        )


def sync_allowlist(state):
    """Reconcile the CrowdSec allowlist with current state + static IPs.
    Allowlist entries override active decisions (incl. range bans),
    unlike the parser-level whitelist which only prevents new alerts."""
    ensure_allowlist_exists()

    desired_ips = set(STATIC_IPS) | {e["ip"] for e in state.values() if "ip" in e}

    inspect = subprocess.run(
        ["docker", "exec", CONTAINER_NAME, "cscli", "allowlists", "inspect",
         ALLOWLIST_NAME, "-o", "json"],
        capture_output=True, text=True,
    )
    current_ips = set()
    if inspect.returncode == 0:
        try:
            data = json.loads(inspect.stdout)
            current_ips = {item["value"] for item in data.get("items", [])}
        except (ValueError, KeyError):
            pass

    for ip in desired_ips - current_ips:
        subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "cscli", "allowlists", "add",
             ALLOWLIST_NAME, ip, "-d", "whitelist-updater managed"],
            capture_output=True, text=True,
        )

    for ip in current_ips - desired_ips:
        subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "cscli", "allowlists", "remove",
             ALLOWLIST_NAME, ip],
            capture_output=True, text=True,
        )


def clear_active_decisions_for_ip(ip):
    """Explicitly delete any active CrowdSec decision that currently
    covers `ip` — including range-scoped bans (e.g. a /17 crawl ban
    from a shared Starlink CGNAT pool), which `cscli decisions delete
    --ip <ip>` does NOT match (it only matches exact IP-scoped
    decisions). This is belt-and-suspenders alongside the allowlist:
    the allowlist should prevent future bans and override active ones
    at query time, but this guarantees immediate relief regardless of
    whether that override is actually being honored end-to-end.

    Returns the list of decision IDs that were deleted.
    """
    try:
        target = ipaddress.ip_address(ip)
    except ValueError:
        app.logger.error(f"clear_active_decisions_for_ip: invalid IP {ip!r}")
        return []

    result = subprocess.run(
        ["docker", "exec", CONTAINER_NAME, "cscli", "decisions", "list", "-o", "json"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        app.logger.error(f"cscli decisions list failed: {result.stderr}")
        return []

    try:
        decisions = json.loads(result.stdout) or []
    except ValueError:
        # cscli sometimes prints a bare "null" for an empty result set
        decisions = []

    matched_ids = []
    for entry in decisions:
        # cscli decisions list -o json can return either a flat list of
        # decisions, or (depending on version) a list of alert objects
        # each containing a "decisions" array. Handle both shapes.
        sub_decisions = entry.get("decisions") if "decisions" in entry else [entry]
        for d in sub_decisions or []:
            value = d.get("value")
            if not value:
                continue
            try:
                if "/" in value:
                    network = ipaddress.ip_network(value, strict=False)
                    contained = target in network
                else:
                    contained = ipaddress.ip_address(value) == target
            except ValueError:
                continue
            if contained and d.get("id") is not None:
                matched_ids.append(d["id"])

    deleted = []
    for decision_id in matched_ids:
        del_result = subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "cscli", "decisions", "delete",
             "--id", str(decision_id)],
            capture_output=True, text=True,
        )
        if del_result.returncode == 0:
            deleted.append(decision_id)
        else:
            app.logger.error(f"Failed to delete decision {decision_id}: {del_result.stderr}")

    return deleted


def get_caller_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr


def get_authenticated_username():
    """Identity comes ONLY from Rivet, never from the request body.
    Caddy's rivet_auth forward_auth snippet verifies the API key against
    Rivet and forwards the resolved consumer name in Rivet-Key-Owner
    (confirmed via /verify: 200 OK, header 'rivet-key-owner: akinus').
    If that header is absent, the request didn't come through rivet_auth
    (e.g. someone hit the container directly) and must be rejected."""
    return request.headers.get("Rivet-Key-Owner")


def parse_device(body):
    device_name = body.get("device_name") or request.args.get("device_name")
    if not device_name:
        return None
    return device_name


def trigger_duo_push(username, device_name):
    try:
        result = duo_auth.auth(
            factor="push",
            username=username,
            device="auto",
            async_txn=False,
            pushinfo=f"device={device_name}",
        )
        return result.get("result") == "allow"
    except Exception as e:
        app.logger.error(f"Duo push failed for {username}: {e}")
        return False


@app.route("/update", methods=["POST"])
def update_whitelist():
    username = get_authenticated_username()
    if not username:
        app.logger.warning("Rejected request with no X-Rivet-Consumer header — not authenticated via rivet_auth")
        return jsonify({"error": "unauthenticated — request must go through rivet_auth"}), 401

    body = request.get_json(silent=True) or {}
    device_name = parse_device(body)
    if not device_name:
        return jsonify({"error": "device_name required"}), 400

    key = f"{username}-{device_name}"

    caller_ip = get_caller_ip()
    if not caller_ip:
        return jsonify({"error": "could not determine caller IP"}), 400

    state = load_state()
    is_new_entry = key not in state

    if is_new_entry:
        approved = trigger_duo_push(username, device_name)
        if not approved:
            return jsonify({"error": "Duo push denied or timed out"}), 403
    elif state[key]["ip"] == caller_ip:
        # IP unchanged since last beacon — still worth clearing any
        # decision that may have landed against it since then.
        cleared = clear_active_decisions_for_ip(caller_ip)
        return jsonify({
            "status": "unchanged",
            "key": key,
            "ip": caller_ip,
            "cleared_decisions": cleared,
        })

    state[key] = {"ip": caller_ip}
    save_state(state)
    sync_allowlist(state)
    cleared = clear_active_decisions_for_ip(caller_ip)

    return jsonify({
        "status": "registered" if is_new_entry else "updated",
        "key": key,
        "ip": caller_ip,
        "cleared_decisions": cleared,
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8300)
