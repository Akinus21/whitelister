import os
import subprocess
import toml
import yaml
from flask import Flask, request, jsonify
import duo_client

app = Flask(__name__)

STATE_FILE = "/config/whitelist-users.toml"
CROWDSEC_WHITELIST_FILE = "/config/parsers/s02-enrich/self-whitelist.yaml"
STATIC_IPS = ["178.105.18.55", "167.233.135.235"]
CONTAINER_NAME = "crowdsec"

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


def regenerate_crowdsec_whitelist(state):
    device_ips = [entry["ip"] for entry in state.values() if "ip" in entry]
    ips = list(dict.fromkeys(STATIC_IPS + device_ips))

    data = {
        "name": "akinus21/self-whitelist",
        "description": "Whitelist events from my own infrastructure IPs",
        "whitelist": {"reason": "own infrastructure", "ip": ips},
    }

    with open(CROWDSEC_WHITELIST_FILE, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    subprocess.run(["docker", "restart", CONTAINER_NAME], capture_output=True)


def get_caller_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr


def parse_key(body):
    username = body.get("username") or request.args.get("username")
    device_name = body.get("device_name") or request.args.get("device_name")
    if not username or not device_name:
        return None, None, None
    return username, device_name, f"{username}-{device_name}"


def trigger_duo_push(username, device_name):
    """Blocking call — waits on the user's phone to approve/deny."""
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
    """Single endpoint. New user-device pair -> Duo push required.
    Existing pair -> IP replaced immediately, no push (beacon-friendly)."""
    body = request.get_json(silent=True) or {}
    username, device_name, key = parse_key(body)
    if not key:
        return jsonify({"error": "username and device_name required"}), 400

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
        return jsonify({"status": "unchanged", "key": key, "ip": caller_ip})

    state[key] = {"ip": caller_ip}
    save_state(state)
    regenerate_crowdsec_whitelist(state)

    return jsonify({
        "status": "registered" if is_new_entry else "updated",
        "key": key,
        "ip": caller_ip,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8300)
