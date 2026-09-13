FROM python:3.12-slim
RUN pip install flask pyyaml toml duo_client
RUN apt-get update && apt-get install -y docker.io && rm -rf /var/lib/apt/lists/*
COPY app.py /app.py
CMD ["python", "/app.py"]
