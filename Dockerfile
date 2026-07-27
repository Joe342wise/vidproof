FROM python:3.12-slim

WORKDIR /app

# OpenCV headless needs libGL; TSA needs openssl CLI
RUN apt-get update && apt-get install -y --no-install-recommends \
        libgl1 \
        libglib2.0-0 \
        openssl \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps from all modules in one layer
COPY backend/requirements.txt     /tmp/req-backend.txt
COPY forensics/requirements.txt   /tmp/req-forensics.txt
COPY dashboard/requirements.txt   /tmp/req-dashboard.txt
RUN pip install --no-cache-dir \
        -r /tmp/req-backend.txt \
        -r /tmp/req-forensics.txt \
        -r /tmp/req-dashboard.txt

COPY . .
