FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    libkrb5-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv

COPY pyproject.toml ./
COPY README.md .
COPY src/ ./src/

RUN uv pip install --system --no-cache .

ENTRYPOINT ["extloader"]
