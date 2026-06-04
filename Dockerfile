FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        whois libmagic1 libzbar0 ca-certificates build-essential \
        libssl-dev libffi-dev tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY ciberbot ./ciberbot
COPY yara_rules ./yara_rules

RUN useradd -r -m -d /home/bot bot \
    && mkdir -p /app/data /app/logs \
    && chown -R bot:bot /app

USER bot

EXPOSE 9090
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "ciberbot"]
