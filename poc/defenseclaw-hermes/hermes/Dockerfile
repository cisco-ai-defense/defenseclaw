FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl jq && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir openai httpx

RUN useradd -m -s /bin/bash hermes
USER hermes
WORKDIR /home/hermes

COPY --chown=hermes:hermes test_agent.py /home/hermes/test_agent.py

VOLUME /data/hermes

ENTRYPOINT ["python", "/home/hermes/test_agent.py"]
