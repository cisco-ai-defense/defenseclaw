FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY . /app/defenseclaw_pkg/
ENV PYTHONPATH="/app/defenseclaw_pkg:${PYTHONPATH}"

EXPOSE 4000

CMD ["litellm", "--config", "/app/config/litellm_config.yaml", "--port", "4000", "--host", "0.0.0.0"]
