FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/cli

WORKDIR /app

COPY cli/defenseclaw /app/cli/defenseclaw
COPY bundles/c3_agent_tokenomics /app/bundles/c3_agent_tokenomics

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin appuser

USER 1000:1000

EXPOSE 8787

CMD ["python", "-m", "defenseclaw.c3_agent_tokenomics.mock_api", "--host", "0.0.0.0", "--port", "8787"]
