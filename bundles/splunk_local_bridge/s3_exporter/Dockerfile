FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY export_splunk_to_s3.py .
RUN useradd -r -u 10001 exporter && mkdir -p /state && chown -R exporter:exporter /state /app
USER exporter

ENTRYPOINT ["python", "/app/export_splunk_to_s3.py"]
