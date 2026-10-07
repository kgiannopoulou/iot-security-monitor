FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 tcpdump \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Alerts reach `docker compose logs` as they happen, not when the buffer fills.
ENV PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY iotmon ./iotmon
ENTRYPOINT ["python", "-m", "iotmon"]
CMD ["--help"]
