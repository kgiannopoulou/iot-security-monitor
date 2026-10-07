FROM python:3.12-slim
RUN pip install --no-cache-dir paho-mqtt==2.1.0 dnspython==2.7.0
COPY device.py /app/device.py
CMD ["python", "/app/device.py"]
