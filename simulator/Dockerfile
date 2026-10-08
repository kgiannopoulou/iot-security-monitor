FROM python:3.12-slim
RUN pip install --no-cache-dir paho-mqtt==2.1.0 dnspython==2.7.0
# IoT device scripts (iot_devices.py, attacks.py) and OT ones (ot_devices.py,
# ot_attacks.py). The compose file picks which to run per container.
COPY iot_devices.py ot_devices.py ot_attacks.py /app/
WORKDIR /app
CMD ["python", "/app/iot_devices.py"]
