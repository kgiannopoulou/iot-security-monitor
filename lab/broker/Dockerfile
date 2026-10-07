FROM eclipse-mosquitto:2
COPY mosquitto.conf /mosquitto/config/mosquitto.conf
# Lab-only credentials, shared by all simulated devices.
RUN mosquitto_passwd -b -c /mosquitto/config/passwd devices 'S3nsor!2026' \
 && chown mosquitto:mosquitto /mosquitto/config/passwd && chmod 0700 /mosquitto/config/passwd
