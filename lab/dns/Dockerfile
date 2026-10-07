FROM alpine:3.20
RUN apk add --no-cache dnsmasq
COPY dnsmasq.conf /etc/dnsmasq.conf
CMD ["dnsmasq", "--keep-in-foreground", "--log-facility=-"]
