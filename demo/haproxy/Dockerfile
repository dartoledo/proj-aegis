FROM docker.io/library/node:18-alpine
RUN apk add --no-cache haproxy socat openssl curl
WORKDIR /app
COPY hello-server.js /app/hello-server.js
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh && mkdir -p /etc/haproxy/certs /var/run/haproxy
EXPOSE 443 8443 8080
CMD ["/app/entrypoint.sh"]
