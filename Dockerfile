FROM alpine:3.20

ARG TARGETARCH

RUN apk add --no-cache ca-certificates tzdata bash

WORKDIR /app

COPY dist/linux-$TARGETARCH/vproxy /app/vproxy
COPY config/config.example.json /app/config.example.json
COPY config/api_keys.example.txt /app/api_keys.example.txt
COPY config/models.json /app/models.json
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENV VPROXY_CONFIG=/app/config/config.json
ENV VPROXY_API_KEYS=/app/config/api_keys.txt
ENV VPROXY_MODELS=/app/config/models.json

EXPOSE 2156

ENTRYPOINT ["/app/entrypoint.sh"]
