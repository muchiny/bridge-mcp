# Stage 1: Build
FROM rust:1.93-alpine AS builder

RUN apk add --no-cache musl-dev pkgconfig

WORKDIR /app
COPY . .

RUN cargo build --release

# Stage 2: Runtime
FROM alpine:3.20

RUN apk add --no-cache ca-certificates openssh-client \
    && adduser -D -h /home/bridge bridge

COPY --from=builder /app/target/release/bridge-mcp /usr/local/bin/
COPY config/config.example.yaml /etc/bridge-mcp/config.example.yaml

USER bridge

ENTRYPOINT ["bridge-mcp"]
