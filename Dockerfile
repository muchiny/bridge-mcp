# Stage 1: Build
#
# Keep this tag at the MSRV in Cargo.toml / rust-toolchain.toml. `COPY . .`
# below brings the toolchain file into the image, and a toolchain file outranks
# the image's own compiler — so if this tag drifts below the MSRV, rustup
# silently downloads the pinned version on every build and the pin here is
# inert. Matching versions keeps the pin honest and the build offline.
FROM rust:1.98-alpine AS builder

RUN apk add --no-cache musl-dev pkgconfig

WORKDIR /app
COPY . .

# `--features full` (cli, mimalloc, http, jq, otel) — the default feature set is
# `cli` alone, which ships without the HTTP transport and without jq/yq output
# filtering, i.e. without the two capabilities the README and the server card
# advertise. `make release` has always used `full`; the image did not.
RUN cargo build --release --features full

# Stage 2: Runtime
FROM alpine:3.20

RUN apk add --no-cache ca-certificates openssh-client \
    && adduser -D -h /home/bridge bridge

COPY --from=builder /app/target/release/bridge-mcp /usr/local/bin/
COPY config/config.example.yaml /etc/bridge-mcp/config.example.yaml

USER bridge

ENTRYPOINT ["bridge-mcp"]
