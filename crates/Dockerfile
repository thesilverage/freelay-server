FROM rust:1.98-slim-trixie AS builder
WORKDIR /build
COPY . .
RUN cargo build --locked --release -p freelay-server

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && useradd --system --uid 10001 freelay && mkdir -p /data && chown freelay /data
WORKDIR /data
COPY --from=builder /build/target/release/freelay /usr/local/bin/freelay
USER freelay
EXPOSE 8080
ENTRYPOINT ["freelay"]
CMD ["serve", "--config", "/config/freelay.toml"]
