FROM node:22-bookworm-slim AS ui-builder
WORKDIR /build/ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY ui/ ./
RUN npm run build

FROM rust:1.89-bookworm AS rust-builder
WORKDIR /build
RUN cargo install cargo-auditable --locked
COPY Cargo.toml Cargo.lock build.rs ./
COPY migrations ./migrations
COPY sdks ./sdks
COPY src ./src
COPY --from=ui-builder /build/ui/dist ./ui/dist
RUN RUSTFLAGS="-C force-unwind-tables=no -C link-arg=-Wl,-z,pack-relative-relocs -C link-arg=-Wl,--as-needed --remap-path-prefix=/build=. --remap-path-prefix=/usr/local/cargo=cargo" \
    cargo auditable build --release --locked

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --create-home bugfinder && \
    mkdir -p /data && chown 10001:10001 /data
COPY --from=rust-builder /build/target/release/bugfinder /usr/local/bin/bugfinder
USER 10001
ENV BUGFINDER_BIND=0.0.0.0:8080 \
    BUGFINDER_DATA_DIR=/data \
    BUGFINDER_ENV=production
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/bugfinder", "healthcheck", "--url", "http://127.0.0.1:8080/api/health"]
ENTRYPOINT ["/usr/local/bin/bugfinder", "--headless"]
