# syntax=docker/dockerfile:1

FROM node:22-alpine AS web
WORKDIR /app
COPY client/package.json client/package-lock.json ./
RUN npm ci
COPY client/ ./
RUN npm run build

FROM rust:1.85-bookworm AS rust
WORKDIR /app
COPY server/Cargo.toml server/Cargo.lock ./
COPY server/migrations ./migrations
COPY server/src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=rust /app/target/release/io3233-server /app/io3233-server
COPY --from=web /app/dist /app/static
ENV STATIC_DIR=/app/static
ENV DATABASE_URL=sqlite:/app/data/data.db?mode=rwc
ENV BIND=0.0.0.0:3233
EXPOSE 3233
VOLUME ["/app/data"]
ENTRYPOINT ["/bin/sh", "-c", "mkdir -p /app/data && exec /app/io3233-server"]
