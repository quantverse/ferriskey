FROM rust:1.95.0-bookworm AS chef

WORKDIR /usr/local/src/ferriskey

RUN cargo install cargo-chef --version 0.1.77 --locked && \
    cargo install sqlx-cli --version 0.8.6 --no-default-features --features postgres --locked

# ── Planner: analyse the workspace and produce recipe.json ────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Builder: cook deps first (cached), then build real source ─────────────────
FROM chef AS builder

COPY --from=planner /usr/local/src/ferriskey/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
RUN cargo build --release

# ── Shared runtime base ───────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates=20230311+deb12u1 \
    libssl3=3.0.17-1~deb12u2 && \
    rm -rf /var/lib/apt/lists/* && \
    addgroup \
    --system \
    --gid 1000 \
    ferriskey && \
    adduser \
    --system \
    --no-create-home \
    --disabled-login \
    --uid 1000 \
    --gid 1000 \
    ferriskey

USER ferriskey

# ── API image ─────────────────────────────────────────────────────────────────
FROM runtime AS api

COPY --from=builder /usr/local/src/ferriskey/target/release/ferriskey-api /usr/local/bin/
COPY --from=builder /usr/local/src/ferriskey/core/migrations /usr/local/src/ferriskey/migrations
COPY --from=builder /usr/local/cargo/bin/sqlx /usr/local/bin/

EXPOSE 80

ENTRYPOINT ["ferriskey-api"]

# ── Operator image ────────────────────────────────────────────────────────────
FROM runtime AS operator

COPY --from=builder /usr/local/src/ferriskey/target/release/ferriskey-operator /usr/local/bin/

EXPOSE 80

ENTRYPOINT ["ferriskey-operator"]

# ── Frontend build ────────────────────────────────────────────────────────────
FROM node:20.14.0-alpine AS webapp-build

WORKDIR /usr/local/src/ferriskey

ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"

RUN \
    corepack enable && \
    corepack prepare pnpm@9.15.0 --activate && \
    apk --no-cache add dumb-init=1.2.5-r3

COPY front/package.json front/pnpm-lock.yaml ./

RUN pnpm install --frozen-lockfile

COPY front/ .

# Cap proof-of-work captcha endpoint, baked in at build time. When empty the
# CapCaptcha widget renders nothing (captcha effectively disabled on the front).
# Point this at the Cap server's site URL, e.g. http://localhost:3000/<site-key>/
ARG VITE_CAP_API_ENDPOINT=""

RUN VITE_API_URL="" VITE_CAP_API_ENDPOINT="$VITE_CAP_API_ENDPOINT" pnpm run build

# ── Frontend runtime ──────────────────────────────────────────────────────────
FROM nginxinc/nginx-unprivileged:1.31.1-alpine3.23-slim AS webapp

COPY --from=webapp-build /usr/local/src/ferriskey/dist /usr/local/src/ferriskey
COPY front/nginx.conf /etc/nginx/conf.d/default.conf
COPY --chmod=0755 front/docker-entrypoint.sh /docker-entrypoint.d/docker-entrypoint.sh

USER root

# Remove default files and ensure the runtime user (101) can write to the html directory
RUN rm -f /usr/share/nginx/html/50x.html /usr/share/nginx/html/index.html && \
    chown -R 101:101 /usr/share/nginx/html

USER 101

# ── Standalone image (API + Frontend, single container) ───────────────────────
FROM debian:bookworm-slim AS standalone

# hadolint ignore=DL3008
RUN \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates=20230311+deb12u1 \
    libssl3=3.0.17-1~deb12u2 \
    nginx \
    supervisor && \
    rm -rf /var/lib/apt/lists/* && \
    rm -f /etc/nginx/sites-enabled/default

COPY --from=builder /usr/local/src/ferriskey/target/release/ferriskey-api /usr/local/bin/
COPY --from=builder /usr/local/src/ferriskey/core/migrations /usr/local/src/ferriskey/migrations
COPY --from=builder /usr/local/cargo/bin/sqlx /usr/local/bin/
COPY --from=webapp-build /usr/local/src/ferriskey/dist /usr/share/nginx/html

COPY front/nginx-standalone.conf /etc/nginx/conf.d/default.conf
COPY docker/supervisord.conf /etc/supervisor/conf.d/ferriskey.conf
COPY --chmod=0755 docker/standalone-entrypoint.sh /standalone-entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/standalone-entrypoint.sh"]
