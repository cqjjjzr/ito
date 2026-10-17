FROM docker.io/library/node:24-trixie-slim AS web
WORKDIR /src/web
COPY docs/modules/ROOT/attachments/openapi.json /src/docs/modules/ROOT/attachments/
COPY web ./
RUN corepack enable && pnpm install --frozen-lockfile && pnpm build

FROM docker.io/library/rust:1.99-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY --from=web /src/web/dist ./web/dist
RUN cargo build --release --locked -p ito

FROM docker.io/library/debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iproute2 wireguard-tools \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/ito /usr/local/bin/ito
COPY LICENSE.txt THIRD_PARTY_NOTICES.md config.default.toml config.schema.json /usr/share/doc/ito/
ENTRYPOINT ["/usr/local/bin/ito"]
CMD ["--config", "/etc/ito/config.toml"]
