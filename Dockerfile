# kustodyan-mcp — a self-contained image that serves the Kustodyan MCP server over
# streamable HTTP behind an nginx bearer-token gate, so it can be reached over the
# network by Claude Code, Cursor, and other MCP clients.
#
# The same binary also speaks stdio (the default) for local `npx`-style use; this
# image runs it in HTTP mode (KUSTODYAN_MCP_TRANSPORT=http) on a loopback port with
# nginx terminating auth in front.
#
# Public default pulls node:24-trixie-slim from Docker Hub. In CI with a registry
# pull-through cache, pass --build-arg REGISTRY=<cache-prefix>/ to route the base image.
ARG REGISTRY=

# ---- build stage: compile TypeScript, then drop dev deps ----
FROM ${REGISTRY}node:24-trixie-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
# --ignore-scripts: skip the `prepare` (tsc) lifecycle here — sources aren't copied yet;
# the explicit `npm run build` below compiles once src/ + tsconfig.json are present.
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

# ---- runtime stage ----
FROM ${REGISTRY}node:24-trixie-slim

# CACHEBUST_DAY (CI passes $(date +%Y%m%d)) invalidates this layer once per day so
# `apt upgrade` picks up freshly-published security patches.
ARG CACHEBUST_DAY=unset
# The trailing rm drops the npm CLI bundled in the node base image: nothing invokes
# npm/npx at runtime (start.sh execs node directly), and npm's vendored deps
# (tar, undici, brace-expansion) are this image's only fixable CVE findings.
RUN echo "cache day: ${CACHEBUST_DAY}" && \
    apt-get update && apt-get -y upgrade && \
    apt-get install -y --no-install-recommends nginx gettext-base tini ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./package.json
COPY nginx.conf.template /etc/nginx/nginx.conf.template
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh && \
    node -e "process.stdout.write(require('./package.json').version)" > /etc/image-version

# Runtime knobs (override at deploy):
#   MCP_BEARER_TOKEN        (required) gate token — Authorization: Bearer <t> or ?token=<t>
#   KUSTODYAN_IDENTITY_URL  (required) e.g. https://<env>.kustodyan.io/api/identity
#   KUSTODYAN_ENGINE_URL    (required) e.g. https://<env>.kustodyan.io/api/engine
#   KUSTODYAN_CLIENT_ID     (required) Engine API client id
#   KUSTODYAN_CLIENT_SECRET (required) Engine API client secret
#   KUSTODYAN_DATA_MODEL    (optional) path to a data-model manifest JSON
#   LISTEN_PORT / INTERNAL_PORT  gate (public) / bridge (loopback) ports
ENV KUSTODYAN_MCP_TRANSPORT=http \
    KUSTODYAN_HTTP_HOST=127.0.0.1 \
    KUSTODYAN_HTTP_PORT=9090 \
    LISTEN_PORT=8080 \
    INTERNAL_PORT=9090 \
    NODE_ENV=production \
    HOME=/tmp \
    npm_config_cache=/tmp/.npm

EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini", "--", "/app/start.sh"]
