# syntax=docker/dockerfile:1.7
# Application image: coordinator, browser driver worker, egress gateway and analyst API roles.
# Base pinned by version AND digest (resolved 2026-10-17 from Docker Hub).
ARG NODE_IMAGE=node:22.22.0-bookworm-slim@sha256:dd9d21971ec4395903fa6143c2b9267d048ae01ca6d3ea96f16cb30df6187d94

FROM ${NODE_IMAGE} AS build
WORKDIR /app
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev --ignore-scripts

FROM ${NODE_IMAGE}
ENV NODE_ENV=production \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    ARTIFACT_ROOT=/data/artifacts \
    COLLECTOR_POLICY_PATH=/app/config/policy.yaml
# tini: init/signal handling. tesseract: selective OCR (one task at a time).
# No browsers in this image: the hardened profile drives a separate browser-engine container.
RUN apt-get update \
 && apt-get install -y --no-install-recommends tini ca-certificates tesseract-ocr tesseract-ocr-eng \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json package-lock.json ./
COPY db ./db
COPY config/policy.default.yaml ./config/policy.default.yaml
COPY config/policy.default.yaml ./config/policy.yaml
COPY config/brands.yaml ./config/brands.yaml
# Analyst console static files (served by `serve api` under a strict CSP).
COPY web ./web
COPY NOTICE THIRD_PARTY_NOTICES.md ./
RUN groupadd --gid 10001 collector \
 && useradd --uid 10001 --gid collector --no-create-home --shell /usr/sbin/nologin collector \
 && mkdir -p /data/artifacts && chown collector:collector /data/artifacts
USER 10001:10001
# -s: act as subreaper, so tini also works cleanly under Compose `init: true` (no PID-1 warning).
ENTRYPOINT ["/usr/bin/tini", "-s", "--", "node", "dist/cli.js"]
CMD ["serve", "coordinator"]
