# syntax=docker/dockerfile:1.7
# Private browser engine: `playwright run-server` exposing a Playwright protocol
# endpoint ONLY on the internal acquisition network. Browsers come from the
# official image whose version matches playwright-core in package-lock.json
# (driver and engine versions must match exactly).
ARG PLAYWRIGHT_IMAGE=mcr.microsoft.com/playwright:v1.56.1-noble@sha256:f1e7e01021efd65dd1a2c56064be399f3e4de00fd021ac561325f2bfbb2b837a
FROM ${PLAYWRIGHT_IMAGE}
WORKDIR /srv/engine
COPY docker/browser-engine/package.json docker/browser-engine/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force
COPY docker/browser-engine/start.sh ./start.sh
# Non-root: Chromium's own sandbox stays enabled (requires the seccomp profile in compose).
USER pwuser
ENV HOME=/home/pwuser
EXPOSE 3000
ENTRYPOINT ["/bin/sh", "/srv/engine/start.sh"]
