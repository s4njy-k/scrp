# syntax=docker/dockerfile:1.7
# Optional Scrapling alternate adapter (profile: scrapling). Base pinned by digest.
ARG PYTHON_IMAGE=python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c
FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
WORKDIR /app
COPY scrapling-worker/requirements.lock ./requirements.lock
RUN pip install --no-cache-dir --require-hashes --no-deps -r requirements.lock \
 && python -m playwright install --with-deps chromium \
 && rm -rf /var/lib/apt/lists/* /root/.cache
COPY scrapling-worker/collector_scrapling ./collector_scrapling
RUN groupadd --gid 10001 collector && useradd --uid 10001 --gid collector --no-create-home --shell /usr/sbin/nologin collector \
 && chmod -R a+rX /opt/ms-playwright
USER 10001:10001
ENTRYPOINT ["python", "-m", "collector_scrapling"]
