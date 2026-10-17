# Exposure Desk container image (Linux x64). Usage, data volume, dashboard access and the browser sandbox note: docs/LINUX.md.
# The base is pinned by digest: the official Node.js 24.18.1 image on Debian 12 (bookworm), the same Node.js version as the Windows and Linux packages.
ARG NODE_IMAGE=node:24.18.1-bookworm-slim@sha256:235600a8101ab264e117b1768e925532262668dc9b581ef1dd7d96ced463b8e7

FROM ${NODE_IMAGE} AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates unzip xz-utils \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY package.json package-lock.json ./
# Exactly the locked dependencies; no install scripts run.
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY . .
# The build writes BUILD_INFO.json, so the doctor can prove file parity inside the image.
# Chrome for Testing and Gitleaks come from their official sources and are checksum-verified (scripts/fetch-linux-distributions.mjs).
RUN node scripts/build.mjs \
 && node scripts/fetch-linux-distributions.mjs --browser /opt/exposure/browser --tools /opt/exposure/tools --summary /opt/exposure/distributions.json

FROM ${NODE_IMAGE}
LABEL org.opencontainers.image.title="Exposure Desk" \
      org.opencontainers.image.description="Local website secret-exposure scanner (authorized targets only)" \
      org.opencontainers.image.licenses="LicenseRef-Proprietary"
COPY --from=build /src /app
COPY --from=build /opt/exposure/browser /app/browser
COPY --from=build /opt/exposure/tools/ /app/tools/
COPY --from=build /opt/exposure/distributions.json /app/LINUX_DISTRIBUTIONS.json
# The OS libraries Chromium needs (Playwright's own list for this browser) and tini, which reaps child processes as PID 1.
# The application files belong to root and are read-only for the runtime user; all writable state lives in the /data volume.
RUN apt-get update \
 && node /app/node_modules/playwright/cli.js install-deps chromium \
 && apt-get install -y --no-install-recommends tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 exposure \
 && useradd --system --uid 10001 --gid 10001 --home-dir /data --no-create-home --shell /usr/sbin/nologin exposure \
 && mkdir -p /data \
 && chown exposure:exposure /data \
 && chmod 0700 /data \
 && chmod -R a-w /app
# EXPOSURE_BROWSER_NO_SANDBOX=1: the default container seccomp profile blocks the user namespaces Chromium's sandbox needs, so the container
# is the isolation boundary instead (docs/LINUX.md). The dashboard always listens on 127.0.0.1 inside the container.
ENV NODE_ENV=production \
    EXPOSURE_DATA_DIR=/data \
    EXPOSURE_NO_OPEN=1 \
    EXPOSURE_BROWSER_NO_SANDBOX=1 \
    HOME=/data
VOLUME ["/data"]
WORKDIR /data
USER exposure:exposure
ENTRYPOINT ["/usr/bin/tini", "--", "node", "/app/dist/src/cli.js"]
CMD ["help"]
