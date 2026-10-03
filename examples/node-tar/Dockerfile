FROM node:24.21.0-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6

WORKDIR /opt/unpackproof-node-adapter
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY adapter.mjs ./adapter.mjs
RUN useradd --uid 10000 --user-group --create-home unpackproof \
  && chmod 0555 /opt/unpackproof-node-adapter/adapter.mjs
USER unpackproof
WORKDIR /fixture/destination
ENTRYPOINT ["node", "/opt/unpackproof-node-adapter/adapter.mjs"]
