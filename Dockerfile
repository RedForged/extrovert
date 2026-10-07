FROM node:26 AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --only=production

FROM node:26-slim
WORKDIR /app
# dumb-init: PID 1; opentype-sanitizer: validates + re-serializes uploaded
# profile fonts (ots-sanitize) before they are stored.
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends dumb-init opentype-sanitizer && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/node_modules ./node_modules
COPY . .
# Run as the unprivileged 'node' user (ASVS V10.2 / container hardening). The
# writable dirs are owned by that user; fresh named volumes inherit this.
RUN mkdir -p /app/data /app/uploads && chown -R node:node /app/data /app/uploads
USER node
EXPOSE 3000
VOLUME ["/app/data", "/app/uploads"]
ENV NODE_ENV=production
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "src/server.js"]
