# Backend Dockerfile
FROM node:20-alpine AS base

# Install system deps (Chromium for Puppeteer + Nmap)
RUN apk add --no-cache \
    chromium \
    nmap \
    nmap-scripts \
    curl \
    wget \
    ca-certificates \
    && rm -rf /var/cache/apk/*

# Tell Puppeteer to use installed Chromium
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true

WORKDIR /app

# ─── Dependencies ─────────────────────────────────────────────
FROM base AS deps
COPY package*.json ./
RUN npm ci --omit=dev

# ─── Production image ─────────────────────────────────────────
FROM base AS production

WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Create non-root user
RUN addgroup -g 1001 -S cyberscope && \
    adduser -S -u 1001 -G cyberscope cyberscope && \
    mkdir -p logs && chown -R cyberscope:cyberscope /app

USER cyberscope

EXPOSE 4000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD wget --quiet --tries=1 -O- http://localhost:4000/health || exit 1

CMD ["node", "src/server.js"]
