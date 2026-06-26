FROM node:20-slim

ENV NODE_ENV=production \
    NPM_CONFIG_LOGLEVEL=warn

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.js ./
COPY public ./public

EXPOSE 8000

# Bind to 0.0.0.0 on $PORT (defaults to 8000)
CMD ["sh", "-c", "node server.js"]