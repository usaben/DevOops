 FROM node:20-slim

ENV NODE_ENV=production \
    NPM_CONFIG_LOGLEVEL=warn

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY server.js ./
COPY public ./public

EXPOSE 8000

# Render / Railway / Fly: bind to $PORT (defaults to 8000)
CMD ["sh", "-c", "node server.js"]