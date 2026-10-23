FROM node:20-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc g++ coreutils \
    && rm -rf /var/lib/apt/lists/*

# node:20-slim already ships a non-root user 'node' (UID/GID 1000) -> reuse it.
# (Creating another user with UID 1000 fails: "UID 1000 is not unique".)

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY server.js runner.js ./
COPY demos ./demos
COPY analytics ./analytics

RUN chown -R node:node /app
USER node

ENV NODE_ENV=production
ENV PORT=4000
EXPOSE 4000

CMD ["node", "server.js"]
