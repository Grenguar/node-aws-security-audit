# VULN: no pinned digest — tag can be overwritten (supply-chain risk)
FROM node:18

# VULN: secret passed as build arg — cached in image layers
ARG DB_PASSWORD

WORKDIR /app

COPY package*.json ./
# VULN: npm install instead of npm ci — non-deterministic builds
RUN npm install

COPY . .

# VULN: no USER directive — container runs as root
# VULN: no NODE_ENV=production — dev dependencies included, no optimisations
# VULN: no .dockerignore — copies .env, .git, node_modules into image

CMD ["node", "src/server.js"]
