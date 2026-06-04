FROM node:22-alpine AS build
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@10.28.1 --activate
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY ui/package.json ui/package.json
COPY packages/js/package.json packages/js/package.json
COPY packages/vue/package.json packages/vue/package.json
RUN pnpm install --frozen-lockfile=false
COPY ui ui
COPY packages packages
RUN pnpm --filter gatekeeper-ui build

FROM caddy:2-alpine
COPY ui/Caddyfile /etc/caddy/Caddyfile
COPY --from=build /app/ui/dist /srv
