FROM node:26.12.1-alpine@sha256:40cd011b55415bc894e45b02fdd5a5dfde056921b7d23a64c74f80497af48797 AS build
WORKDIR /app
COPY package*.json tsconfig*.json ./
RUN npm ci
COPY src ./src
COPY web ./web
COPY vite.config.ts ./
RUN npm run build
FROM node:26.12.1-alpine@sha256:40cd011b55415bc894e45b02fdd5a5dfde056921b7d23a64c74f80497af48797
WORKDIR /app
ENV NODE_ENV=production HOST=0.0.0.0 PORT=3001
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist
COPY --from=build /app/web-dist ./web-dist
COPY migrations ./migrations
RUN mkdir -p /app/.data/mail && chown -R node:node /app/.data
USER node
EXPOSE 3001
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s CMD node -e "fetch('http://127.0.0.1:3001/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/src/server.js"]
