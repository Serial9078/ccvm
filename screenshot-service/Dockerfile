FROM mcr.microsoft.com/playwright:v1.54.1-noble

WORKDIR /app

COPY package.json ./

RUN npm install --omit=dev

COPY server.js ./

ENV PORT=3001
ENV SCREENSHOT_DIR=/data/screenshots
ENV NAVIGATION_TIMEOUT_MS=30000
ENV MAX_CONCURRENT_PAGES=2

EXPOSE 3001

CMD ["npm", "start"]
