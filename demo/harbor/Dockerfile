FROM node:22-alpine
WORKDIR /app
COPY harbor-server.js /app/harbor-server.js
EXPOSE 8880
ENV PORT=8880
CMD ["node", "/app/harbor-server.js"]
