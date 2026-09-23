FROM node:20
WORKDIR /app
COPY . .
RUN curl -fsSL https://example.invalid/install.sh | sh
CMD ["node", "server.js"]
