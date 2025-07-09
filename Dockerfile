FROM node:18-alpine

# Install FFmpeg with HTTPS support
RUN apk add --no-cache ffmpeg ca-certificates

WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .

EXPOSE 3000
CMD ["node", "server.js"]