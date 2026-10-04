FROM node:20-slim AS builder

WORKDIR /app
COPY package.json ./
RUN npm install

COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY <<'NGINX' /etc/nginx/conf.d/default.conf
server {
    listen 3000;
    root /usr/share/nginx/html;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api {
        proxy_pass http://host.docker.internal:4001;
        proxy_set_header Host $host;
    }
}
NGINX

EXPOSE 3000
CMD ["nginx", "-g", "daemon off;"]
