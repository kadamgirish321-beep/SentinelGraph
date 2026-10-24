# Multi-stage build for AttackGraphX React Frontend
FROM node:20-alpine AS build

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# Production server
FROM nginx:1.25-alpine

COPY --from=build /app/dist /usr/share/nginx/html

# Custom nginx configuration for SPA routing
RUN printf 'server {\n\
    listen 5173;\n\
    location / {\n\
        root /usr/share/nginx/html;\n\
        index index.html index.htm;\n\
        try_files $uri $uri/ /index.html;\n\
    }\n\
}\n' > /etc/nginx/conf.d/default.conf

EXPOSE 5173

CMD ["nginx", "-g", "daemon off;"]
