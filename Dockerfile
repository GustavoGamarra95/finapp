FROM nginx:alpine
COPY index.html manifest.json sw.js icon.svg /usr/share/nginx/html/
