server {
    listen ${LISTEN_PORT};


    location /static {
        alias /vol/static;
    }
    
    location /serve_attachment {
        internal;
        alias /uploads/;
    }

    location / {
        uwsgi_pass              ${APP_HOST}:${APP_PORT};
        include                 /etc/nginx/uwsgi_params;
        client_max_body_size    ${MAX_REQUEST_SIZE};
    }

}
