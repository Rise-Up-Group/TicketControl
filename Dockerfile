FROM python:3.9.10-alpine3.15
LABEL maintainer="https://github.com/Rise-Up-Group"

ENV PYTHONUNBUFFERED 1

COPY ./requirements.txt  /requirements.txt
COPY ./app /app
COPY /scripts /scripts

WORKDIR /app
EXPOSE 8000

# use venv to seperate dependencies of python of those of alpine
# use non root user for security
RUN python -m venv /py && \
    /py/bin/pip install --upgrade pip && \
    apk add --update --no-cache --virtual .tmp-deps \
        linux-headers build-base musl-dev && \
    /py/bin/pip install -r /requirements.txt && \
    apk del .tmp-deps && \
    adduser --disabled-password --no-create-home app && \
    mkdir -p /vol/web/static && \
    mkdir -p /vol/web/media && \
    chown -R app:app /vol && \
    chmod -R 755 /vol/ && \
    chmod -R +x /scripts

ENV PATH="/scripts:/py/bin:$PATH"

USER app

CMD ["run.sh"]
