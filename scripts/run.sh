#!/bin/sh

set -e

# may need to wait for database

python manage.py collectstatic --noinput
python manage.py migrate


uwsgi --socket :9000 --workers 4 --master --enable-threads --module app.wsgi
