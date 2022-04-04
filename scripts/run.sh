#!/bin/sh

set -e

# remenber to also change the run command in the dev compose file
while ! python manage.py sqlflush > /dev/null 2>&1 ;do
  echo "Waiting for the db to be ready."
  sleep 1
done


python manage.py collectstatic --noinput
python manage.py migrate
python manage.py loaddata contenttypes permissions groups admin_user


uwsgi --socket :9000 --workers 4 --master --enable-threads --module ticketcontrol.wsgi
