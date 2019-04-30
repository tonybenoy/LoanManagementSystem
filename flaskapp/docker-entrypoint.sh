#!/bin/sh
flask db init
flask db migrate
flask db upgrade
/usr/local/bin/gunicorn -w 2 -b :8000 wsgi:app