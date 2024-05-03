#! /bin/sh

gunicorn --workers 5 --threads 8 --preload --timeout 0 run:app -b :1337