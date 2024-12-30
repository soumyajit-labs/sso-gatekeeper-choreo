#!/usr/bin/env bash
gunicorn --log-level debug -w 4 -b 0.0.0.0:5000 wsgi:application