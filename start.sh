#!/usr/bin/env bash
gunicorn --bind 0.0.0.0:$PORT app_secured:app
