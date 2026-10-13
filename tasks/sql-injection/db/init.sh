#!/bin/sh
set -eu
app_password="$(cat /run/lab/db-app-password.txt)"
lab_flag="$(cat /run/lab/flag.txt)"
case "$lab_flag" in KB2CTF\{*\}) ;; *) echo "Invalid lab configuration" >&2; exit 1 ;; esac
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --no-psqlrc --quiet \
 --set=ON_ERROR_STOP=1 --set=app_password="$app_password" --set=lab_flag="$lab_flag" \
 --file=/opt/lab/init.sql
