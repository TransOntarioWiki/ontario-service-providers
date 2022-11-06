#!/bin/bash
set -e -o pipefail
initdb -U transontario --locale=C -E UTF-8 ./db
pg_ctl -o "-p 5490" start -D ./db
createdb -p 5490 -U transontario transontario
psql -p 5490 -U transontario < ./01_init.sql
psql -p 5490 -U transontario < ./02_review_timestamp.sql
pg_ctl stop -D ./db

