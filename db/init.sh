#!/bin/bash
set -e -o pipefail
initdb -U transontario --locale=C -E UTF-8 ./db
pg_ctl -o "-p 5490" start -D ./db
createdb -p 5490 -U transontario transontario
psql -p 5490 -U transontario < ./01_schema.sql
psql -p 5490 -U transontario < ./02_rho.sql
psql -p 5490 -U transontario < ./03_api.sql
psql -p 5490 -U transontario < ./04_auth.sql
psql -p 5490 -U transontario < ./05.sql
psql -p 5490 -U transontario < ./06.sql
pg_ctl stop -D ./db

