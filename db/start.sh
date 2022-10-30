#!/bin/bash
set -e -o pipefail

function finish {
  pg_ctl stop -D ./db
}
trap finish EXIT

pg_ctl -o "-p 5490" restart -D ./db
postgrest postgrest.conf
