# Backend

The backend is written using [PostgREST](https://postgrest.org/en/stable/).

## Dependencies

- [PostgreSQL 14+](https://www.postgresql.org/) with binaries in your path (`export PATH=/usr/lib/postgresql/14/bin/:$PATH` on Ubuntu). PostgreSQL does not need to be running.
- plpython3u: not included in brew's postgres package. On macOS, you can install [EDB's PostgreSQL distribution](https://www.postgresql.org/download/macosx/) and then install plpython3u using the included "Application Stack Builder" app.
- pgcrypto (found in postgres-contrib, often included when you install postgres)
- [postgrest](https://postgrest.org/en/stable/)

## Environment variables

- `TRANSONTARIO_DISCORD_CLIENT_ID`: obtained from https://discord.com/developers/applications
- `TRANSONTARIO_DISCORD_SECRET`: obtained from https://discord.com/developers/applications
- `TRANSONTARIO_JWT_SECRET`: any string (needs to match what's in `./postgrest.conf`)
- `TRANSONTARIO_DISCORD_REDIRECT`: you probably want http://localhost:3001/oauth

## Running in development mode

- Run `./init.sh` to create a database.
- Run `./start.sh` with the above environment variables set.
- The database is stored in `db` under this folder. You can `rm -fr ./db` to remove the database
- You can use the Dockerfile if you don't want to set up the above.
