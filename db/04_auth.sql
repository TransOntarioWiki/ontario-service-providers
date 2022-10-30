CREATE LANGUAGE plpython3u;
CREATE EXTENSION pgcrypto;

GRANT SELECT ON discord_user TO web_anon;
GRANT INSERT ON discord_user TO web_anon;
GRANT UPDATE ON discord_user TO web_anon;

CREATE OR REPLACE FUNCTION discord_client_id ()
  RETURNS text
AS $$
  import os
  return os.getenv('TRANSONTARIO_DISCORD_CLIENT_ID')
$$ LANGUAGE plpython3u;

CREATE OR REPLACE FUNCTION discord_oauth_redirect ()
  RETURNS text
AS $$
  import os
  return os.getenv('TRANSONTARIO_DISCORD_REDIRECT')
$$ LANGUAGE plpython3u;

CREATE VIEW api.discord_application AS SELECT discord_client_id() AS client_id, discord_oauth_redirect() AS redirect_uri;
GRANT SELECT ON api.discord_application TO web_anon;

CREATE OR REPLACE FUNCTION url_encode(data bytea) RETURNS text LANGUAGE sql AS $$
    SELECT translate(encode(data, 'base64'), E'+/=\n', '-_');
$$ IMMUTABLE;


CREATE OR REPLACE FUNCTION url_decode(data text) RETURNS bytea LANGUAGE sql AS $$
WITH t AS (SELECT translate(data, '-_', '+/') AS trans),
     rem AS (SELECT length(t.trans) % 4 AS remainder FROM t) -- compute padding size
    SELECT decode(
        t.trans ||
        CASE WHEN rem.remainder > 0
           THEN repeat('=', (4 - rem.remainder))
           ELSE '' END,
    'base64') FROM t, rem;
$$ IMMUTABLE;


CREATE OR REPLACE FUNCTION algorithm_sign(signables text, secret text, algorithm text)
RETURNS text LANGUAGE sql AS $$
WITH
  alg AS (
    SELECT CASE
      WHEN algorithm = 'HS256' THEN 'sha256'
      WHEN algorithm = 'HS384' THEN 'sha384'
      WHEN algorithm = 'HS512' THEN 'sha512'
      ELSE '' END AS id)  -- hmac throws error
SELECT url_encode(hmac(signables, secret, alg.id)) FROM alg;
$$ IMMUTABLE;


CREATE OR REPLACE FUNCTION sign(payload json, secret text, algorithm text DEFAULT 'HS256')
RETURNS text LANGUAGE sql AS $$
WITH
  header AS (
    SELECT url_encode(convert_to('{"alg":"' || algorithm || '","typ":"JWT"}', 'utf8')) AS data
    ),
  payload AS (
    SELECT url_encode(convert_to(payload::text, 'utf8')) AS data
    ),
  signables AS (
    SELECT header.data || '.' || payload.data AS data FROM header, payload
    )
SELECT
    signables.data || '.' ||
    algorithm_sign(signables.data, secret, algorithm) FROM signables;
$$ IMMUTABLE;


CREATE OR REPLACE FUNCTION verify(token text, secret text, algorithm text DEFAULT 'HS256')
RETURNS table(header json, payload json, valid boolean) LANGUAGE sql AS $$
  SELECT
    convert_from(url_decode(r[1]), 'utf8')::json AS header,
    convert_from(url_decode(r[2]), 'utf8')::json AS payload,
    r[3] = algorithm_sign(r[1] || '.' || r[2], secret, algorithm) AS valid
  FROM regexp_split_to_array(token, '\.') r;
$$ IMMUTABLE;

CREATE OR REPLACE FUNCTION do_auth ()
  RETURNS trigger
AS $$
  from urllib import request
  from urllib.error import URLError
  from urllib.parse import urlencode
  import os
  import json
  import ssl

  ctx = ssl.create_default_context()
  ctx.check_hostname = False
  ctx.verify_mode = ssl.CERT_NONE

  code = TD['new']['code']
  req = request.Request("https://discord.com/api/oauth2/token")

  body = {
    "client_id": os.getenv('TRANSONTARIO_DISCORD_CLIENT_ID'),
    "client_secret": os.getenv('TRANSONTARIO_DISCORD_SECRET'),
    "grant_type": "authorization_code",
    "code": code,
    "redirect_uri": os.getenv('TRANSONTARIO_DISCORD_REDIRECT'),
    "scope": "identify guilds.members.read"
  }
  query = urlencode(body)
  queryasbytes = query.encode('utf-8')   # needs to be bytes
  req.add_header('Content-Length', len(queryasbytes))
  req.add_header('User-Agent', "curl/7.79.1")
  try:
    response = request.urlopen(req, queryasbytes, context=ctx)
  except URLError as e:
    print(e)
    print(e.fp.read())
    raise Exception("Unauthorized")

  access_token = json.load(response)["access_token"]

  req = request.Request("https://discord.com/api/users/@me/guilds/886244497346940948/member")
  req.add_header("Authorization", "Bearer " + access_token)
  req.add_header('User-Agent', "curl/7.79.1")
  try:
    response = request.urlopen(req, context=ctx)
  except URLError as e:
    print(e)
    print(e.fp.read())
    raise Exception("Unauthorized")

  print(response)
  member = json.load(response)
  roles = member["roles"]

  # Check if the user is level 2
  if "999736008058867823" not in roles:
    raise Exception("Unauthorized")

  plan = plpy.prepare("insert into discord_user values($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET username=$2, discriminator=$3, avatar=$4", [
    "text", "text", "text", "text"])
  plpy.execute(plan, [
    member["user"]["id"],
    member["user"]["username"],
    member["user"]["discriminator"],
    member["avatar"] or member["user"]["avatar"],
  ])

  plan = plpy.prepare("SELECT sign($1, $2) AS jwt", ["json", "text"])
  jwt = plpy.execute(plan, [
    json.dumps({"role": "editor", "id": member["user"]["id"], "source": "discord"}),
    os.getenv('TRANSONTARIO_JWT_SECRET')
  ])

  TD['new']['bearer'] = jwt[0]["jwt"]

  return "MODIFY"
$$ LANGUAGE plpython3u;

CREATE VIEW api.auth AS SELECT NULL AS code, NULL AS bearer;

DROP TRIGGER auth ON api.auth;
CREATE TRIGGER auth
INSTEAD OF INSERT OR UPDATE OR DELETE ON api.auth
    FOR EACH ROW EXECUTE PROCEDURE do_auth();

GRANT SELECT ON api.auth TO web_anon;
GRANT INSERT ON api.auth TO web_anon;
