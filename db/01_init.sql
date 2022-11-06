--
-- PostgreSQL database cluster dump
--

SET default_transaction_read_only = off;

SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;

--
-- Roles
--

CREATE ROLE editor;
ALTER ROLE editor WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
CREATE ROLE transontario;
ALTER ROLE transontario WITH SUPERUSER INHERIT CREATEROLE CREATEDB LOGIN REPLICATION BYPASSRLS;
CREATE ROLE web_anon;
ALTER ROLE web_anon WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;

--
-- User Configurations
--








--
-- Databases
--

--
-- Database "template1" dump
--

\connect template1

--
-- PostgreSQL database dump
--

-- Dumped from database version 15.0
-- Dumped by pg_dump version 15.0

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- PostgreSQL database dump complete
--

--
-- Database "postgres" dump
--

\connect postgres

--
-- PostgreSQL database dump
--

-- Dumped from database version 15.0
-- Dumped by pg_dump version 15.0

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- PostgreSQL database dump complete
--

--
-- Database "transontario" dump
--

--
-- PostgreSQL database dump
--

-- Dumped from database version 15.0
-- Dumped by pg_dump version 15.0

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: transontario; Type: DATABASE; Schema: -; Owner: transontario
--

CREATE DATABASE transontario WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'C';


ALTER DATABASE transontario OWNER TO transontario;

\connect transontario

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: api; Type: SCHEMA; Schema: -; Owner: transontario
--

CREATE SCHEMA api;


ALTER SCHEMA api OWNER TO transontario;

--
-- Name: plpython3u; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS plpython3u WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpython3u; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpython3u IS 'PL/Python3U untrusted procedural language';


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: algorithm_sign(text, text, text); Type: FUNCTION; Schema: public; Owner: transontario
--

CREATE FUNCTION public.algorithm_sign(signables text, secret text, algorithm text) RETURNS text
    LANGUAGE sql IMMUTABLE
    AS $$
WITH
  alg AS (
    SELECT CASE
      WHEN algorithm = 'HS256' THEN 'sha256'
      WHEN algorithm = 'HS384' THEN 'sha384'
      WHEN algorithm = 'HS512' THEN 'sha512'
      ELSE '' END AS id)  -- hmac throws error
SELECT url_encode(hmac(signables, secret, alg.id)) FROM alg;
$$;


ALTER FUNCTION public.algorithm_sign(signables text, secret text, algorithm text) OWNER TO transontario;

--
-- Name: discord_client_id(); Type: FUNCTION; Schema: public; Owner: transontario
--

CREATE FUNCTION public.discord_client_id() RETURNS text
    LANGUAGE plpython3u
    AS $$
  import os
  return os.getenv('TRANSONTARIO_DISCORD_CLIENT_ID')
$$;


ALTER FUNCTION public.discord_client_id() OWNER TO transontario;

--
-- Name: discord_oauth_redirect(); Type: FUNCTION; Schema: public; Owner: transontario
--

CREATE FUNCTION public.discord_oauth_redirect() RETURNS text
    LANGUAGE plpython3u
    AS $$
  import os
  return os.getenv('TRANSONTARIO_DISCORD_REDIRECT')
$$;


ALTER FUNCTION public.discord_oauth_redirect() OWNER TO transontario;

--
-- Name: do_auth(); Type: FUNCTION; Schema: public; Owner: transontario
--

CREATE FUNCTION public.do_auth() RETURNS trigger
    LANGUAGE plpython3u
    AS $_$
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
$_$;


ALTER FUNCTION public.do_auth() OWNER TO transontario;

--
-- Name: post_review(); Type: FUNCTION; Schema: public; Owner: transontario
--

CREATE FUNCTION public.post_review() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    BEGIN
        IF (TG_OP = 'DELETE') THEN
            DELETE FROM review WHERE provider_id = OLD.provider_id and discord_user_id = (SELECT id FROM discord_user WHERE discord_user.username = OLD.username AND discord_user.discriminator = OLD.discriminator);
            IF NOT FOUND THEN RETURN NULL; END IF;
            RETURN OLD;
        ELSIF (TG_OP = 'UPDATE') THEN
            UPDATE review SET text = NEW.text, score = NEW.score WHERE provider_id = OLD.provider_id AND discord_user_id = (SELECT id FROM discord_user WHERE discord_user.username = OLD.username AND discord_user.discriminator = OLD.discriminator);
            IF NOT FOUND THEN RETURN NULL; END IF;
            RETURN NEW;
        ELSIF (TG_OP = 'INSERT') THEN
            INSERT INTO review VALUES(
	      NEW.provider_id, 
	      (current_setting('request.jwt.claims', true)::json->>'id'),
	      NEW.text,
	      NEW.score);
            RETURN NEW;
        END IF;
    END;
$$;


ALTER FUNCTION public.post_review() OWNER TO transontario;

--
-- Name: sign(json, text, text); Type: FUNCTION; Schema: public; Owner: transontario
--

CREATE FUNCTION public.sign(payload json, secret text, algorithm text DEFAULT 'HS256'::text) RETURNS text
    LANGUAGE sql IMMUTABLE
    AS $$
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
$$;


ALTER FUNCTION public.sign(payload json, secret text, algorithm text) OWNER TO transontario;

--
-- Name: update_provider(); Type: FUNCTION; Schema: public; Owner: transontario
--

CREATE FUNCTION public.update_provider() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE _provider_revision_id INTEGER;
BEGIN
	INSERT INTO provider_revision(
		provider_id,
		discord_user_id,
		timestamp,
		revision_index,
		source,
		slug,
		name,
		address,
		assessments_provided,
		description,
		email,
		hours_of_operation,
		phone,
		fsa,
		satellite_locations,
		fee_info,
		submitted_by,
		accessibility_available,
		website
	) VALUES (
		NEW.id,
	        (current_setting('request.jwt.claims', true)::json->>'id'),
		now(),
		COALESCE((select revision_index + 1 from provider_revision where provider_id = NEW.id order by revision_index desc limit 1), 1),
		CASE WHEN (TG_OP = 'UPDATE') THEN
		  OLD.source  -- cannot be changed
		ELSE 
		  NEW.source 
		END,
		NEW.slug,
		NEW.name,
		NEW.address,
		NEW.assessments_provided,
		NEW.description,
		NEW.email,
		NEW.hours_of_operation,
		NEW.phone,
		NEW.fsa,
		NEW.satellite_locations,
		NEW.fee_info,
		NEW.submitted_by,
		NEW.accessibility_available,
		NEW.website
	) RETURNING provider_revision.provider_revision_id INTO _provider_revision_id;

	INSERT INTO provider(
		id,
		source,
		slug,
		name,
		address,
		assessments_provided,
		description,
		email,
		hours_of_operation,
		phone,
		fsa,
		satellite_locations,
		fee_info,
		submitted_by,
		accessibility_available,
		website
	) VALUES (
		NEW.id,
		CASE WHEN (TG_OP = 'UPDATE') THEN
		  OLD.source  -- cannot be changed
		ELSE 
		  NEW.source 
		END,
		NEW.slug,
		NEW.name,
		NEW.address,
		NEW.assessments_provided,
		NEW.description,
		NEW.email,
		NEW.hours_of_operation,
		NEW.phone,
		NEW.fsa,
		NEW.satellite_locations,
		NEW.fee_info,
		NEW.submitted_by,
		NEW.accessibility_available,
		NEW.website
	) ON CONFLICT(id) DO UPDATE SET 
		source = CASE WHEN (TG_OP = 'UPDATE') THEN
		  OLD.source  -- cannot be changed
		ELSE 
		  NEW.source 
		END,
		slug = NEW.slug,
		name = NEW.name,
		address = NEW.address,
		assessments_provided = NEW.assessments_provided,
		description = NEW.description,
		email = NEW.email,
		hours_of_operation = NEW.hours_of_operation,
		phone = NEW.phone,
		fsa = NEW.fsa,
		satellite_locations = NEW.satellite_locations,
		fee_info = NEW.fee_info,
		submitted_by = NEW.submitted_by,
		accessibility_available = NEW.accessibility_available,
		website = NEW.website;

	INSERT INTO provider_revision_expertise(
		provider_revision_id,
		characteristic_id
	) SELECT
		_provider_revision_id,
		characteristic.id
	FROM UNNEST(NEW.specializes_in) AS characteristic_name
	LEFT JOIN characteristic ON characteristic.person_kind = characteristic_name;

	DELETE FROM provider_expertise WHERE provider_id = NEW.id;
	INSERT INTO provider_expertise(
		provider_id,
		characteristic_id
	) SELECT
		NEW.id,
		characteristic_id
	FROM provider_revision_expertise WHERE provider_revision_expertise.provider_revision_id = _provider_revision_id;

	INSERT INTO provider_revision_training(
		provider_revision_id,
		training_id
	) SELECT
		_provider_revision_id,
		rho_training.id
	FROM UNNEST(NEW.training) AS training_name
	LEFT JOIN rho_training ON rho_training.training_kind = training_name;

	DELETE FROM provider_training WHERE provider_id = NEW.id;
	INSERT INTO provider_training(
		provider_id,
		training_id
	) SELECT
		NEW.id,
		training_id
	FROM provider_revision_training WHERE provider_revision_training.provider_revision_id = _provider_revision_id;

	INSERT INTO provider_revision_referral_requirement(
		provider_revision_id,
		referral_requirement_id
	) SELECT
		_provider_revision_id,
		referral_requirement.id
	FROM UNNEST(NEW.referral_requirements) AS referral_requirement_name
	LEFT JOIN referral_requirement ON referral_requirement.referral_requirement_kind = referral_requirement_name;

	DELETE FROM provider_referral_requirement WHERE provider_id = NEW.id;
	INSERT INTO provider_referral_requirement(
		provider_id,
		referral_requirement_id
	) SELECT
		NEW.id,
		referral_requirement_id
	FROM provider_revision_referral_requirement WHERE provider_revision_referral_requirement.provider_revision_id = _provider_revision_id;

	INSERT INTO provider_revision_language(
		provider_revision_id,
		language_id
	) SELECT
		_provider_revision_id,
		language.id
	FROM UNNEST(NEW.languages) AS new_language_name
	LEFT JOIN language ON language.language_name = new_language_name;

	DELETE FROM provider_language WHERE provider_id = NEW.id;
	INSERT INTO provider_language(
		provider_id,
		language_id
	) SELECT
		NEW.id,
		language_id
	FROM provider_revision_language WHERE provider_revision_language.provider_revision_id = _provider_revision_id;

	INSERT INTO provider_revision_fee(
		provider_revision_id,
		fee_id
	) SELECT
		_provider_revision_id,
		fee.id
	FROM UNNEST(NEW.fees) AS fee_name
	LEFT JOIN fee ON fee.fee_kind = fee_name;

	DELETE FROM provider_fee WHERE provider_id = NEW.id;
	INSERT INTO provider_fee(
		provider_id,
		fee_id
	) SELECT
		NEW.id,
		fee_id
	FROM provider_revision_fee WHERE provider_revision_fee.provider_revision_id = _provider_revision_id;

	INSERT INTO provider_revision_service(
		provider_revision_id,
		service_id
	) SELECT
		_provider_revision_id,
		service.id
	FROM UNNEST(NEW.services) AS service_name
	LEFT JOIN service ON service.service_kind = service_name;

	DELETE FROM provider_service WHERE provider_id = NEW.id;
	INSERT INTO provider_service(
		provider_id,
		service_id
	) SELECT
		NEW.id,
		service_id
	FROM provider_revision_service WHERE provider_revision_service.provider_revision_id = _provider_revision_id;

	RETURN NEW;
END;
$$;


ALTER FUNCTION public.update_provider() OWNER TO transontario;

--
-- Name: url_decode(text); Type: FUNCTION; Schema: public; Owner: transontario
--

CREATE FUNCTION public.url_decode(data text) RETURNS bytea
    LANGUAGE sql IMMUTABLE
    AS $$
WITH t AS (SELECT translate(data, '-_', '+/') AS trans),
     rem AS (SELECT length(t.trans) % 4 AS remainder FROM t) -- compute padding size
    SELECT decode(
        t.trans ||
        CASE WHEN rem.remainder > 0
           THEN repeat('=', (4 - rem.remainder))
           ELSE '' END,
    'base64') FROM t, rem;
$$;


ALTER FUNCTION public.url_decode(data text) OWNER TO transontario;

--
-- Name: url_encode(bytea); Type: FUNCTION; Schema: public; Owner: transontario
--

CREATE FUNCTION public.url_encode(data bytea) RETURNS text
    LANGUAGE sql IMMUTABLE
    AS $$
    SELECT translate(encode(data, 'base64'), E'+/=\n', '-_');
$$;


ALTER FUNCTION public.url_encode(data bytea) OWNER TO transontario;

--
-- Name: verify(text, text, text); Type: FUNCTION; Schema: public; Owner: transontario
--

CREATE FUNCTION public.verify(token text, secret text, algorithm text DEFAULT 'HS256'::text) RETURNS TABLE(header json, payload json, valid boolean)
    LANGUAGE sql IMMUTABLE
    AS $$
  SELECT
    convert_from(url_decode(r[1]), 'utf8')::json AS header,
    convert_from(url_decode(r[2]), 'utf8')::json AS payload,
    r[3] = algorithm_sign(r[1] || '.' || r[2], secret, algorithm) AS valid
  FROM regexp_split_to_array(token, '\.') r;
$$;


ALTER FUNCTION public.verify(token text, secret text, algorithm text) OWNER TO transontario;

--
-- Name: auth; Type: VIEW; Schema: api; Owner: transontario
--

CREATE VIEW api.auth AS
 SELECT NULL::text AS code,
    NULL::text AS bearer;


ALTER TABLE api.auth OWNER TO transontario;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: characteristic; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.characteristic (
    id integer NOT NULL,
    person_kind text NOT NULL
);


ALTER TABLE public.characteristic OWNER TO transontario;

--
-- Name: characteristics; Type: VIEW; Schema: api; Owner: transontario
--

CREATE VIEW api.characteristics AS
 SELECT characteristic.person_kind AS characteristic
   FROM public.characteristic;


ALTER TABLE api.characteristics OWNER TO transontario;

--
-- Name: discord_application; Type: VIEW; Schema: api; Owner: transontario
--

CREATE VIEW api.discord_application AS
 SELECT public.discord_client_id() AS client_id,
    public.discord_oauth_redirect() AS redirect_uri;


ALTER TABLE api.discord_application OWNER TO transontario;

--
-- Name: fee; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.fee (
    id integer NOT NULL,
    fee_kind text NOT NULL
);


ALTER TABLE public.fee OWNER TO transontario;

--
-- Name: fees; Type: VIEW; Schema: api; Owner: transontario
--

CREATE VIEW api.fees AS
 SELECT fee.fee_kind AS fee
   FROM public.fee;


ALTER TABLE api.fees OWNER TO transontario;

--
-- Name: language; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.language (
    id integer NOT NULL,
    language_name text NOT NULL
);


ALTER TABLE public.language OWNER TO transontario;

--
-- Name: languages; Type: VIEW; Schema: api; Owner: transontario
--

CREATE VIEW api.languages AS
 SELECT language.language_name AS language
   FROM public.language;


ALTER TABLE api.languages OWNER TO transontario;

--
-- Name: discord_user; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.discord_user (
    id text NOT NULL,
    username text NOT NULL,
    discriminator text NOT NULL,
    avatar text
);


ALTER TABLE public.discord_user OWNER TO transontario;

--
-- Name: me; Type: VIEW; Schema: api; Owner: transontario
--

CREATE VIEW api.me AS
 SELECT discord_user.username,
    discord_user.discriminator,
    discord_user.avatar,
    discord_user.id
   FROM public.discord_user
  WHERE (discord_user.id = ((current_setting('request.jwt.claims'::text, true))::json ->> 'id'::text));


ALTER TABLE api.me OWNER TO transontario;

--
-- Name: fsa; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.fsa (
    fsa text NOT NULL,
    region text NOT NULL
);


ALTER TABLE public.fsa OWNER TO transontario;

--
-- Name: provider; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.provider (
    id integer NOT NULL,
    source text DEFAULT 'rho'::text NOT NULL,
    slug text NOT NULL,
    name text,
    address text,
    assessments_provided text,
    description text,
    email text,
    hours_of_operation text,
    phone text,
    fsa text,
    satellite_locations text,
    fee_info text,
    submitted_by text,
    accessibility_available integer,
    website text
);


ALTER TABLE public.provider OWNER TO transontario;

--
-- Name: provider_expertise; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.provider_expertise (
    provider_id integer NOT NULL,
    characteristic_id integer NOT NULL
);


ALTER TABLE public.provider_expertise OWNER TO transontario;

--
-- Name: provider_fee; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.provider_fee (
    provider_id integer NOT NULL,
    fee_id integer NOT NULL
);


ALTER TABLE public.provider_fee OWNER TO transontario;

--
-- Name: provider_language; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.provider_language (
    provider_id integer NOT NULL,
    language_id integer NOT NULL
);


ALTER TABLE public.provider_language OWNER TO transontario;

--
-- Name: provider_referral_requirement; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.provider_referral_requirement (
    provider_id integer NOT NULL,
    referral_requirement_id integer NOT NULL
);


ALTER TABLE public.provider_referral_requirement OWNER TO transontario;

--
-- Name: provider_service; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.provider_service (
    provider_id integer NOT NULL,
    service_id integer NOT NULL
);


ALTER TABLE public.provider_service OWNER TO transontario;

--
-- Name: provider_training; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.provider_training (
    provider_id integer NOT NULL,
    training_id integer NOT NULL
);


ALTER TABLE public.provider_training OWNER TO transontario;

--
-- Name: referral_requirement; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.referral_requirement (
    id integer NOT NULL,
    referral_requirement_kind text NOT NULL
);


ALTER TABLE public.referral_requirement OWNER TO transontario;

--
-- Name: review; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.review (
    provider_id integer NOT NULL,
    discord_user_id text NOT NULL,
    text text NOT NULL,
    score integer NOT NULL
);


ALTER TABLE public.review OWNER TO transontario;

--
-- Name: rho_training; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.rho_training (
    id integer NOT NULL,
    training_kind text NOT NULL
);


ALTER TABLE public.rho_training OWNER TO transontario;

--
-- Name: service; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.service (
    id integer NOT NULL,
    service_kind text NOT NULL
);


ALTER TABLE public.service OWNER TO transontario;

--
-- Name: providers; Type: VIEW; Schema: api; Owner: transontario
--

CREATE VIEW api.providers AS
 SELECT provider.slug,
    provider.source,
    provider.name,
    provider.address,
    provider.assessments_provided,
    provider.description,
    provider.email,
    provider.hours_of_operation,
    provider.phone,
    provider.satellite_locations,
    provider.fee_info,
    provider.submitted_by,
    provider.accessibility_available,
    provider.website,
    fsa.region,
    q1.languages,
    q2.specializes_in,
    q3.training,
    q4.referral_requirements,
    q5.fees,
    q6.services,
    q7.review_count,
    provider.id,
    provider.fsa
   FROM ((((((((public.provider
     LEFT JOIN public.fsa ON ((provider.fsa = fsa.fsa)))
     LEFT JOIN ( SELECT provider_1.id,
            array_agg(language.language_name) FILTER (WHERE (language.* IS NOT NULL)) AS languages
           FROM ((public.provider provider_1
             LEFT JOIN public.provider_language ON ((provider_language.provider_id = provider_1.id)))
             LEFT JOIN public.language ON ((language.id = provider_language.language_id)))
          GROUP BY provider_1.id) q1 ON ((provider.id = q1.id)))
     LEFT JOIN ( SELECT provider_1.id,
            array_agg(characteristic.person_kind) FILTER (WHERE (characteristic.* IS NOT NULL)) AS specializes_in
           FROM ((public.provider provider_1
             LEFT JOIN public.provider_expertise ON ((provider_expertise.provider_id = provider_1.id)))
             LEFT JOIN public.characteristic ON ((characteristic.id = provider_expertise.characteristic_id)))
          GROUP BY provider_1.id) q2 ON ((provider.id = q2.id)))
     LEFT JOIN ( SELECT provider_1.id,
            array_agg(rho_training.training_kind) FILTER (WHERE (rho_training.* IS NOT NULL)) AS training
           FROM ((public.provider provider_1
             LEFT JOIN public.provider_training ON ((provider_training.provider_id = provider_1.id)))
             LEFT JOIN public.rho_training ON ((rho_training.id = provider_training.training_id)))
          GROUP BY provider_1.id) q3 ON ((provider.id = q3.id)))
     LEFT JOIN ( SELECT provider_1.id,
            array_agg(referral_requirement.referral_requirement_kind) FILTER (WHERE (referral_requirement.* IS NOT NULL)) AS referral_requirements
           FROM ((public.provider provider_1
             LEFT JOIN public.provider_referral_requirement ON ((provider_referral_requirement.provider_id = provider_1.id)))
             LEFT JOIN public.referral_requirement ON ((referral_requirement.id = provider_referral_requirement.referral_requirement_id)))
          GROUP BY provider_1.id) q4 ON ((provider.id = q4.id)))
     LEFT JOIN ( SELECT provider_1.id,
            array_agg(fee.fee_kind) FILTER (WHERE (fee.* IS NOT NULL)) AS fees
           FROM ((public.provider provider_1
             LEFT JOIN public.provider_fee ON ((provider_fee.provider_id = provider_1.id)))
             LEFT JOIN public.fee ON ((fee.id = provider_fee.fee_id)))
          GROUP BY provider_1.id) q5 ON ((provider.id = q5.id)))
     LEFT JOIN ( SELECT provider_1.id,
            array_agg(service.service_kind) FILTER (WHERE (service.* IS NOT NULL)) AS services
           FROM ((public.provider provider_1
             LEFT JOIN public.provider_service ON ((provider_service.provider_id = provider_1.id)))
             LEFT JOIN public.service ON ((service.id = provider_service.service_id)))
          GROUP BY provider_1.id) q6 ON ((provider.id = q6.id)))
     LEFT JOIN ( SELECT provider_1.id,
            count(review.*) AS review_count
           FROM (public.provider provider_1
             LEFT JOIN public.review ON ((review.provider_id = provider_1.id)))
          GROUP BY provider_1.id) q7 ON ((provider.id = q7.id)))
  ORDER BY q7.review_count DESC;


ALTER TABLE api.providers OWNER TO transontario;

--
-- Name: referral_requirements; Type: VIEW; Schema: api; Owner: transontario
--

CREATE VIEW api.referral_requirements AS
 SELECT referral_requirement.referral_requirement_kind AS requirement
   FROM public.referral_requirement;


ALTER TABLE api.referral_requirements OWNER TO transontario;

--
-- Name: regions; Type: VIEW; Schema: api; Owner: transontario
--

CREATE VIEW api.regions AS
 SELECT DISTINCT fsa.region
   FROM public.fsa;


ALTER TABLE api.regions OWNER TO transontario;

--
-- Name: reviews; Type: VIEW; Schema: api; Owner: transontario
--

CREATE VIEW api.reviews AS
 SELECT review.provider_id,
    review.text,
    review.score,
    discord_user.username,
    discord_user.discriminator,
    discord_user.avatar,
    discord_user.id AS discord_user_id
   FROM (public.review
     LEFT JOIN public.discord_user ON ((review.discord_user_id = discord_user.id)));


ALTER TABLE api.reviews OWNER TO transontario;

--
-- Name: services; Type: VIEW; Schema: api; Owner: transontario
--

CREATE VIEW api.services AS
 SELECT service.service_kind AS service
   FROM public.service;


ALTER TABLE api.services OWNER TO transontario;

--
-- Name: training; Type: VIEW; Schema: api; Owner: transontario
--

CREATE VIEW api.training AS
 SELECT rho_training.training_kind
   FROM public.rho_training;


ALTER TABLE api.training OWNER TO transontario;

--
-- Name: characteristic_id_seq; Type: SEQUENCE; Schema: public; Owner: transontario
--

CREATE SEQUENCE public.characteristic_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.characteristic_id_seq OWNER TO transontario;

--
-- Name: characteristic_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: transontario
--

ALTER SEQUENCE public.characteristic_id_seq OWNED BY public.characteristic.id;


--
-- Name: fee_id_seq; Type: SEQUENCE; Schema: public; Owner: transontario
--

CREATE SEQUENCE public.fee_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.fee_id_seq OWNER TO transontario;

--
-- Name: fee_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: transontario
--

ALTER SEQUENCE public.fee_id_seq OWNED BY public.fee.id;


--
-- Name: language_id_seq; Type: SEQUENCE; Schema: public; Owner: transontario
--

CREATE SEQUENCE public.language_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.language_id_seq OWNER TO transontario;

--
-- Name: language_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: transontario
--

ALTER SEQUENCE public.language_id_seq OWNED BY public.language.id;


--
-- Name: provider_id_seq; Type: SEQUENCE; Schema: public; Owner: transontario
--

CREATE SEQUENCE public.provider_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.provider_id_seq OWNER TO transontario;

--
-- Name: provider_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: transontario
--

ALTER SEQUENCE public.provider_id_seq OWNED BY public.provider.id;


--
-- Name: provider_revision; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.provider_revision (
    provider_revision_id integer NOT NULL,
    provider_id integer NOT NULL,
    discord_user_id text,
    "timestamp" timestamp with time zone,
    revision_index integer,
    source text,
    slug text NOT NULL,
    name text,
    address text,
    assessments_provided text,
    description text,
    email text,
    hours_of_operation text,
    phone text,
    fsa text,
    satellite_locations text,
    fee_info text,
    submitted_by text,
    accessibility_available integer,
    website text
);


ALTER TABLE public.provider_revision OWNER TO transontario;

--
-- Name: provider_revision_expertise; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.provider_revision_expertise (
    provider_revision_id integer NOT NULL,
    characteristic_id integer NOT NULL
);


ALTER TABLE public.provider_revision_expertise OWNER TO transontario;

--
-- Name: provider_revision_fee; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.provider_revision_fee (
    provider_revision_id integer NOT NULL,
    fee_id integer NOT NULL
);


ALTER TABLE public.provider_revision_fee OWNER TO transontario;

--
-- Name: provider_revision_language; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.provider_revision_language (
    provider_revision_id integer NOT NULL,
    language_id integer NOT NULL
);


ALTER TABLE public.provider_revision_language OWNER TO transontario;

--
-- Name: provider_revision_provider_revision_id_seq; Type: SEQUENCE; Schema: public; Owner: transontario
--

CREATE SEQUENCE public.provider_revision_provider_revision_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.provider_revision_provider_revision_id_seq OWNER TO transontario;

--
-- Name: provider_revision_provider_revision_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: transontario
--

ALTER SEQUENCE public.provider_revision_provider_revision_id_seq OWNED BY public.provider_revision.provider_revision_id;


--
-- Name: provider_revision_referral_requirement; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.provider_revision_referral_requirement (
    provider_revision_id integer NOT NULL,
    referral_requirement_id integer NOT NULL
);


ALTER TABLE public.provider_revision_referral_requirement OWNER TO transontario;

--
-- Name: provider_revision_service; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.provider_revision_service (
    provider_revision_id integer NOT NULL,
    service_id integer NOT NULL
);


ALTER TABLE public.provider_revision_service OWNER TO transontario;

--
-- Name: provider_revision_training; Type: TABLE; Schema: public; Owner: transontario
--

CREATE TABLE public.provider_revision_training (
    provider_revision_id integer NOT NULL,
    training_id integer NOT NULL
);


ALTER TABLE public.provider_revision_training OWNER TO transontario;

--
-- Name: referral_requirement_id_seq; Type: SEQUENCE; Schema: public; Owner: transontario
--

CREATE SEQUENCE public.referral_requirement_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.referral_requirement_id_seq OWNER TO transontario;

--
-- Name: referral_requirement_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: transontario
--

ALTER SEQUENCE public.referral_requirement_id_seq OWNED BY public.referral_requirement.id;


--
-- Name: rho_training_id_seq; Type: SEQUENCE; Schema: public; Owner: transontario
--

CREATE SEQUENCE public.rho_training_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.rho_training_id_seq OWNER TO transontario;

--
-- Name: rho_training_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: transontario
--

ALTER SEQUENCE public.rho_training_id_seq OWNED BY public.rho_training.id;


--
-- Name: service_id_seq; Type: SEQUENCE; Schema: public; Owner: transontario
--

CREATE SEQUENCE public.service_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.service_id_seq OWNER TO transontario;

--
-- Name: service_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: transontario
--

ALTER SEQUENCE public.service_id_seq OWNED BY public.service.id;


--
-- Name: characteristic id; Type: DEFAULT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.characteristic ALTER COLUMN id SET DEFAULT nextval('public.characteristic_id_seq'::regclass);


--
-- Name: fee id; Type: DEFAULT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.fee ALTER COLUMN id SET DEFAULT nextval('public.fee_id_seq'::regclass);


--
-- Name: language id; Type: DEFAULT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.language ALTER COLUMN id SET DEFAULT nextval('public.language_id_seq'::regclass);


--
-- Name: provider id; Type: DEFAULT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider ALTER COLUMN id SET DEFAULT nextval('public.provider_id_seq'::regclass);


--
-- Name: provider_revision provider_revision_id; Type: DEFAULT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision ALTER COLUMN provider_revision_id SET DEFAULT nextval('public.provider_revision_provider_revision_id_seq'::regclass);


--
-- Name: referral_requirement id; Type: DEFAULT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.referral_requirement ALTER COLUMN id SET DEFAULT nextval('public.referral_requirement_id_seq'::regclass);


--
-- Name: rho_training id; Type: DEFAULT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.rho_training ALTER COLUMN id SET DEFAULT nextval('public.rho_training_id_seq'::regclass);


--
-- Name: service id; Type: DEFAULT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.service ALTER COLUMN id SET DEFAULT nextval('public.service_id_seq'::regclass);


--
-- Data for Name: characteristic; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.characteristic (id, person_kind) FROM stdin;
1	Adults
2	Children and Youth
3	Intersex
4	LGBT2SQ Parents and Families
5	People Living with Disabilities
6	Racialized Communities
7	Seniors
8	Trans
9	Trans and Non-Binary Children and Youth
10	Two-Spirit
22	Bisexual
23	Gay
25	Lesbian
26	Newcomers and/or Refugees
28	People who are HIV Positive
32	Trans and Non-Binary
\.


--
-- Data for Name: discord_user; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.discord_user (id, username, discriminator, avatar) FROM stdin;
\.


--
-- Data for Name: fee; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.fee (id, fee_kind) FROM stdin;
1	Free
3	Covered by OHIP
5	Fee for Service
8	Fee for Service With Sliding Scale
\.


--
-- Data for Name: fsa; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.fsa (fsa, region) FROM stdin;
K1A	ottawa
K2A	ottawa
K4A	ottawa
K6A	ottawa
K7A	ottawa
K8A	ottawa
K9A	kingston
K1B	ottawa
K2B	ottawa
K4B	ottawa
K8B	ottawa
K1C	ottawa
K2C	ottawa
K4C	ottawa
K7C	ottawa
K1E	ottawa
K2E	ottawa
K1G	ottawa
K2G	ottawa
K7G	kingston
K1H	ottawa
K2H	ottawa
K6H	ottawa
K7H	ottawa
K8H	ottawa
K9H	durham
K1J	ottawa
K2J	ottawa
K6J	ottawa
K9J	durham
K1K	ottawa
K2K	ottawa
K4K	ottawa
K6K	ottawa
K7K	kingston
K9K	durham
K1L	ottawa
K2L	ottawa
K7L	kingston
K9L	durham
K1M	ottawa
K2M	ottawa
K4M	ottawa
K7M	kingston
K1N	ottawa
K7N	kingston
K8N	kingston
K1P	ottawa
K2P	ottawa
K4P	ottawa
K7P	kingston
K8P	kingston
K1R	ottawa
K2R	ottawa
K4R	ottawa
K7R	kingston
K8R	kingston
K1S	ottawa
K2S	ottawa
K7S	ottawa
K1T	ottawa
K2T	ottawa
K6T	kingston
K1V	ottawa
K2V	ottawa
K6V	kingston
K7V	ottawa
K8V	kingston
K9V	durham
K1W	ottawa
K2W	ottawa
K1X	ottawa
K1Y	ottawa
K1Z	ottawa
L1A	durham
L2A	niagara
L4A	york
L5A	peel
L6A	york
L7A	peel
L9A	hamilton
L1B	durham
L3B	niagara
L4B	york
L5B	peel
L6B	york
L7B	york
L8B	hamilton
L9B	hamilton
L1C	durham
L3C	niagara
L4C	york
L5C	peel
L6C	york
L7C	peel
L9C	hamilton
L1E	durham
L2E	niagara
L4E	york
L5E	peel
L6E	york
L7E	peel
L8E	hamilton
L9E	hamilton
L1G	durham
L2G	niagara
L4G	york
L5G	peel
L6G	york
L7G	peel
L8G	hamilton
L9G	hamilton
L1H	durham
L2H	niagara
L4H	york
L5H	peel
L6H	hamilton
L8H	hamilton
L9H	hamilton
L1J	durham
L2J	niagara
L3J	niagara
L4J	york
L5J	peel
L6J	hamilton
L7J	peel
L8J	hamilton
L9J	barrie
L1K	durham
L3K	niagara
L4K	york
L5K	peel
L6K	hamilton
L7K	peel
L8K	hamilton
L9K	hamilton
L1L	durham
L3L	york
L4L	york
L5L	peel
L6L	hamilton
L7L	hamilton
L8L	hamilton
L9L	durham
L1M	durham
L2M	niagara
L3M	hamilton
L4M	barrie
L5M	peel
L6M	hamilton
L7M	hamilton
L8M	hamilton
L9M	barrie
L1N	durham
L2N	niagara
L4N	barrie
L5N	peel
L7N	hamilton
L8N	hamilton
L9N	york
L1P	durham
L2P	niagara
L3P	york
L4P	barrie
L5P	peel
L6P	peel
L7P	hamilton
L8P	hamilton
L9P	durham
L1R	durham
L2R	niagara
L3R	york
L4R	barrie
L5R	peel
L6R	peel
L7R	hamilton
L8R	hamilton
L9R	barrie
L1S	durham
L2S	niagara
L3S	york
L4S	york
L5S	peel
L6S	peel
L7S	hamilton
L8S	hamilton
L9S	barrie
L1T	durham
L2T	niagara
L3T	york
L4T	peel
L5T	peel
L6T	peel
L7T	hamilton
L8T	hamilton
L9T	hamilton
L1V	durham
L2V	niagara
L3V	barrie
L4V	peel
L5V	peel
L6V	peel
L8V	hamilton
L9V	peel
L1W	durham
L2W	niagara
L4W	peel
L5W	peel
L6W	peel
L8W	hamilton
L9W	peel
L1X	durham
L3X	york
L4X	peel
L6X	peel
L9X	barrie
L1Y	durham
L3Y	york
L4Y	peel
L6Y	peel
L9Y	barrie
L1Z	durham
L3Z	york
L4Z	peel
L6Z	peel
L9Z	barrie
M3A	toronto
M4A	toronto
M5A	toronto
M6A	toronto
M7A	toronto
M9A	toronto
M1B	toronto
M3B	toronto
M4B	toronto
M5B	toronto
M6B	toronto
M9B	toronto
M1C	toronto
M3C	toronto
M4C	toronto
M5C	toronto
M6C	toronto
M9C	toronto
M1E	toronto
M4E	toronto
M5E	toronto
M6E	toronto
M1G	toronto
M4G	toronto
M5G	toronto
M6G	toronto
M1H	toronto
M2H	toronto
M3H	toronto
M4H	toronto
M5H	toronto
M6H	toronto
M1J	toronto
M2J	toronto
M3J	toronto
M4J	toronto
M5J	toronto
M6J	toronto
M1K	toronto
M2K	toronto
M3K	toronto
M4K	toronto
M5K	toronto
M6K	toronto
M1L	toronto
M2L	toronto
M3L	toronto
M4L	toronto
M5L	toronto
M6L	toronto
M9L	toronto
M1M	toronto
M2M	toronto
M3M	toronto
M4M	toronto
M5M	toronto
M6M	toronto
M9M	toronto
M1N	toronto
M2N	toronto
M3N	toronto
M4N	toronto
M5N	toronto
M6N	toronto
M9N	toronto
M1P	toronto
M2P	toronto
M4P	toronto
M5P	toronto
M6P	toronto
M9P	toronto
M1R	toronto
M2R	toronto
M4R	toronto
M5R	toronto
M6R	toronto
M7R	toronto
M9R	toronto
M1S	toronto
M4S	toronto
M5S	toronto
M6S	toronto
M1T	toronto
M4T	toronto
M5T	toronto
M1V	toronto
M4V	toronto
M5V	toronto
M8V	toronto
M9V	toronto
M1W	toronto
M4W	toronto
M5W	toronto
M8W	toronto
M9W	toronto
M1X	toronto
M4X	toronto
M5X	toronto
M8X	toronto
M4Y	toronto
M7Y	toronto
M8Y	toronto
M8Z	toronto
N1A	kw
N2A	kw
N3A	kw
N5A	kw
N6A	london
N7A	kw
N8A	windsor
N9A	windsor
N2B	kw
N3B	kw
N4B	london
N6B	london
N9B	windsor
N1C	kw
N2C	kw
N3C	kw
N5C	london
N6C	london
N9C	windsor
N1E	kw
N2E	kw
N3E	kw
N6E	london
N9E	windsor
N1G	kw
N2G	kw
N4G	london
N6G	london
N7G	london
N9G	windsor
N1H	kw
N2H	kw
N3H	kw
N5H	london
N6H	london
N8H	windsor
N9H	windsor
N2J	kw
N6J	london
N9J	windsor
N1K	kw
N2K	kw
N4K	barrie
N6K	london
N9K	windsor
N1L	kw
N2L	kw
N3L	kw
N4L	barrie
N5L	london
N6L	london
N7L	windsor
N1M	kw
N2M	kw
N6M	london
N7M	windsor
N8M	windsor
N2N	kw
N4N	barrie
N6N	london
N8N	windsor
N1P	kw
N2P	kw
N3P	hamilton
N5P	london
N6P	london
N8P	windsor
N1R	kw
N2R	kw
N3R	kw
N5R	london
N8R	windsor
N1S	kw
N3S	kw
N4S	kw
N7S	sarnia
N8S	windsor
N1T	kw
N2T	kw
N3T	kw
N4T	kw
N7T	sarnia
N8T	windsor
N2V	kw
N3V	kw
N4V	kw
N5V	london
N7V	sarnia
N8V	windsor
N9V	windsor
N3W	hamilton
N4W	kw
N5W	london
N7W	sarnia
N8W	windsor
N4X	kw
N5X	london
N7X	sarnia
N8X	windsor
N3Y	hamilton
N5Y	london
N8Y	windsor
N9Y	windsor
N2Z	windsor
N4Z	kw
N5Z	london
P1A	sudbury
P2A	sudbury
P3A	sudbury
P5A	sudbury
P6A	sudbury
P7A	thunder-bay
P9A	thunder-bay
P1B	sudbury
P2B	sudbury
P3B	sudbury
P6B	sudbury
P7B	thunder-bay
P1C	sudbury
P3C	sudbury
P6C	sudbury
P7C	thunder-bay
P3E	sudbury
P5E	sudbury
P7E	thunder-bay
P3G	sudbury
P7G	thunder-bay
P1H	sudbury
P7J	thunder-bay
P7K	thunder-bay
P1L	sudbury
P3L	sudbury
P7L	thunder-bay
P2N	sudbury
P3N	sudbury
P4N	sudbury
P5N	thunder-bay
P8N	thunder-bay
P9N	thunder-bay
P1P	sudbury
P3P	sudbury
P4P	sudbury
P4R	sudbury
P8T	thunder-bay
P3Y	sudbury
K0A	ottawa
K0E	kingston
K0G	ottawa
K0J	ottawa
K0K	kingston
K0M	kingston
L0J	peel
L0L	durham
L0M	barrie
L0R	niagara
L0S	niagara
N0B	kw
N0C	barrie
N0E	hamilton
N0M	london
P0B	barrie
P0C	barrie
P0E	barroe
P0P	sudbury
P0S	sudbury
\.


--
-- Data for Name: language; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.language (id, language_name) FROM stdin;
1	Cree
2	English
5	Other
8	Chinese (simplified)
11	French
12	Italian
13	Mandarin
14	Ojibwe
16	Spanish
17	Tamil
44	Korean
78	Arabic
138	Portugese
252	Hungarian
258	Russian
261	Vietnamese
\.


--
-- Data for Name: provider; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.provider (id, source, slug, name, address, assessments_provided, description, email, hours_of_operation, phone, fsa, satellite_locations, fee_info, submitted_by, accessibility_available, website) FROM stdin;
1	rho	2-spirited-people-of-the-1st-nations-2-spirits	2 Spirited People of the 1st Nations (2 Spirits)	Toronto	\N	2 Spirited People of the 1st Nations (2 Spirits) is a non profit social service organization whose membership consists of Aboriginal 2-Spirit(people that carried male and female spirits)gay, lesbian, intersexed,bisexual and trasngendered people in Toronto. Due to the AIDS epidemic, the organization was prompted to have health, counseling and advocacy expertise.\n“We are the only Aboriginal non profit organaization in Canada that offers these services and support to two spirited people and to all Aboriginal people living with and/or affected by HIV/AIDS”	\N	\N	\N	\N	\N	\N	\N	\N	http://www.2spirits.com/
2	rho	2nd-chance-employment	2nd Chance Employment	177 Norfolk Street\nGuelph, N1H 4K1	\N	Whether it is your first job or a career change, we can support you to find, secure and maintain employment. Group and one to one services are available.\nProfessional services at no cost.	info@2ndchance.ca	\N	519 823-2440	N1H	435 Stone Road West, Guelph, ON, CanadaDirections\n160 St. David Street South, Guelph, ON, CanadaDirections	\N	Chris Baginski-Hansen\nDirector	\N	https://www.2ndchance.ca/
3	rho	2slgbtqia-neurology-clinic	2SLGBTQIA+ Neurology Clinic	5 West Wing- Toronto Western Hospital\n399 Bathurst Street\nToronto, M5T 2S8	\N	The 2SLGBTQIA+ Neurology Clinic at Toronto Western Hospital is a new outpatient service at UHN that provides inclusive, comprehensive, and individualized assessment and care to persons identifying as 2SLGBTQIA+ for a full range of neurological conditions that affect the brain, spinal cord, and nerves.\nThe referral form is available to download through the clinic’s webpage. Please complete all sections on the referral form and fax the completed form and all supporting documents to 416-603-6402.	kshirkooluhn@gmail.com	Mondays 8 a.m. to 4 p.m.	416-603-5232	M5T	\N	\N	Koorosh Shirkool\nMD, FRCPC	\N	https://www.uhn.ca/Krembil/Clinics/2SLGBTQIA_Neurology_Clinic
4	rho	4-rivers-massage-therapy	4 Rivers Massage Therapy	240 Roncesvalles Avenue\nToronto, M6R 1M3	\N	Private practice of Registered Massage Therapy on Roncesvalles ave. Offering massage therapy, aromatherapy, reflexology and reiki. Massage therapy’s primary purpose is in stress reduction, of which the importance cannot be overlooked, due to the permeating effects of stress on our wellbeing. Massage can also be a complimentary modality for managing symptoms associated with different kinds of emotional trauma, anxiety, depression, body dysmorphia, etc. Beyond stress reduction and relaxation, massage can be helpful in treating physical injuries or postural related conditions.	ckern.rmt@gmail.com	\N	6476773419	M6R	\N	\N	Carl Kern\nRMT	\N	https://www.4rivers.ca
5	rho	a-rahalkar-medicine-professional-corporation	A Rahalkar Medicine Professional Corporation	120 Vidal Street North\nSarnia, N7T 5X5	\N	Endocrinology and metabolism	drrahalkar@outlook.com	\N	519 332 5959	N7T	\N	\N	Amit Rahalkar\nMD, FRCPC	\N	\N
6	rho	a-s-electrolysis-laser-clinic	A.S. ELECTROLYSIS & LASER CLINIC	320 Danforth Avenue\nToronto, M4K 1N8	\N	Located in Toronto above the Carrot Common at 320 Danforth Avenue, Suite 203, we are conveniently accessible by car from the DVP or walking distance from Chester subway station.\nWe offer a full range of hair removal services, including:\nWe are proud to offer a safe, comfortable and supportive environment where clients can feel at ease when dealing with their concerns of unwanted hair. We are an LGBTQ positive space and have supported the Trans community for 25 years. All client information remains strictly confidential.\nA.S. Electrolysis is inspected by Toronto Public Health on a yearly basis to ensure we meet the highest industry standards and the inspection report is prominently displayed.\nCall 416.466.9518 to book your complimentary consultation where we will work together to find the best treatment plan for your hair removal needs.	\N	\N	416.466.9518	M4K	\N	\N	E.A.S Electrolysis Training Program: Electrolysis and the Blend	\N	https://www.aselectrolysis.com/
7	rho	abc-all-babies-count-canada-prenatal-nutrition-program	ABC; All Babies Count, Canada Prenatal Nutrition Program	361 Eagle Street\nNewmarket, L3Y 1K5	\N	Free weekly prenatal nutrition program funded by Public Health Agency of Canada. Offering support for expecting parents to promote maternal and infant health. Information on nutrition, cooking classes, labour and delivery, breastfeeding, parenting, etc. Opportunity to socialize with other parents, eat a healthy meal and/or snack together and take home a gift card or groceries. Assistance with transportation and translation services may be available.	information@roseofsharon.com	\N	905-853-5514 or 1-877-516-3715	L3Y	\N	\N	Sally Freitas\nBA, BSW, RSW	\N	https://information@roseofsharon.com
8	rho	accendus-group-psychotherapy	Accendus Group Psychotherapy	345 Lakeshore Road East\nSuite 200\nOakville, L6J1J5	\N	David is an individual, couples/relationship, and family therapist. He believes in creating a safe space where people of all backgrounds are welcome, and where clients feel seen, heard, valued, and supported. He works together with clients to empower inherent strengths and skills in those that he sees.  Here, clients can discover greater feelings of connection, understanding, curiosity and mindfulness in their lives.\nAs an Elementary School Teacher since 2001, David has worked with children and youth in the learning environment, and supported students with a broad range of issues, including depression, anxiety, trauma, and relationship challenges.\nAs a Registered Psychotherapist (Qualifying), David has focused on a mindfulness-based framework that fosters self-discovery, as well as identifying and resisting shame.  Specific treatment approaches include, but not limited to, evidence-based therapeutic modalities: Cognitive Behavior Therapy, Emotionally Focused Couples Therapy, Narrative Therapy, Solution Focused Therapy, and Family Systems Therapy.  He works from a trauma and attachment informed, harm reduction model of practice.\nDavid also has a strong focus on providing psychotherapy services for LGBTQ individuals and couples.\nDavid offers psychotherapy and counselling to individuals/couples, as well who are experiencing:\n	david.accendusgroup@gmail.com	MTWTH 430-830pm Saturday 9-2pm Sunday 1-5pm	6477831131	L6J	\N	$100\nSliding scale range - $/Hour Minimum: 100 Maximum: 150	David Johnston\nRegistered Psychotherapist (Qualifying)	\N	https://www.accendusgroup.com
9	rho	access-aids-network	Access AIDS Network	111 Elm Street\nGreater Sudbury, P3C 1T3	\N	Services available to any individual infected, affected or at risk of/by HIV/AIDS and Hepatitis C.\nResource Centre\n-Anonymous HIV and STI testing, Hep C testing\n-Condom and lubricant distribution\n-Educational presentations/wokshops on HIV/AIDS and co-infections, safer sex, harm reduction, homophobia and heterosexism\nOutreach Services\n-Support groups for LGBT2-SQ Youth and Adults\n-HIV+ women support group\n-HIV + men support group\n-Hep C+ Support group\nSupportive counselling available to LGBT2-SQ youth and adults, coming out issues, gender identity and healthy sexual relationships.\nHours of service begin at 8.30 am.	access@cyberbeach.net	\N	705.688.0500	P3C	\N	\N	\N	\N	https://www.accessaidsnetwork.com
10	rho	access-alliance-multicultural-health-and-community-services	Access Alliance Multicultural Health and Community Services	340 College Street\nToronto, L0J 1C0	\N	We provide a wide range of programs and services for immigrants and refugees living in the City of Toronto. Working through partnerships, we help develop innovative responses to newcomer issues. Please go to our web site for more information.	mail@accessalliance.ca	\N	416-324-8677	L0J	\N	\N	\N	\N	https://accessalliance.ca
11	rho	ace-physiotherapy-and-allied-health-services	Ace Physiotherapy and Allied Health Services	2 Carlton Street\nSuite 601\nToronto, M5B 1J3	\N	At Ace Physiotherapy Toronto our Registered Physiotherapists specialize in treating sports-related injuries, motor vehicle accident injuries, chronic conditions and workplace injuries. Whatever your complaint, our integrated team of experts will guide you along your road to recovery.\nOur core service is  with a difference.  At Ace Physio we believe customized care is essential to a successful outcome so we book you with your own Registered Physiotherapist in a one-on-one appointment. During the initial 45-minute visit, your therapist will take the time to assess your physical condition, determine the root cause(s) of your symptoms and design a treatment plan that meets your recovery goals and fits in with your busy schedule.  Included in your first visit is your first treatment to start you on your road to recovery.	info@acephysio.ca	Monday – Thursday 8am – 7pm Friday 8am – 4pm Saturday 9am – 2pm	416-900-6653	M5B	true	$99 for initial assessment $75 for 30-minute follow up treatment	Team\nPT, DPM	\N	http://www.acephysio.ca
12	rho	ace-physiotherapy-downtown-toronto	Ace Physiotherapy – Downtown Toronto	2 Carlton Street\nToronto, M5B 1J3	\N	Our experienced multidisciplinary team at Ace Physio includes; Registered Physiotherapists, Registered Massage Therapists, Occupational Therapists, and a Chiropodist.\nWe are conveniently located in the heart of downtown Toronto at Yonge and College.\nOur Physiotherapy services include:\nPhysiotherapy\nShockwave Therapy\nSpinal Decompression\nLaser Therapy\nCustom Orthotics\nAcupuncture\nGua Sha Massage\nUltrasound\nCustom Knee Braces\nMotor Vehicle Accident Rehab	info@acephysio.com	\N	4169006653	M5B	\N	\N	Brad Saltz\nPhysiotherapist	\N	https://www.torontophysiotherapy.co
13	rho	act-aids-committee-of-toronto	ACT  (AIDS Committee of Toronto)	543 Yonge Street, 4th floor\nToronto, Ontario	\N	Founded in 1983 as the AIDS Committee of Toronto, today ACT provides free programs and services for all people living with HIV.\nWe also offer specific programming for gay men, women and young people living with HIV, and we provide information, outreach, and education on HIV, STIs and sexual health for women, youth and gay/bi/queer men regardless of HIV status.\n	ask@actoronto.org	Monday - Thursday 10am - 9pm. Friday 10am - 5pm.	416-340-2437	\N	\N	\N	\N	\N	https://www.actoronto.org
14	rho	act-integrative-health	Act Integrative Health	15 Atlantic Ave\n2nd Floor\nToronto , M6K 3E7	\N	Act Integrative Health provides hybrid virtual pelvic health physiotherapy available across Ontario with targeted in person treatment available in Toronto.\nPelvic health physiotherapy is evidenced based assessment and treatment of the pelvic floor muscles and the systems of which they are a part. It can help with bladder and bowel dysfunction like urinary or fecal incontinence, persistent pain with sexual activity, persistent low back, hip and pelvic pain.\nPelvic health physiotherapy is relevant for all ages and is not exclusive to one sex or gender. Specifically, pelvic health physiotherapy can help with preparation and rehabilitation for transition related surgeries.\nA registered pelvic health physiotherapist has specialized training to provide care that is informed, sensitive and skilled enough to talk about your goals and perform the external and internal palpation that makes assessment and treatment of the pelvic floor effective.	physio@actintegrativehealth.ca	Virtual Hours: Mon-Thursday 12pm-8pm In Person Hours: Wed 9am-8pm	647-372-2408	M6K	\N	$110-$150	Erin Fraser\nRegistered Physiotherapist, MPT, Pelvic Health Physiotherapist	\N	http://actintegrativehealth.ca/
15	rho	action-positive-vih-sida	Action positive VIH/sida	399 Church Street\nToronto, M5B 2A1	\N	ACTION POSITIVE VIH/Sida est un organisme à but non lucratif dédié exclusivement au soutient des personnes et des communautés d’expression française à Toronto, qui vivent avec le VIH/sida, qui en sont affectées, ou à risque de le contracter. Il cible particulièrement les hommes qui ont des relations sexuelles avec d’autres hommes (HsH), les hommes gais, bisexuels, transsexuels d’expression française à Toronto. Les services sont offerts de façon confidentielle, sensible, efficace et professionnelle. Notre approche fait la promotion de la santé, du mieux-être, de la valeur et des droits des personnes et des communautés qui vivent avec le VIH/sida.	info@actionpositvievihsida.org	\N	\N	M5B	\N	\N	\N	\N	https://www.apvs.ca/
16	rho	acupuncture-and-trauma-life-coaching	Acupuncture and Trauma Life Coaching	2333 Dundas West Suite 501\nToronto, M6R 3A6	\N	I provide acupuncture, Chinese herbs and life coaching for people living with trauma. I also work a lot with people trying to have babies.	tcmpjenb@gmail.com	Thursday 12-6 Online consultations available.	416 476-6979	M6R	489 College Street Suite 301416 324-8888Directions	Sliding scale range - $/Hour Minimum: 40 Maximum: 150	Jennifer Bowers\nRTCMP, Certified Life Coach	\N	http://www.littledragonacupuncture.com
17	rho	acutoronto	Acutoronto	2401 Yonge St #215\ntoronto, m4p3h1	\N	We are a multidisciplinary clinic providing superior care in the field of Traditional Chinese Medicine, Acupuncture, Registered Massage Therapy, Psychotherapy.\n	info@acutoronto.com	Wednesday 12–8p.m. Thursday 12–8p.m. Friday 12–8p.m. Saturday 9a.m.–2p.m. Sunday 8a.m.–2p.m. Tuesday 9a.m.–1p.m	416-486-5222	\N	\N	\N	\N	\N	https://www.acutoronto.com/
18	rho	acutoronto-wellness-clinic	Acutoronto Wellness Clinic	2401 Yonge Street\nToronto, M4P 3H1	I can provide secondary assessments for transition-related bottom surgeries	I provide art therapy, psychotherapy, mental health counselling and referral to community resources for individuals over the age of 16. I also provide clinical supervision to registered psychotherapists. My services are offered both in-office at Yonge and Eglinton as well as online using a secure Zoom account.	therapy@taliasinger.com	Mondays Wednesdays Fridays Saturdays	416-486-5222	M4P	\N	$135.00	Talia Singer\nRN RP PhD	\N	https://www.acutoronto.com
19	rho	adam-gratton-naturopath	Adam Gratton Naturopath	\N	\N	Adam is a licensed naturopathic doctor providing alternative and complementary care to patients of all levels of health. Services provided include: acupuncture, clinical nutrition, homeopathy, botanical medicine, nutritional and lifestyle counselling, and weight loss programs. Adam is also experience in treated patients with HIV and has held a supervisory role a the Sherbourne Community Health Centre’s Naturopathic Clinic.	\N	\N	\N	\N	\N	\N	\N	\N	\N
20	rho	adam-weinmann-rd	Adam Weinmann, RD	484 Crawford St\nTORONTO, M6G 3J8	\N		adam.weinmann@gmail.com	Monday 8:30a.m.–7:30p.m. Tuesday 8:30a.m.–7:30p.m. Wednesday 8:30a.m.–7:30p.m. Thursday 8:30a.m.–7:30p.m. Friday 8:30a.m.–6:30p.m. Saturday 10a.m.–4p.m.	4169481477	M6G	\N	$125/hour	Adam Weinmann\nRD, MHSc, MFA	\N	https://www.brainpowerednutrition.com
21	rho	adapt	ADAPT	165 Cross Ave\nSuite 203\nOakville, L6J 0A9	\N	ADAPT is a non-profit, community-based, outpatient addiction, assessment and treatment agency funded by the Ministry of Health & Long Term Care, the Ministry of Children and Youth Services, the Ministry of Community Safety and Correctional Services, and the United Way to provide a range of services throughout the Halton Region. At ADAPT, we offer you drug addiction treatment, alcohol addiction treatment, gambling addiction treatment and more.	adapt@haltonadapt.org	Services open Monday to Firday 8:30am to 4:30pm. Some evening hours available.	905-639-6537	L6J	\N	\N	\N	\N	https://haltonadapt.org/
22	rho	addictions-and-mental-health-services-hastings-prince-edward	Addictions and Mental Health Services- Hastings Prince Edward	15 Victoria Avenue\nBelleville, K8N 1Z5	\N	Addictions and Mental Health Services- Hastings Prince Edward is a community-based agency providing a range of client-centred services and supports throughout Hastings and Prince Edward Counties to individuals 16 and older. Services can be provided in the individual’s home environment, office setting or in the community.\nAll services are confidential and offered at no cost to the individual. Addictions and Mental Health Services Hastings Prince Edward is funded by the Ministry of Health and Long Term Care and the Southeast Local Health Integration Network (SELHIN).	\N	\N	613-967-4734	K8N	\N	\N	\N	\N	https://hopedreamrecover.ca
23	rho	addison-brash-registered-massage-therapist	Addison Brash – Registered Massage Therapist	Cambridge, N3C2B9	\N	Addison Brash – Registered Massage Therapist. Safe for all QT BIPOC folks.\nOpen, friendly, safe, and non-judgemental.\nAnti-fatphobia, no body shame, no unsolicited weight / nutrition advice!	addison.l.brash@gmail.com	2:30-6:30 Monday to Friday	9059121301	N3C	\N	$90/hr $55/30 mins	Addison Brash	\N	https://walkingtreewellness.ca
24	rho	adhd-solutions	ADHD Solutions	Toronto, M5A 1K5	\N		jennifer@ADHDSolutions.ca	Mon: 9:00am-5:00pm Tues: Closed Wed: 9:00am-5:00pm Thursday: 9:00am-5:00pm Friday: 9:00am-5:00pm Sat: Closed Sun: Closed	(438) 794-2483	M5A	true	$120 per session\nSliding scale range - $/Hour Minimum: 90	Jennifer Hogan, MScOT ADHD Coach\nMScOT, ADHD Coach	\N	http://www.ADHDSolutions.ca
25	rho	adrienne-richardson-niagara-counselling-online-therapy	Adrienne Richardson Niagara Counselling / Online Therapy	6150 Valley Way\nNiagara Falls, L2E 1X9	\N	I am an LGBTQ- friendly and knowledgeable registered gestalt psychotherapist, who can also provide psychological services. I am attuned to and have experience with cultural considerations and issues faced by LGBTQ individuals and their families. Please feel free to call to book a 50 minute session either at my offices in Niagara Falls, Ontario or via telephone. I’ve got your back!	arichxoxo@gmail.com	\N	4168785556	L2E	\N	\N	Adrienne Richardson PhD Counselling\nPhD MsED registered Gestalt Psychotherapist	\N	https://niagaramarriagecounselling.com/
26	rho	advanced-institute-of-electrolysis-laser	Advanced Institute Of Electrolysis & Laser	1033 Bay Street\nToronto, M5S 3A3	\N	Electrolysis, Laser, Facials, Acne & Acne Scars Treatment, Brown Spots, Teeth Whitening	info@advancedinstitute.ca	\N	416 979 8081	M5S	\N	\N	Dana Almeida\nElectrolysis,Laser,Facials,Teeth Whitening	\N	https://advancedinstitute.ca
27	rho	affective-consulting-psychotherapy-services	Affective Consulting & Psychotherapy Services	\N	\N	Individual psychotherapy services as well as organizational training in anti-oppression, mental health, addiction, harm reduction, trans inclusion and LGBT health.	\N	\N	\N	\N	\N	\N	\N	\N	\N
28	rho	africans-in-partnership-against-aids-apaa	Africans in Partnership Against AIDS (APAA),	526 Richmond Street East\nToronto	\N	Africans in Partnership Against AIDS (APAA), is committed to the provision of HIV/AIDS education in a linguistically and culturally sensitive context. APAA believes that a supportive environment is essential to the well-being of people living with HIV/AIDS (PHAs), as well as to the well-being of their partners, families and friends.\nAPAA believes in the health and dignity of people living with HIV/AIDS (PHAs), recognizing the difficulties that African people face when they are infected or affected by HIV/AIDS. APAA continues to respond to an increasing number of requests for practical and emotional support from a diverse clientele, but especially from people living with HIV/AIDS within African communities.	info@apaa.ca	\N	416-924-5256	\N	\N	\N	\N	\N	https://apaa.ca/
29	rho	agnes-kim-therapy	Agnes Kim Therapy	720 Spadina Ave, Suite 509\nToronto, M5S 2T9	\N	Agnes Daeun Kim (she/they) offers client-centred, anti-oppressive, and trauma-informed therapy that is strengths-based and collaborative. They bring authenticity and warmth to her practice to provide a safe and compassionate space for her clients. She values transparency within the therapeutic relationship and also understands the importance of working at the client’s pace.\nShe is passionate about working with diverse populations, including BIPOC, newcomers, and members of the LGBTQIA2+ community. Agnes self-identifies as a queer person of colour, and she speaks both English and (limited) Korean.\nAgnes is licensed by the College of Registered Psychotherapists of Ontario (CRPO).	contact@agneskimtherapy.com	Monday 11:00AM - 7:30PM Tuesday 11:00AM - 7:30PM Thursday 11:00AM - 7:30PM Friday 1:00PM - 5:00PM Sunday 11:00AM - 5:30PM	(647) 360-9486	M5S	\N	$120+HST	Agnes Daeun Kim\nMEd, Registered Psychotherapist	\N	https://agneskimtherapy.com
30	rho	aidan-jeffery	Aidan Jeffery	Lincoln, L0R1B5	\N	Family Physician with an interest in LGBT and trans health	draidanjeffery@gmail.com	Monday to Friday, daytime hours	905 563-1212	L0R	\N	\N	\N	\N	http://www.lincolnmedicalcentre.com/
31	rho	aids-committee-of-cambridge-kitchener-waterloo-area	AIDS Committee of Cambridge, Kitchener, Waterloo & Area	Kitchener	\N	ACCKWA responds to the changing needs of Waterloo Region community and individuals infected, affected and at risk for HIV/AIDS through the provision of prevention, education, advocacy and support programs and services.	m2m@acckwa.com	\N	519-570-3687	\N	\N	\N	\N	\N	\N
32	rho	aids-committee-of-durham-region	AIDS Committee of Durham Region	Oshawa	\N	ACDR provides accessible, culturally competent, and holistic support services to people living with and affected by HIV and AIDS.  To accomplish this, we reduce barriers to accessing ACDR’s programs and services, and assist clients in navigating public, private and non-profit sector programs and services. Our goal is to engage, empower and build the capacity of people living with HIV and AIDS (PLWHA) and individuals and families affected by HIV and AIDS by offering services that meet clients where they’re at and respond to self-identified needs.\nWhat We Offer: Advocacy, Case Management, Complementary Therapies Program, Counseling, Food Bank Program, Food Bank Program, Holiday Hamper Program, Inter-Agency Support & Community Partnerships, Medical Services Drop-in, Peer Mentoring Program, PHA Skills Development- Workshops/Conferences, Positive Connections Newsletter, Positive Living Wellness Fund, Social Activities/Events, Support Groups,”The Pozzy” Youth, Volunteer Driver Program\nHIV/AIDS support, education and harm reduction services. Agency hours are 9-5pm Monday through Friday. Agency is closed for Lunch between 12:30 and 1PM.	info@aidsdurham.com	\N	905-576-1445	\N	\N	\N	\N	\N	https://www.aidsdurham.com
66	rho	anne-newchild-counselling-services	Anne Newchild, Counselling Services	Ottawa , K2S1E5	\N	I am currently offering individual counselling sessions to LGBT2SQ+ (ages 20+) online through a video platform. I specialize in working with anxiety, stress, depression, trauma, addictions, relationship difficulties, and burnout.	Anne.Newchild@gmail.com	Flexible	613-220-3588	K2S	\N	\N	A. Newchild	\N	\N
67	rho	annie-lu-m-d	Annie Lu, M.D.	\N	\N	Rural Family Physician who welcomes LGBTQ patients. Will provide consult service for patients wishing to transition with HRT. Office hours vary during the week.\nDr Lu is a part of the Upper Grand Family Health Team.	\N	\N	\N	\N	\N	\N	\N	\N	\N
33	rho	aids-committee-of-north-bay-and-area	AIDS Committee of North Bay and Area	147 McIntyre Street West\nSuite 102\nNorth Bay, P1B 2Y5	\N	The AIDS Committee of North Bay & Area (ACNBA) is a community-based, registered, non-profit organization, serving people in the North Bay catchment area – bounded by West Nipissing, Kirkland Lake, Mattawa and Huntsville – who are infected and/or affected by HIV/AIDS or Hepatitis C since 1991*.\nACNBA’s mission is to assist and support all people infected and/or affected by HIV/AIDS and/or Hepatitis C and to limit the spread of the viruses through education, outreach and treatment strategies.	oaacnba@gmail.com	Monday 8:30am – 12:00pm & 1:00pm-4:00pm Tuesday 8:30am – 12:00pm & 1:00pm-4:00pm Wednesday 8:30am – 12:00pm & 1:00pm-4:00pm Thursday 8:30am – 12:00pm & 1:00pm-4:00pm Friday 8:30am – 12:00pm & 1:00pm-3:30pm Saturday/ Sunday Closed	7054973560	P1B	\N	\N	\N	\N	https://aidsnorthbay.ca/
34	rho	aids-committee-of-north-bay-area	AIDS Committee of North Bay & Area	269 Main Street West\nNorth Bay, P1B 2T8	\N	Support Services include: counselling and referrals, treatment resources, tender assistance fund, and a lounge with computer and internet access.\nIf you are a person living with HIV, or are concerned about someone who is, our services may be helpful to you. If you are concerned about HIV exposure, safer sex/needle use practices, HIV testing, or discrimination based your HIV status, our support workers are available for you.\nAll our services are completely confidential, free of charge and open to everyone. Your privacy and the confidential nature of your concerns are extremely important to us.\nSpecial accommodation can be made for evening appointments by scheduling with the support workers directly.\n* Food vouchers\n* Travel assistance\n* Complimentary therapies\n* Medical services\n* Health kits and multivitamins\n* Hospital/Home supports\n* Other health initiatives	oaacnba@vianet.ca	\N	(705) 497-3560	P1B	\N	\N	\N	\N	https://www.aidsnorthbay.com
35	rho	aids-committee-of-ottawa	AIDS Committee of Ottawa	251 Bank Street\nOttawa, K2P 1X2	\N	The AIDS Committee of Ottawa (ACO) is a community-based, non-profit organization providing free, confidential services for people living with, affected by and at risk of HIV in the Ottawa area. Starting from a small group of gay men and lesbians in 1985, ACO has grown to include a broad cross section of volunteers, participants and staff members who come together to reduce the barriers that foster HIV infection, their causes, and negative consequences through advocacy.	info@aco-cso.ca	\N	(613) 238-5014	K2P	\N	\N	\N	\N	https://aco-cso.ca/
36	rho	aids-committee-of-toronto	AIDS Committee of Toronto	399 Church Street\nToronto, M5B 2A1	\N	Founded in 1983, the AIDS Committee of Toronto (ACT) provides information, as well as practical, emotional and social support services to men, women and youth living with HIV/AIDS in Toronto. We also help people with HIV/AIDS to re-enter the work force.	ask@actoronto.org	\N	416.340.2437	M5B	\N	\N	\N	\N	https://www.actoronto.org
37	rho	aids-committee-of-windsor	Aids Committee of Windsor	\N	\N	The AIDS Committee of Windsor (ACW) is a registered charity that provides support, education and outreach services for people living with, affected by, or at-risk of HIV/AIDS. Our services span the Windsor-Essex and Chatham-Kent counties through two offices located in downtown Windsor and downtown Chatham respectively.	\N	\N	\N	\N	\N	\N	\N	\N	\N
38	rho	aids-committee-of-windsor-chatham	AIDS Committee of Windsor/Chatham	511 Pelissier Street\nWindsor, N9A 4L2	\N	AIDS Committee of Windsor (ACW) is a registered charity that provides support, education and outreach services for people at risk of, or living with HIV or AIDS. Our services span the Windsor-Essex and Chatham-Kent counties through two offices located in downtown Windsor and downtown Chatham.\nACW services include: food and nutrition programs, support services, case management, social events and community programming.	msharp@aidswindsor.org	\N	519 973 0222	N9A	\N	\N	\N	\N	https://www.aidswindsor.org
39	rho	aids-committee-of-york-region	AIDS Committee of York Region	194 Eagle Street\nNewmarket, L3Y 1J6	\N	HIV Drive-to-Care provides free door-to-door transportation for geographically isolated PHA’s to medical and other treatment and care appointments in Toronto\nAnnual Client Retreat\nCompassion Fund provides emergency financial assistance to clients\nIndividual support\nMonthly support groups\nPeer support\nInformation resourcing\nReferrals to other services\nHoliday gift program	supportacyr@bellnet.ca	\N	905-953-1372	L3Y	\N	\N	\N	\N	https://acyr.org
40	rho	albina-veltman-psychiatry	Albina Veltman Psychiatry	\N	\N	I provide psychiatric consults and brief follow-up for individuals who identify as LGBTTIQ who are currently struggling with mental health issues.	albina_veltman@hotmail.com	\N	905-525-0300	\N	\N	\N	Albina Veltman\nMD, FRCPC	\N	\N
41	rho	alejandra-lindan	Alejandra Lindan	79 Hiawatha Road\nToronto, M4L 2X7	\N	Adapted/intensive individual DBT (weekly) psychotherapy for youth and adults.\nDBT-/attachment-/trauma-centred psychotherapy for Individuals, families, couples and constellations.	alejandra@lindan.ca	\N	647 968 7628	M4L	2005 Danforth Ave, Toronto, ON, Canada647 968 7628Directions	\N	Alejandra Lindan\nRegistered Psychotherapist	\N	https://lindanpsychotherapy.com
42	rho	alex-norris-therapy	Alex Norris Therapy	Toronto, M6P 3K8	I can provide secondary assessments for transition-related bottom surgeries	Alex is a non-binary social worker providing psychotherapy and secondary assessments virtually across Ontario. For more information about their practice, please visit their Psychology Today profile.	alexnorristherapy@gmail.com	Tuesday-Friday, 11:30-5:30 PM	1-888-577-5772	M6P	\N	140	Alex Norris\nMSW, RSW	\N	https://www.psychologytoday.com/ca/therapists/alex-norris-toronto-on/795045
43	rho	ali-ahmad-psychotherapy-social-work	Ali Ahmad Psychotherapy/Social Work	848 Bloor Street West\nToronto, M6G 1M2	\N	Ali is a Registered Social Worker who is experienced working with people living with stress, anxiety and depression arising from life transitions, grief and substance use. Ali works from a person-centred approach, helping you to find balance and resilience, using modalities such as Mindfulness, Emotionally Focused Couples Therapy and Cognitive Behavioural Therapy (CBT). Ali is employed at the outpatient clinic at the Michael Garron Hospital and he also works with patients admitted to the mental health unit. He works with diverse populations from various ethnic, religious and cultural backgrounds including refugees, newcomers and members of LGBTQ community. Ali has a Master of Social Work and a Bachelor of Social Work degree, along with certifications in many modalities. He speaks Urdu, Hindi and Punjabi, however, psychotherapy is conducted in English.	aliahmadpsychotherapy@gmail.com	\N	416-929-3982	M6G	\N	\N	Ali Ahmad\nPsychotherapist, Ontario College of Social Workers and Social Service Workers	\N	\N
68	rho	antoine-quenneville-psychotherapist	Antoine Quenneville Psychotherapist	180 Argyle Avenue\nOttawa, K2P 0N2	\N	Fluently bilingual (french/english) experienced counsellor. Areas of specialization: male survivors of childhood abuse, anger management, depression and relationship issues. I also provide training on GLBT Issues in the workplace, Gay/Bi survivors of sexual abuse and Conflict in the Workplace. Can be covered by extended health care benefits.	aquenneville@themensproject.ca	\N	613-230-6179 ext. 401	K2P	\N	\N	Antoine Quenneville\nM.A., OACCPP	\N	https://www.themensproject.ca
44	rho	alliance-for-south-asian-aids-prevention	Alliance for South Asian AIDS Prevention	20 Carlton Street\nToronto, M5B 2H5	\N	ASAAP is a Toronto based AIDS service organization.It was founded in 1989 as a result of the voluntary efforts of members of Khush (a social group for South Asian gays and lesbians that has since closed down), in a community response to a request for support for a South Asian couple infected with HIV/AIDS who died in isolation, unable to access services in their own language. Our catchment area is greater Toronto and all the surrounding suburbs/towns. Our services include preventative education, support to South Asians infected with and affected by HIV/AIDS, outreach, and advocacy. Services are available in Tamil, Hindi, Urdu, Punjabi, Gujarati, and Bengali. You may need to call ahead to arrange assistance in South Asian languages.\nASAAP is a non profit charitable organization. The governing body is a 11 Member Board of Directors elected by members of ASAAP at the Annual General Meeting in accordance with the agency’s By-laws. ASAAP has 8 staff members. True to our history, we continue to provide many of our services through collaboration with our talented and committed volunteers.	info@asaap.ca	\N	(416)599-2727	M5B	\N	\N	\N	\N	https://www.asaap.ca and www.dosti.ca
45	rho	allison-small-m-d	Allison Small, M.D.	\N	\N	Family practice serving all ages and providing comprehensive care to patients. LGBTQ positive primary health care.	\N	\N	\N	\N	\N	\N	\N	\N	\N
46	rho	alm-consulting-coaching-and-counselling	ALM Consulting: Coaching and Counselling	\N	\N	Anna Maranta enjoys guiding and supporting people along their life journeys using different modalities including counselling, education, life-coaching and spiritual direction. Anna works from an integral approach; she will guide you through the process of renewing yourself in Heart, Mind, Body and Soul!	\N	\N	\N	\N	\N	\N	\N	\N	\N
47	rho	aloft-rmt-movement	Aloft RMT + Movement	327 Ottawa Street North\nUnit 213\nHamilton, L8H3Z8	\N	Body positive massage therapy and exercise – to feel and move better in your daily life. Massage therapy, acupuncture, Pilates.	aloftrmt@gmail.com	Monday to Friday: 10 a.m. to 3 p.m.	9059294506	L8H	\N	\N	Maureen	\N	https://www.aloftrmt.com/
48	rho	alpha-court-community-mental-health-and-addictions-services	Alpha Court Community Mental Health and Addictions Services	221 Wilson Street\nThunder Bay, P7B 1M7	\N	Alpha Court is a non-profit community organization. We provide subsidized housing and case management services to individuals with a serious mental illness and/or a drug/alcohol addiction. Services are provided by dedicated and professional staff.\nAlpha Court promotes living beyond mental illness and addiction through the provision of individualized, recovery-orientated community-based services.\nAlpha Court envisions a society where all individuals, regardless of their mental health or addiction challenges, can reach their full potential and live productive lives.\nThere is an LGBTQ group as part of the Day Program.	\N	\N	(807) 683-8200	P7B	\N	\N	\N	\N	https://www.alphacourt.ca/
49	rho	alpha-health-services	ALPHA Health Services	40 Holly street\n901\nToronto, M4S 3C3	\N	At ALPHA Health Services, our goal is to offer the best care, advice and treatment to enable you to be as physical as you can, want and need to be. Our name was picked specifically to encompass the focus of our practice; to help you develop and maintain the musculature to live an Active Life, to allow you to reach your peak Performance in sports, hobbies or regular life and to promote Healthy Aging. We believe in a holistic approach to rehabilitation and strive to get you back to optimum health as safely and quickly as possible.	info@alphahealthservices.ca	8am - 8pm	4165451881	M4S	true	Contact for Rates - Covered by many Private Insurance Companies	\N	\N	https://www.alphahealthservices.ca
50	rho	alternative-horizon-counselling-and-consulting	Alternative Horizon Counselling and Consulting	20 Eglinton Avenue East\nToronto, M4P 1A6	\N	Individual, Couple and Family Counselling; Sex Therapy; EMDR\nAreas of Specialization include: LGBT, Couples Enhancement, Sexuality, Childhood Abuse and other trauma, Sexual Addiction, Depression, Anxiety	jeremy@alternativehorizon.com	\N	416-486-2161	M4P	\N	\N	Jeremy Tomlinson\nM.Ed., R.S.W., EMDRIA Certified	\N	https://www.alternativehorizon.com
51	rho	alternatives-for-women-prince-edward-county	Alternatives for Women – Prince Edward County	Prince Edward, K0K 2T0	\N	Alternatives for Women in Prince Edward County is dedicated to providing safe and confidential services while working to end violence and abuse of women.\nAt Alternatives for Women, we strive to meet the needs of our clients. We offer an array of services, such as:	\N	\N	613-476-2787	K0K	\N	\N	\N	\N	https://www.alternativesforwomen.org/
52	rho	alyssa-mccarthy-she-her-speech-language-pathologist-voice-therapist	Alyssa McCarthy (she/her), Speech Language Pathologist & Voice Therapist	2300 Yonge Street\nSuite 1600\nToronto, ON	\N	Transgender and gender affirming voice training: support for individuals seeking voice feminization, masculinization and neutralization\nVoice therapy for rehabilitation and/or prevention of voice disorders (e.g. nodules, cysts, muscular tension dysphonia)\nCurrently offering online services	Alyssa@speechappealclinic.com	(Hours may vary) Monday-Thursday: 11:30am-7:30pm Friday: 10:00am-3:00pm Occasional weekend	1-416-549-1641	\N	\N	\N	Alyssa McCarthy, Speech-Language Pathologist & Voice Therapist\nM.Sc. S-LP, S-LP (C), Reg. CASLPO	\N	https://www.speechappealclinic.com/alyssamccarthy
53	rho	alyssa-mccarthy-speech-language-pathologist-voice	Alyssa McCarthy, Speech-Language Pathologist (Voice)	2300 Yonge Street\nSuite 1600\nToronto, M4P 1E4	\N	Alyssa (she/her) is a registered Speech-Language Pathologist and Voice Therapist who passionately supports folks in discovering their congruent voice in a supportive environment. Gender affirming voice training includes voice feminization, voice masculinization, and voice neutralization. Alyssa also provides training for voice injury prevention and post-operation therapy and rehabilitation.	alyssa@speechappealclinic.com	Monday-Thursday 12:00 p.m.-7:30 p.m. Friday 10:00 a.m. - 4:00 p.m. Saturdays: Vary	416-549-1641	M4P	true	\N	Alyssa McCarthy\nBA Mus., MSc. S-LP (C).,  Reg. CASLPO	\N	https://www.speechappealclinic.com
64	rho	anna-berger-doula	Anna Berger Doula	1652 Bathurst Street\nToronto, M5P 3J9	\N	I am a DONA-trained birth doula with additional in many aspects of prenatal, birth, and postpartum support. I do not provide medical care, but rather offer emotional, physical, and informational support throughout these processes.\nIt is part of my personal mission to ensure that all people have access to this kind of support in their family planning process, and I strive to make my services welcoming and affordable for all families, regardless of situation. I offer a sliding scale for fees and a wide variety of service options.\nI gladly support all kinds of families, including families across the gender spectrum and families with any number of parents. I will happily describe my experience with these types of families during our consultation so we can be sure we’re a good fit for each other!	midtowndoulagta@gmail.com	\N	416-660-9352	M5P	\N	\N	Anna Berger\nDoula	\N	https://midtowndoula.ca
65	rho	anna-wesolinska-psychotherapy	Anna Wesolinska Psychotherapy	\N	\N	Private psychotherapy practice. Ongoing workshops.	\N	\N	\N	\N	\N	\N	\N	\N	\N
1015	rho	west-end-pharmacy	West End Pharmacy	426 Huron Street\nStratford, N5A 5T7	\N	Pharmacy	info@westendpharmacy.org	\N	519-273-7200	N5A	\N	\N	George Jansen\nBScPhm, RPh, CRE, TEACH trained	\N	https://www.westendpharmacy.org
54	rho	amelia-sloan-psychotherapy	Amelia Sloan Psychotherapy	Hamilton, L8L 7N9	\N	I provide Relational Somatic (body-centered) psychotherapy and Sex Therapy to a diverse client population experiencing a wide range of life circumstances & difficulties. This includes, but it not limited to: anxiety, depression, numbness and sadness; Self-esteem & body image, emotional regulation/dysregulation, illness or medical diagnosis; Reconnecting with your body; Relationship problems and transitions, divorce/relationship endings; bereavement and grief. Exploring gender and/or sexual identity; sexuality and intimacy challenges; kink/BDSM, living with HIV/AIDS, coping with sexually transmitted infections and/or exploring diverse relationship models.\nIn relational therapy we unpack how repetitive beliefs & patterns show up in your relationship with yourself & others, paying close attention to the impact of your earliest relationships. We explore and make sense of your feelings, thoughts, experiences, needs & boundaries and create new patterns and ways of connecting with others, while developing a secure sense of self. This starts with the strong therapeutic relationship between you and I. Using somatic psychotherapy and mindfulness practices, we can additionally explore the ways your body & nervous system  participates in your emotional and mental health and wellbeing, holds memories & trauma & the sensations and feelings that accompany this. We can also increase your resources and tools to help restore balance to your life.\nMy practice is grounded in the frameworks of intersectional feminism, anti-oppression, anti-racism, social justice, queer theory & harm/risk reduction. I am sex & kink-positive, sex-work positive, class-conscious & anti-racist.	ameliasloantherapy@gmail.com	Monday noon-6pm Tuesday 130pm to 8pm Thursday noon-6pm Friday noon-6pm	n/a	L8L	\N	80-155	Amelia Sloan\nRP, RN, MN	\N	https://ameliasloantherapy.com
55	rho	anchoridge-counselling	Anchoridge Counselling	295 Weber Street North, Unit 6A\nWaterloo, N2J 3H8	\N	We have clinicians and counsellors that specialize in gender identity, gender dysphoria, anxiety, depression, personality disorders, eating disorders, and more. We provide individual, group, family, and couples counselling.\nAt Anchoridge Counselling we believe the anchor symbolizes support and strength to get you through the difficult times in your life – we will your anchor.\nOur goal is to connect you with the right mental health professional who will strive to empower you to reach a breakthrough within six to eight sessions. Here, we know the value of giving compassionate, qualified counsellors the chance to work with the population they know best. That is why if you have the courage to share your story and the willingness to work, your counsellor will develop an individualized treatment plan to give you the understanding, support, and tools you need to overcome.\nOur careful, highly selective hiring process for counsellors means you can rest assured that you are receiving the highest standard of quality care from the moment you arrive — and after you leave. What makes Anchoridge unique is that our work doesn’t end when the session does. We are committed to finding all the resources you need to overcome the obstacles in your life.	info@anchoridgecounselling.com	Monday: 9:00 am - 8:00 pm Tuesday: 9:00 am - 8:00 pm Wednesday: 9:00 am - 8:00 pm Thursday: 9:00 am - 8:00 pm Friday: 9:00 am - 4:0 0pm Saturday: CLOSED Sunday: CLOSED	(519) 745-4141	N2J	\N	Sliding scale range - $/Hour Minimum: 125 Maximum: 170	\N	\N	https://www.anchoridgecounselling.com
56	rho	anchoridge-counselling-services	Anchoridge Counselling Services	475 Park Street\nKitchener, N2G 4V5	\N	Mental Health Services	natashalavji@anchoridgecounselling.com	\N	5197454141	N2G	\N	\N	Natasha Lavji\nB.A, M.S, CCC, RP (Q)	\N	https://www.anchoridgecounselling.com
57	rho	anchoridge-counselling-services-2	Anchoridge Counselling Services	348 Bronte Street South\nVirtual Location\nMilton,  L9T 1Y8	\N		jocelynblake@anchoridgecounselling.com	Monday to Thursday: 9:00 am - 8:00 pm Friday: 9:00 am - 4:00 pm	(289) 386-5110	L9T	\N	$130	Jocelyn Blake\nMA Counselling Psychology, Registered Psychotherapist (Qualifying)	\N	https://www.anchoridgecounselling.com/jocelyn-blake
58	rho	ander-negrazis-mental-health-counselling	Ander Negrazis – Mental Health Counselling	114 Maitland Street\nToronto, M4Y 1E1	\N	Ander provides individual, couple, and group counselling to LGBT clients and clients with dis/Abilities. Working from an Anti-Oppression framework, Ander uses an integrative approach drawing from CBT, Creative, Narrative, and Person-Centered therapies. Ander also provides educational counselling and Learning Strategizing for clients with Learning Disabilities.	anderpsychotherapy@gmail.com	\N	416-540-1053	M4Y	\N	\N	Ander Negrazis\nM.Ed, Counselling Psychology	\N	https://therapists.psychologytoday.com/rms/name/Ander_Negrazis_HonBA,MEd_Toronto_Ontario_222644
59	rho	andrea-faveri-low-cost-relational-psychotherapy	Andrea Faveri – Low Cost Relational Psychotherapy	Currently offering online therapy only\nOnline therapy for residents of Ontario, M4T 1k2	\N	I am a bi-racial woman and proud member of the LGBTQIA2S community. My approach to Relational Psychotherapy is client-led, which means that you decide what to talk about in our sessions. Together, we will illuminate and make sense of issues in your emotional life. We will create space for new understandings about yourself. This self-discovery will be handled with compassionate regard for you and the process that you are going through.	afaveritherapy@gmail.com	Weekdays and evenings.	See email	\N	\N	$85.	Andrea Faveri\nB.A., M.A., B.Ed.	\N	https://www.andreafaveri.com/
60	rho	andrew-foster-r-m-t	Andrew Foster R.M.T.	189 Parkmount Road\nToronto, M4J 4V5	\N	Andrew Foster is the Health Clinic Director of the Cambridge Club and has provided RMT services for a number of A-list celebrity clients.\nHe offers affordable, professional, registered massage therapy services, active release therapy and craniosacral therapy for those in need from his private clinic located in the east york area at Danforth and Coxwell.\nHe also provides RMT receipts for insurance purposes.	andyrmt2@rogers.com	\N	416-778-7533	M4J	\N	\N	Andrew Foster\nRMT, CST, ART	\N	https://www.andrewfoster.ca
61	rho	andrew-kriger-md	Andrew Kriger MD	8 York Street\nToronto, M5J2Y2	\N	Family physician in downtown Toronto.  LGBT2SQ informed care in a family medicine and walk-in clinic.	info@hmedical.ca	Tuesdays: 1 p.m. -8 p.m. Wednesdays to Fridays: 8 a.m. - 3 p.m. One Saturday per month 10 a.m. - 4 p.m.	4163662273	M5J	\N	\N	\N	\N	https://www.hmedical.ca/
62	rho	anishnawbe-health-toronto-community-health-centre	Anishnawbe Health Toronto – Community Health Centre	225 Queen Street East\nToronto, M5A 1S4	\N	Our mission is to improve the health and well being of Aboriginal People in spirit, mind, emotion and body through both Traditional and Western healing approaches. The programs and services we offer are based on our culture and traditions through a multi-disciplinary team of dedicated healthcare professionals and service providers.\nDr Yoella Teplitsky is trained to meet trans clients specific needs.	\N	\N	(416) 360-0486	M5A	\N	\N	Canadian Centre for Accreditation	\N	https://www.aht.ca/
63	rho	anishnawbe-mushkiki	Anishnawbe Mushkiki	101 Syndicate Avenue North\nThunder Bay, P7C 3V4	\N	Nurse practitioner offering LGBTQ friendly and knowledgeable care. I am confident and comfortable in providing transition related services.	nsereda.rn@gmail.com	\N	807-623-0383	P7C	\N	\N	Nicole Sereda\nPrimary Health Care Nurse Practitioner	\N	\N
69	rho	anton-corvus-gestalt-psychotherapy-and-holistic-hypnotherapy	Anton Corvus, Gestalt Psychotherapy and Holistic Hypnotherapy	421 Bloor St E\nSuite 409, Be Here Now\nToronto, M4W 3T1	\N	Transmasc non-binary therapist supporting empaths, creative people, LGBTQ+ questioning and trans including non-binary folks, is my specialty. My core clients can’t easily say no, need to keep busy, have intimacy problems, depression, anxiety, or have experienced childhood sexual abuse.\nMy style is relational, client driven, trauma informed. We work together to build safety, reconnect mind, body and emotions, in a creative, body expressive style, supporting breath and embodied spaciousness, working with what we are able to sense in the present moment.\nI support individuals and couples, with relational gestalt psychotherapy, which is creative, intuitive, exploratory and trauma informed.	antonccorvus@protonmail.com	Tuesday, Wednesday, Thursday: online Friday - Saturday: in-person and online	647-746-8919	M4W	\N	Sliding scale range - $/Hour Minimum: 120 Maximum: 135	Anton Corvus\nRegistered Psychotherapist (Qualifying)  RPq	\N	https://interwoven-souls.ca
70	rho	arch-hiv-aids-community-health	ARCH HIV/AIDS Community Health	89 Dawson Road\nGuelph, N1H 1A6	\N	The Support Program is designed to provide confidential counselling and practical support to individuals and families who are living with, affected by or at risk of HIV/AIDS.\nIf you are a person living with HIV/AIDS, or are concerned about someone living with HIV/AIDS, our services may be of use. We believe that people living with HIV/AIDS deserve compassionate support and accurate information to assist them in making informed choices in managing their own health.\nAll services we provide are completely confidential and free of charge. We provide:\nARCH Clinic is committed to providing inclusive and respectful primary health care for Transgender people in Guelph and the surrounding area. ARCH Clinic offers treatment and monitoring of temporary and chronic health issues for Transgender individuals.\nARCH Clinic offers hormonal treatment options for those looking for medical support through transitioning.  Patients can self-refer or be referred to ARCH by a health care provider. ARCH Clinic operates within an informed consent model meaning that psychiatric evaluations are not necessary for individuals to begin hormonal treatment.  Patients begin with a detailed intake appointment  with our nurse, where hormonal treatment information is discussed.  Patients return after a minimum of two weeks with a signed consent form, to their first appointment with the doctor to discuss their treatment options. Preventative healthcare that includes annual physicals, immunizations, testing and screening is available.\nTo book an appointment or ask a question, please call 519-780-5298 or email at coordinator@archguelph.ca.	coordinator@archguelph.ca	\N	519-763-2255	N1H	\N	\N	\N	\N	https://www.archguelph.ca/
71	rho	ariel-blau-psychotherapy	Ariel Blau Psychotherapy	Toronto	\N	I am a queer identified clinical social worker providing supportive LGBTQIA2S-positive psychotherapy. I am a gifted therapist with a knack for quickly establishing trusting therapeutic relationships and for connecting with my clients’ experience. Clients with whom I work find comfort in talking to me because they experience me as authentic, curious, compassionate, and caring. I provide non-judgmental psychotherapy that is nuanced by my working experience with a wide range of cultures, national backgrounds and identities. My expertise encompasses evidence-based DBT, DBT skills, CBT, trauma-focused, Mindfulness and other therapeutic modalities, which I apply with imagination, intuition, warmth, and effectiveness.	arielblau@arielblau.com	\N	416.260.6038	\N	\N	\N	Ariel  Blau\nMSW, Registered Social Worker	\N	https://arielblau.com
72	rho	arlie-millyard	Arlie Millyard	Toronto, M6H 2K1	\N	Meet Arlie Millyard, a naturopathic doctor, LGBTQ2SIA+ inclusion and equity expert, and cauliflower enthusiast. Arlie helps folks who feel alienated and unseen in health and wellness spaces work towards wellness on their own terms, so they can feel comfortable and empowered in their bodies.\nArlie particularly loves guiding patients’ journeys to digestive health, working on stress management and stress-aggravated conditions, and helping those with complex chronic illness learn to manage their symptoms at their own pace.\nArlie’s signature non-judgemental, highly individualized style makes every patient feel in control. Her patients’ love Arlie because of her ability to explain exactly what’s going on in your body, matter-of-fact acceptance of every individual, and unshakeable commitment to helping wellness misfits take control of their health and live their lives authentically.\nCurrently all services are provided virtually and are open to all Ontario residents. Some patients may be eligible for home visits. Book a free discovery appointment to see if we’re a good fit!	hello@arliemillyard.ca	Wednesday: 9 a.m. - 3 p.m., 7 p.m. - 8:30 p.m. Thursday: 9 a.m. - 4 p.m. Sunday: 9:30 a.m. - 4 p.m.	647-467-1306	M6H	\N	Sliding scale range - $/Hour Minimum: 100 Maximum: 160	Arlie Millyard\nND	\N	https://arliemillyard.ca/
73	rho	around-the-rainbow	Around the Rainbow	312 Parkdale Avene\nOttawa, K1Y 4X5	\N	We provide 2SLGBTQI++ services and resources to our communities to support families and individuals. Our services include:\nTraining and education for service providers, schools and organizations serving Ottawa* to create welcoming, inclusive and equal spaces for 2SLGBTQI++ families and individuals\nRainbow Families Art and Play afternoons for 2SLGBTQI+ families and their children\nSupport group for parents and caregivers of gender creative, gender fluid, non-binary, trans children and youth\nArts-based support group for youth (11-17) who identify as gender fluid, trans, two-spirit, gender diverse, non-binary\nSpecial family events\nInformation, referral and supports for 2SLGBTQI+ families and individuals\nCounselling services with an 2SLGBTQI+identified counsellor.	lmontroy@familyservicesottawa.org	M-F 9-5, evenings for groups, evening training available.	(613) 725-3601 X105	K1Y	\N	\N	Family Services Ottawa	\N	https://familyservicesottawa.org/services/around-the-rainbow/
74	rho	art-of-thriving	Art of Thriving	Niagara Falls, L2G6Y4	\N	Art of Thriving is a virtual teletherapy service that provides support specialized around self-esteem, body image and disorder eating recovery. We recognize that everyone’s journey is unique and the support we provide reflects that. For each person we support, we work with you to create a tailored treatment plan that incorporates methods and tools that speak to you. From traditional cognitive behavioural therapy, to artistic art expression, you are in the drivers seat while we act as a guide through the process.\nMy name is Alicia Pinelli (they/them), RSW, MSW and as queer, nonbinary, person with loved experience it has always been my goal to provide a space where we can all feel safe, supported, and involved in our own treatment. I recognize that not everyone will fit with my style or the service from Art of Thriving, and that is okay. I welcome you to reach out for a free discovery meeting where can explore your options, and see where this journey takes us. It can feel anxiety provoking, overwhelming and scary to start counselling, but sometimes just beginning is all we really need to get the process started.	artofthriving@outlook.com	Virtual Provider, flexible hours including: Days, evening, weekends and holidays.	2895477522	L2G	\N	Sliding scale range - $/Hour Minimum: 80 Maximum: 125	Alicia\nPinelli	\N	https://www.artofthriving.ca
75	rho	asian-community-aids-services	Asian Community AIDS Services	260 Spadina Avenue\nToronto, M5T 2E4	\N	Asian Community AIDS Services (ACAS) is a charitable, non-profit, community-based organization. It provides HIV/AIDS education, prevention, and support services to the East and Southeast Asian Canadian communities. These programs are based on a pro-active and holistic approach to HIV/AIDS and are provided in a collaborative, empowering, and non-discriminatory manner.\nOur programs and services for men, women and youth range from volunteer training, workshops, peer-to-peer training and brief counseling to settlement and immigration. We practice from an anti-oppression framework and the GIPA/MIPA principles.\nPrograms and Services include:\nQueer Asian Youth group\nSupport Services\nVolunteer Program\nTrans Friendly Women’s Outreach Program\nAsian Transwomen and Employment Project	info@acas.org	\N	416-963-4300	M5T	\N	\N	\N	\N	https://www.acas.org
76	rho	associated-youth-services-of-peel	Associated Youth Services of Peel	160 Traders Boulevard East\nMississauga, L4Z 3K7	\N	Associated Youth Services of Peel provides many services free of charge including: family programs, child and youth programs, justice programs and groups.\nYouth Beyond Barriers – The YBB Program provides confidential services for youth who identify as Lesbian, Gay, Bisexual, Transgender, Transsexual, Intersex, Queer, Questioning, 2-Spirited (LGBTTIQQ2S) through a support and education group, individual counselling, and through social media. The YBB group brings together LGBTTIQQ2S youth to share their experiences and talk about issues that matter to them. The group offers support and education on a range of relevant issues and topics. It is an open group that operates year round. Individual counselling is available for youth aged 12-17, identifying as LGBTTIQQ2S and requiring support. Additionally, support can be provided for parents/caregivers of youth involved in the program.\nThe YBB Program facilitates educational workshops, trainings, and community events to raise awareness regarding LGBTTIQQ2S issues and other forms of oppression. The program provides support and service to the Gay-Straight Alliances in the Peel District School Board schools.	general@aysp.ca	\N	905-890-5222	L4Z	\N	\N	\N	\N	https://www.aysp.ca/
77	rho	athletic-therapy	Athletic Therapy	18 Dovercourt Rd\nToronto, M6J 3C3	\N	I am a certified Athletic Therapist who works to find, and treat, the root cause of an injury for all patients. I have a Bachelors of Kinesiology from the University of Toronto, a Bachelor of Athletic Therapy from Sheridan College and registered with the Canadian Athletic Therapy Association. Through clinical and field settings I have a variety of experiences that make me uniquely equipped to handle high performance sport injuries, persistent minor concerns and everything in between.\nMy training includes treatment for acute injuries (sprains, strains, fractures), as well as chronic injuries (back pain, shin pain, headaches). Starting with a full and holistic assessment, I use soft tissue manipulation, assisted movement, taping and gradual individualized movement plans to get patients back to what they love.\nMy services and experiences extend to trans and non binary specific concerns of chest binding, top surgery & mastectomies, and breast augmentation.\nI strive to make Athletic Therapy welcoming and accessible by fostering a supportive and safe environment for genuine conversations. This includes using a trauma-informed, body positive, and inclusive approach. You deserve care that is specific to you and your body, not a one-size-fits-all approach.	freya@theathletesgrid.com	Bookable online Tues & Fri 9am-1pm. Can be booked outside of those hours if contacted directly.	(647) 236-3227	M6J	\N	Minimum $75 - Maximum $170	Freya Jones-Eriksson\nCAT(C), BKIN	\N	https://theathletesgrid.janeapp.com/#/staff_member/35
78	rho	authentic-self-counselling-services	Authentic Self Counselling Services	Pickering, L1W 2L5	\N	My practice is centered on clients needs. I work with all individuals who are looking to make changes. I provide a safe space & positive space for folks in the LGBTQ+ community, their families, partners and friends.\nMy beliefs are each individual has the right to identify how they choose, and that only they know what is best for them and their life. I work with individuals who are just coming out, contemplating transition, beginning transition or just needing some help during a life transition.\nI help clients identify shifting personal relationships with family and friends, explore sexuality and gender identity, as well as internal and external homo/transphobia.	jakefarr@authenticselfcs.com	\N	416-678-2340	L1W	\N	\N	Jake Farr\nMSW, RSW	\N	http://authenticselfcs.com/
79	rho	avni-jain	Avni Jain	417 Bloor Street West\nToronto, M5S1X6	\N	I provide psychotherapy and counselling  to LGBTTQ2SI communities.\nMy work is client centered, integrative and holistic. I support individuals, couples and families through difficult situations and life transitions. I offer the space and opportunity for clients to explore themselves and their past, in order to develop new skills and insights. I empower my clients to face present and future challenges with greater awareness.	avniajain1@gmail.com	Monday 9-5 Tuesday 2-7 Wednesday 2-7 Thursday 9-5 Sunday 9-1	\N	M5S	\N	\N	Avni\nJain	\N	https://www.avnijain.ca/
80	rho	aworie-health-and-wellness-services	Aworie Health and Wellness Services	60 Atlantic Avenue\n200\nToronto, M6K 1X9	\N		info@Aworie.com	Administration Hours: Monday: 11am - 5pm Tuesday: 11am - 5pm Wednesday: 11am - 5pm Thursday: 11am - 5pm Friday: 11am - 5pm Saturday: 11am - 5pm Sunday: Closed Counselling Service Hours: Monday - Saturday: Appointment only Sunday: Closed	4166194956	M6K	\N	$120/hour\nSliding scale range - $/Hour Minimum: 80 Maximum: 150	\N	\N	https://www.aworie.com/
81	rho	balance-psychology	Balance Psychology	130 Slater Street\nOttawa	\N	Psychology practice.	Info@balancepsychology.ca	\N	6136996510	\N	\N	\N	Crystal Holly\nClinical Psychologisy, PhD	\N	https://www.balancepsychology.ca
82	rho	balanced-health-care	Balanced Health Care	\N	\N	Provide chiropractic care which includes soft tissue therapy (ART and Graston) and rehabilitation exercises. Also trained in Webster Technique for pregnancy care. The clinic also offers registered massage therapy, acupuncture, naturopathic care, and homeopathy.	\N	\N	\N	\N	\N	\N	\N	\N	\N
83	rho	balanced-nutrition-solutions	Balanced Nutrition Solutions	1537 Sandpiper Drive\nLondon, N5X 0G4	\N	Providing one on one counseling for a wide range of nutrition issues in a non judgmental and safe space. Please visit the website for more information on services offered.	Info@balancednutritionsolutions.com	\N	5197195600	N5X	\N	\N	Ayesha Sarathy\nRegistered Dietitian	\N	https://www.balancednutritionsolutions.com
84	rho	balanced-nutrition-solutions-2	Balanced Nutrition Solutions	\N	\N	Provide one on one nutrition coaching for a variety of nutrition related concerns, including transgender nutrition.	ayeshakapoor@gmail.com	\N	5197195600	\N	\N	\N	Ayesha Sarathy\nRegistered Dietitian	\N	https://www.balancednutritionsolutions.com
85	rho	balancing-from-birth-to-baby	Balancing from Birth to Baby	50 Ottawa Street South\nKitchener, N2G 3S7	\N	Prenatal and parenting preparation courses, Doula services, infant safety and infant feeding workshops, community events and birth product rentals.	Info@balancingbirthbaby.com	\N	5194967787	N2G	\N	\N	Maggie Hilton\nRN	\N	https://www.balancingbirthbaby.com
86	rho	barbara-cowan-naturopath	Barbara Cowan Naturopath	120 Harvie Street\nGravenhurst, P1P 1H3	\N	Naturopathic Medicine is a unique and comprehensive approach to improving health and treating illness. Naturopathic Doctors (NDs) are primary healthcare providers who support and stimulate the body’s ability to heal itself, using natural substances and treatments which include acupuncture, herbal medicine, homeopathy, nutritional and lifestyle counselling.. Naturopathic Medicine blends our evolving scientific knowledge with traditional, natural forms of medicine. The naturopathic philosophy is to stimulate the healing power of the body and treat the underlying cause of disease. Symptoms are seen as signs of imbalanced functioning of the body and can be the result of unfavourable lifestyle habits. Naturopathic Doctors treat the entire continuum of illness – they can provide relief for the acute manifestations of disease, such as pain and infection, and they can treat the underlying causes of chronic illness, creating the opportunity for full healing and the restoration of health & vitality.\nAs a primary healthcare provider, NDs can address a wide variety of health problems in every stage of life, from obstetrics to geriatrics.\nDr. Cowan ND practices in Gravenhurst and Orillia, ON. She welcomes all LGBTTTIQ people to her clinic.	gravenhurstnd@yahoo.ca	\N	705-684-9444	P1P	\N	\N	Barbara Cowan\nND	\N	https://www.BarbaraCowanND.com
87	rho	barrie-and-community-family-health-team	Barrie and Community Family Health Team	567 Cundles Road East\nBarrie, L4M 0G9	\N	Primary care health practitioner	jcoutts@bcfht.ca	\N	705 726-4681	L4M	\N	\N	Janice Coutts\nNurse Practitioner	\N	\N
88	rho	bay-street-clinic-of-electrolysis-skin-care	Bay Street Clinic of Electrolysis & Skin care	1033 Bay Street\nToronto, M5S 3A3	\N	Welcome to Bay Street Clinic\nElectrolysis is a medically approved safe permanent hair removal system for both men and women. This method has been recognized as the most reliable permanent hair removal technique utilizing electrical current to destroy the hair papilla.\nRegular treatments are important to ensure success. New sterile disposable needles are used for every treatment, which is performed by a medically trained certified electrologist with over 20 years of experience\nWe offer a safe ,hygienic,private and comfortable environment\nEVERYONE IS WELCOME !!\nOpen 7 days a week Free consultation\n1033 Bay Street suite 310 tel: 416 921-1357\nanother location 600 Sherbourne Street suite 304 tel: 416 929 -9000\nWe treat skin conditions : acne,brown spots,dry skin\nplease see our web www.baystreetclinic.ca	beautysolutions@rogers.com	\N	416  921-1357	M5S	\N	\N	Victoria Cuturicu\nEsthetician, Electrologist, Owner of the skin care line VICTORY	\N	https://baystreetclinic.ca
89	rho	bay-street-clinic-of-electrolysis-skin-care-2	Bay Street Clinic of Electrolysis & Skin Care	\N	\N	We offer a Free consultation and 15 min Treatment Electrolysis (Thermolysis , Blend technique) or Laser) where we will work together to find the best treatment plan for your hair removal needs.\nThis might include using both laser and electrolysis treatments together within the treatment plan. (Never used simultaneously)\nWe are LGBTQ friendly and have supported the trans community for more than 25 years.\nOur clinics are inspected by Toronto Public Health on a yearly basis to ensure we meet the highest industry standards and the inspection report is prominently displayed.\nHaving a background in Pharmacy, I understand and support the medical history and medications that my clients identify as trans may be taking.\nOur goal is to provide a personalized treatment program to meet each client’s specific needs and to see\nthat each client is successful and happy with the results\n4 Locations to serve you ( 3 downtown locations and one in Chinatown Mall)\nCall 416.921.1357 ; 416.921.2512	bestbeautydeal@hotmail.com	\N	416.921.1357; 416.921.2512	\N	Directions	\N	Victoria Cuturicu\nMedical aesthetician,Laser technician, Pharmacy background	\N	https://baystreetclinic.ca
90	rho	bayshore-home-care-solutions	Bayshore Home Care Solutions	5 Coleman Street\nMississippi Mills, K0A 1A0	\N	Agency-based nursing home care services, contracted through the LHIN.	avarsava82@bayshore.ca	\N	6138055246	K0A	\N	\N	Ashley Varsava\nRPN	\N	\N
91	rho	be-strong-physiotherapy-inc	Be Strong Physiotherapy Inc.	3220 Kingston Road\nToronto, M1M 1P4	\N	Physiotherapy, Chiropractic, Massage therapy	info@bestrongphysio.ca	\N	416-792-6440	M1M	\N	\N	Emma Calderone	\N	https://www.bestrongphysio.ca
92	rho	be-strong-physiotherapy-inc-2	Be Strong Physiotherapy Inc.	\N	\N	An active rehabilitation clinic with Physiotherapy, Chiropractic, Massage therapy.	info@bestrongphysio.ca	\N	(416) 792-6440	\N	\N	\N	Emma Calderone\nPhysiotherapist	\N	https://www.bestrongphysio.ca
93	rho	bee-kind-counselling	Bee Kind Counselling	Brantford, N3T1N9	\N	*Servicing all of Ontario* via virtual video counselling on a PHIPA approved database.\nAre you looking for one on one support with issues you are dealing with in your day to day life? You’ve come to the right place. I am an Indigenous woman part of the LGBTQ+ community who specializes in supporting your specific needs with a personalized plan of care. I work with all kinds of individuals and/or families/couples based on their needs. I work Individually with clients aged 10+. My services are on a sliding scale rate to ensure clients are able to access affordable therapy. If this is something you are looking for please feel free to reach out via phone, email or on my website to schedule a free 15-minute phone consultation.	beekindcounselling@hotmail.com	Services are offered Monday-Friday with day and evening sessions available. All administrative inquiries are answered as they come, there are no set hours for inquiries. Please allow us 24-hours to respond to your inquiry.	519-757-7842	N3T	\N	Individual- 100 +/- Family/Couple- 150 +/-	Bre Traverse\nBSW, MSW, RSW	\N	https://www.beekindcounselling.com/
94	rho	belleville-and-quinte-west-community-health-centre	Belleville and Quinte West Community Health Centre	Trenton, K8V 0A8	I can provide transition related surgery assessments for top or bottom surgeries	I’m a family physician providing trans care for folks in Trenton and surrounding areas	reception@bqwchc.com	M-F 8:30-4:30	613-965-0698	K8V	true	\N	Dr. Sofija Rans\nMD, CCFP	\N	https://www.bqwchc.com/
95	rho	belleville-qunite-west-community-health-center-chc	Belleville & Qunite West Community Health Center (CHC)	161 Bridge St W, Belleville, ON	\N	I’m a family physician specializing in trans care and LGBTQ health, accepting new patients in the Belleville, Quinte West and Prince Edward County area.	\N	\N	613-962-0000	\N	\N	\N	Kira Abelsohn\nFamily physician	\N	\N
96	rho	beth-mares-counselling	Beth Mares Counselling	\N	\N	Online therapy and counselling for adults 18+ and couples, same sex and other sex, in Northern Ontario, Toronto and elsewhere in Ontario and English Canada. Depression, anxiety disorders, relationships, marriage, family, sexual problems, sex addictions, internet addiction, drinking problems, eating disorders, weight problems, unwanted habits.	\N	\N	\N	\N	\N	\N	\N	\N	\N
97	rho	better-life-counselling-centre	Better Life Counselling Centre	220 Duncan Mill Rd.\nSuite: 215\nNorth York , M3B 3J5	\N		info@blcc.ca	Monday- Saturday 11am-8pm	647-726-2999	M3B	\N	Sliding scale range - $/Hour Minimum: 60 Maximum: 170	\N	\N	https://www.blcc.ca
551	rho	lisa-shouldice-psychotherapy	Lisa Shouldice Psychotherapy	717 Bloor Street West\nToronto, M6G 1L5	\N	Individual, couple and family therapist	lshouldice@rogers.com	\N	416-953-6880	M6G	\N	\N	Lisa Shouldice\nCertified Canadian Counsellor	\N	https://www.lisashouldice.com
98	rho	betty-ann-mcpherson-counselling-and-consulting	Betty Ann McPherson Counselling and Consulting	1639 Lasalle Boulevard\nSuite 306\nGreater Sudbury, P3A 1Z8	\N	Providing counselling and psychotherapy to individuals and families dealing with transitions in their life including transgender emergence. We provide assistance to those who are dealing with coming out and identifying as gay, lesbian, bisexual, queer, trans, and/or are questioning.	Contact@BettyAnnMcPherson.com	Monday 9:00 a.m. to 4:00 p.m. Tuesday 9:00 a.m. to 6:00 p.m. Wednesday 9:00 a.m. to 4:00 p.m. Thursday 9:00 a.m. to 6:00 p.m.	705-560-2481	P3A	\N	also covered for NIHB (those who are Indigenous and have a status card)	Betty Ann McPherson\nRegistered Psychotherapist	\N	https://www.BettyAnnMcPherson.com
99	rho	betty-kershner-phd-registered-toronto-psychologist	Betty Kershner, PhD – Registered Toronto Psychologist	100 Morrow Avenue\nToronto, M6R 2H9	\N	I work with people of all ages and many types of issues, some of which suggest different approaches. Together, we consider the best method for what is on your mind. I perform assessments, conduct treatment, and consult to individuals, couples, families, and organizations. My approach to treatment is relational and psychodynamic: I aim to get a deeper understanding of thoughts and feelings, experiences and interactions that may not really be in tune with what you want: how you want to be and how you want to live your life. With assessments, we aim to investigate strengths and weaknesses, what helps and what impedes, to find out what is going on and what works best for you. I aim for cultural sensitivity and sexual orientation support. We work together to develop practical solutions.	betty@bettykershner.ca	\N	416-518-7758	M6R	\N	\N	Betty Kershner\nPh.D. + Registered with the College of Psychologists of Ontario	\N	https://www.bettykershner.ca
100	rho	birds-bees-egg-and-sperm-donor-introductions	BIRDS + BEES: Egg and Sperm Donor Introductions	\N	\N	We are a boutique introduction service. We introduce clients who need donor egg and/or sperm to vetted donors – with the specific attributes that clients require – who will only donate to one family.	\N	\N	\N	\N	\N	\N	\N	\N	\N
101	rho	birth-beginnings	Birth Beginnings	4187 Sutherland Crescent\nBurlington, L7L 5G3	\N	Birth Beginnings has been and trusted source for educating, empowerment and support for expectant and new families since 2001. Clients appreciate the passion, care, skills, and ability to present balanced information in a comfortable unbiased way. Parents feel heard, validated, at ease, and completely prepared.\nWe provide birth, postpartum and bereavement support, as well as engaging, informative, practical prenatal classes that take parents beyond what to expect. They come away feeling confident and excited about the next phase of their journey.	michelle@birthbeginnings.com	\N	9054648076	L7L	\N	\N	Michelle Hache\nBirth, Postpartum and Bereavement doula, Childbirth Educator	\N	https://birthbeginnings.com/
102	rho	birth-boss-maternity-care	Birth Boss Maternity Care	Toronto	\N	Birth Boss is all about helping parents-to-be feel empowered in their journey to parenthood. Founded in modern neuroscience and ancient healing traditions, the Birth Boss approach to support aims to prevent the exhaustion and depletion so many modern moms and dads experience today. As a full spectrum doula service, Birth Boss supports all families and experiences – 110% judgment-free.	INFO@thebirthboss.com	\N	4169089052	\N	\N	\N	Rhiannon Langford\nCertified Stillbirthday Birth & Bereavement Doula; Maternal Support Practitioner	\N	https://www.thebirthboss.com
103	rho	birth-support-services	Birth Support Services	78 Wellington Road\nLondon, N6C 4M8	\N	Support for women and their families during the childbearing years. Our services are designed to provide you with knowledge of all your options through our Lamaze Childbirth Classes, our one-to-one doula support during birth and postpartum and our parenting programs. We offer a range of services for this very important time in your life. Discover the doula difference at www.babeezeinarms.com – Everyone differs a positive birth experience!	jill@babeezeinarms.com	\N	519-673-4441	N6C	\N	\N	\N	\N	https://www.babeezeinarms.com
104	rho	black-coalition-for-aids-prevention	Black Coalition for AIDS Prevention	20 Victoria Street\nToronto, M5C 2N8	\N	Our Harm Reduction Program seeks to reduce harms associated with substance use within Toronto’s African, Caribbean and Black Community (ACB) serving those that identify as Gay, Queer, Bi or Questioning and other Men who sleep with Men (MSM), as well as Transgender and other non-binary people. Our outreach activities seek to meet the unique needs of our communities “where they are at” to reduce the risk of HIV and STI infections, communicable diseases (i.e. HEP C), criminalization, overdose, and violence. These activities include community outreach at local events, bars, clubs and bathhouses, as well as housing two drop-ins, one for MSM and one for Trans and other non-binary people.	j.nagy@black-cap.com	\N	4169779955	M5C	\N	\N	Jacob Nagy	\N	https://www.blackcap.ca/
105	rho	black-coalition-for-aids-prevention-black-cap	Black Coalition for AIDS Prevention (Black CAP)	20 Victoria Street\nToronto, M5C 2N8	\N	Black CAP is an organization that works to reduce HIV/AIDS in Toronto’s Black, African and Caribbean communities and enhance the quality of life of Black people living with or affected by HIV/AIDS. HIV/AIDS is spreading quickly in Toronto’s Black communities and we believe that our work is more important than ever. At this time, Black, African and Caribbean people account for more than one-fifth of all new HIV infections in Toronto, in the early nineties we made up only one-tenth of new HIV infections. Issues of HIV related stigma and discrimination, homophobia, anti-Black racism, immigration, poverty, and barriers to social inclusion also continue to make our work harder.\nBlack CAP provides a wide range of free, confidential supportive and practical services to men, women, youth and children living with HIV/AIDS. We also offer support to their friends, partners, family and caregivers, and to those at risk for HIV infection. We also work with LGBT communities to address the challenges and barriers they experience in our community.	info@black-cap.com	\N	(416) 977 - 9955	M5C	\N	\N	\N	\N	https://www.black-cap.com/
106	rho	black-creek-community-health-centre	Black Creek Community Health Centre	1 York Gate Boulevard\nToronto, M3N 3A1	\N	BCCHC is a non-profit community based organization that provides health care services in a holistic manner and works with people to create safe and healthy communities.\nErin Barnes, NP has training in provision of trans primary care, hormone therapy, and surgical assessment and referral.	\N	\N	416-246-2388	M3N	\N	\N	\N	\N	https://www.bcchc.com/
107	rho	bloor-park-physio-and-rehab	Bloor Park Physio and Rehab	726 Bloor Street West\nToronto, M6G 1L4	\N	Physiotherapy & Massage Therapy	Contact@bloorparkphysio.ca	\N	647-368-4400	M6G	\N	\N	Charles Azulay\nRMT	\N	https://bloorparkphysiotherapy.ca/
108	rho	blueberry-therapy-massage-therapy-for-children	Blueberry Therapy – massage therapy for children	14 Cross Street\nHamilton, L9H 2R4	\N	Providing massage therapy treatment to children from ages 3 weeks to 18 years.	Halexanderrmt@gmail.com	\N	647 638 8186	L9H	\N	\N	Heather Alexander-Clark\nRegistered Massage Therapist, Pediatric Specialist	\N	https://www.blueberrytherapy.ca
1016	rho	west-lambton-community-health-centre	WEST LAMBTON COMMUNITY HEALTH CENTRE	429 Exmouth Street\nSarnia, N7T 5P1	\N	LGBTQ and transgender healthcare	AHALFPENNY@NLCHC.COM	\N	519-344-3014	N7T	\N	\N	Alana Halfpenny\nPRIMARY CARE NURSE PRACTITIONER	\N	https://www.nlchc.com/
109	rho	bluebird-laser	Bluebird Laser	324 Bloor St. West\nToronto, M5S 1W5	\N	Laser hair removal with a focus on trans, non-binary and queer folks.	hello@bluebirdlaser.com	Wednesday to Saturday, 9am-5pm	647-282-5083	M5S	\N	\N	Djuna Day\nLicensed medical esthitician and laser hair removal technician	\N	https://www.bluebirdlaser.com
110	rho	blueprint-counselling-2	Blueprint Counselling	London, N6B2M2	I can provide secondary assessments for transition-related bottom surgeries	It takes a lot of courage to reach out for help and we’re so glad you’re here. We believe mental health care should be collaborative, inclusive and personalized based on your values, goals and lived experienced.\nWe are group of LGBQ+, Trans, Non-binary and Poly affirming psychotherapy providers who provide individual, couple and group counselling to youth (12+) and adults. We have counsellors with specific expertise in gender transition, sexual identity exploration, mental health, substance use, grief, trauma and ADHD who will meet you where you are at and help you get where you are going. We are proud to offer the services of providers who are queer trans, indigenous and neurodivergent (ADHD).\nWe know how hard you’ve been working to keep it all together and we want to help. We will work with you to create a meaningful life full of authenticity and self-compassion. Let us know when you’re ready to get started.	info@bpcounselling.com	Monday - Thursday 8:30 AM - 9:00 PM Friday 8:30 AM - 5:30 PM	2262128272	N6B	\N	Sliding scale range - $/Hour Minimum: 90 Maximum: 150	\N	\N	https://www.bpcounselling.com
111	rho	bode-spa-and-electrolysis	Bodé Spa And Electrolysis	156 Parliament Street\nToronto, M5A 2Z1	\N	Bodé Spa is a queer-owned business that provides esthetic services in a private (one-on-one) setting. We are an inclusive space that accepts everyone, not just cis-gendered men. We have trans men, trans women, and non-binary/gender fluid clients who enjoy the private environment and the personable, educational services that we deliver.\nThe spa industry and the education therapists receive is almost entirely geared for women. For that reason, we have branded ourselves as a spa for men due to the specialized education we provide our therapists and the services that we offer to clients.\nWe provide electrolysis (permanent hair removal), which is a popular service for trans women and trans men interested in undergoing gender affirming surgeries. It is also popular in facial hair removal and removing any other unwanted body hair.\nBesides electrolysis, we offer a variety of esthetic and relaxation services; facial skin care, therapeutic pedicures, body hair removal (waxing, shaving and clipping), massages, etc.	toronto@bodespa.com	Monday to Friday: 10 am to 8pm Saturday: 10am to 6pm Sunday: 11am to 5pm	647-688-0338	M5A	\N	\N	Aharon Trottier	\N	https://www.bodespa.com
112	rho	body-beautiful-clinic	Body Beautiful Clinic	660 Fischer-Hallman Road\nBody Beautiful Clinic\nKitchener, N2E 1L7	\N	Safe and permanent hair removal in a caring and friendly environment. Single use disposable needles, regular public health inspections, hospital level sterilization.\nIf you have any questions or concerns please feel free to contact us.	bodybeautifulclinic@icloud.com	Monday to Tuesday: 9 a.m. - 5:00 p.m. Wednesday: 9 a.m. - 2:30 p.m. Thursday to Friday: 8:30 a.m. - 2:30 p.m.	519-574-3132	N2E	\N	Complete price list is available on my website	Christina L Watson\nElectrologist	\N	https://www.bodybeautifulclinic.com
113	rho	bodymed-rehabilitation-centre	Bodymed Rehabilitation Centre	205 Marycroft Avenue\nVaughan, L4L 5X7	\N	Physiotherapy, Acupuncture, Chiropody, massage therapy, Weight loss, Sportstherapy, leave smoking, Motor vehicle accidents, Pre natal massage, Infertility, Stress management, shockwave therapy, pelvic floor therapy	seobodymed@gmail.com	\N	9052658870	L4L	\N	\N	Body med\nBodymed	\N	https://www.bodymed.ca/woodbridge-therapy/chiropractor-woodbridge-vaughan/
114	rho	bonnie-simpson-counselling-and-psychotherapy	Bonnie Simpson Counselling and Psychotherapy	\N	\N	Both short and long term work focusing primarily on relationship issues, stress, anxiety and depression, coming out, internalized homophobia, childhood trauma and aging.\nSliding scale available.	\N	\N	\N	\N	\N	\N	\N	\N	\N
115	rho	bonnielynn-marker-asl-english-interpreter	Bonnielynn Marker ASL/English Interpreter	88 Crockford Boulevard\nToronto, M1R 5B6	\N	I am a queer identified ASL/English interpreter providing interpretation services to Deaf and hard-of-hearing members of the queer community for over 20 years. I work on a freelance basis. Generally I am booking about two weeks in advance.	barkerbl@mac.com	\N	6479921499	M1R	\N	\N	Bonnielyn Barker\nCOI, B.Sc., AVLIC	\N	\N
116	rho	bournetherapy-work-life-care	Bournetherapy Work. Life. Care	55 Fernwood Park Avenue\nToronto, M4E 3E9	\N	Confidential individual, couple and family counselling by experienced Certified EMDR psychotherapist; offices located near transit in the Beaches area of Toronto, (Beech or Main subway stattion) or highway access from 401/ Kingston Road. Coverage with Blue Cross, FNIH, NIHB, auto insureres and most extended health plans.	bournetherapy@gmail.com	\N	416 694 9995	M4E	\N	\N	Valerie Bourne\nMSW, Certified EMDR (Eye Movement Desensitization and Reprocessing) an evidence-based treatment for trauma	\N	https://www.bournetherapy.com
117	rho	brampton-optometrists	brampton optometrists	791 Bovaird Drive West\nBrampton, L6X 0T9	\N	Eye Doctor providing eyecare services with comprehensive eye exams to patients in Brampton and the GTA.	bramptonoptometrists@gmail.com	\N	9057825211	L6X	\N	\N	tanu bansal	\N	https://www.bramptonoptometrists.com
118	rho	brent-rousseau-massage-therapist	Brent Rousseau, Massage Therapist	42 Chester Hill Road\nToronto, M4K 1X3	\N	For treatment of muscle injuries, pain and stress management and enhancement of physical health and well being. Day, evening, and weekend appointments available. Insurance coverage. Visa and MC accepted, free parking. 416-708-3996 Broadview/Danforth.	rbrentr@rogers.com	\N	4167083996	M4K	\N	\N	Brent  Rousseau\nRegistered Massage Therapist	\N	https://brentrousseau.com/
119	rho	breslau-pharmacy-wellness-centre-2	Breslau Pharmacy Wellness Centre	\N	\N	We are an independently owned community pharmacy dedicated to providing exceptional pharmaceutical care and patient-centered services.	office@breslaupharmacy.com	\N	519-213-4444	\N	\N	\N	Pharmacy	\N	https://www.facebook.com/breslaupharmacy/
120	rho	brian-konik-msw-rsw-toronto-psychotherapy-consultation	Brian Konik MSW, RSW – Toronto Psychotherapy & Consultation	95 St Joseph St\nUnit 106\nToronto, M5S 3C2	\N	My clients talk about deteriorating relationships, unsatisfying sex, infidelity, coming out, feeling overwhelmed, depression, and trans identity. They also talk about substance use, feeling like an “impostor” at work, surviving after a trauma, body image, HIV, oppression, and fitting in. I provide both brief and long term therapy.\nI don’t believe the person is the problem, I believe the problem is the problem. In a compassionate environment we will work together on what’s important to you. I want to hear your story.	info@briankonik.com	See website	647-483-7100	M5S	\N	145	Brian Konik\nBA, BSW, MSW, RSW	\N	https://www.briankonik.com
269	rho	dr-elspeth-evans-ph-d-psychologist	Dr Elspeth Evans, Ph.D., Psychologist	London, N5Y 3H5	\N	Clinical and Counselling Psychologist with experience working on Western University’s Trans Care Team, now working in private practice in London, ON.	drelspethevans@gmail.com	9-5 Monday-Thursday	519-200-4895	N5Y	\N	\N	\N	\N	http://oldnorthpsychology.ca
121	rho	brillig-house-counselling-psychotherapy	Brillig House Counselling & Psychotherapy	16 Dundas Street East\nUpper Unit\nNapanee, K7R1H6	\N	Brillig House Counselling & Psychotherapy offers LGBT2SQ-friendly and affirmative therapy for both couples and individuals.\nCouples therapy is completed using an Emotion-Focused Therapy modality.\nService is private pay, but covered under many private benefit plans.\nPlease contact me, Michael Wade, MSW, RSW for further information.	michael@brillighouse.ca	Monday-Thursday 9am-5pm	613-561-6878	K7R	\N	$165-$185/session	Michael Wade\nMSW, RSW	\N	https://www.brillighouse.ca
122	rho	brittney-hartwick-m-s-w-r-s-w	Brittney Hartwick M.S.W., R.S.W.	Windsor , N8X 4W2	\N	Inclusive and affirming counselling  for teens and adults with life transitions, anxiety, stress, self- esteem and relationships.	bhartwickrsw@gmail.com	Monday, Tuesday, Friday 8:30 to 4:30 pm Wednesday, Thursday 9:00 am to 6:30 pm	+1-226-243-0537	N8X	\N	$110 per session	Brittney Hartwick\nM.S.W.,R.S.W	\N	https://www.psychologytoday.com/ca/therapists/brittney-hartwick-windsor-on/850234
123	rho	brookside-psychologists	Brookside Psychologists	274 Fourth Avenue\nUnit 4\nSt. Catharines, L2R 6P9	I can provide transition related surgery assessments for top or bottom surgeries\nI can provide secondary assessments for transition-related bottom surgeries	Brookside Psychologists is a healthcare group made up of clinical psychologists, neuropsychologists, registered psychotherapists, and supervised therapists. We provide treatment and diagnostic testing for a range of conditions. Services are provided for children, teens, adults, and seniors. We help couples and parents.\nWe offer affirmative counselling and assessment services to people presenting with LGBTTIQ+ related issues and to determine readiness for gender affirming hormone therapy and gender affirming surgery. Support for trans-partners offered as well.\nWe have two office locations – in Burlington and St. Catharines. and we provide video and telephone counselling to help clients throughout the province.	adminsc@brooksidetherapy.com	Monday through Friday 9 am - 7 pm Saturday 10 am - 6 pm	905-641-0789	L2R	true	$125-$225 per hour	Office Manager	\N	https://www.brooksidetherapy.com
124	rho	bruno-jung-millen-msw-rsw-counselling-and-family-services	Bruno Jung-Millen, MSW, RSW Counselling and Family Services	160 Bristol Crescent\nKemptville, K0G 1J0	I can provide secondary assessments for transition-related bottom surgeries	Our society has come a long way in recognizing the human rights of individuals who identity as 2SLGBTQIA+. Yet, these individuals are still facing discrimination at both systemic and community levels based on their gender expression and sexual orientation.\nWe have to do more and better. As a queer clinician, I offer affirmative therapy services in combination with other clinical approaches for individuals including children and youth who are struggling with their gender and sexual identities, or for those who simply wish to find a queer clinician who can provide a safe space. Additionally, I am honored to work with those individuals who are living with HIV/AIDS.\nImportant Note:\nI also work with families to support their children who are transitioning or identify as 2SLGBTQIA+, or those parents/caregivers who are struggling to accept their child’s gender and sexual identity.\nI do not provide religious-based counselling and psychotherapy services.	contact@brunojungmillenmswrsw.com	Our availability is generally weekdays 3:30pm-10:30pm and weekends 8:30am-12:30pm & 8:30pm-10:30pm.	6134006430	K0G	\N	$150.00 per 1-hour individual therapy session / $180.00 per 1-hour couples and family therapy session\nSliding scale range - $/Hour Minimum: 85.00	Bruno Jung-Millen\nMSW, RSW	\N	https://www.brunojungmillenmswrsw.com/
125	rho	bryan-chung-md-phd-frcsc	Bryan Chung MD, PhD, FRCSC	333 Sherbourne St\nToronto, M5A2S5	\N	Dr. Chung is plastic surgeon with fellowship training in gender-affirmation surgery. He is willing to see clients for pre-operative information consultation, post-surgical care, and currently offers top surgery (not fully covered by OHIP).	\N	M-F 9:00am to 4pm	416-324-4100	M5A	\N	\N	Dr. Bryan Chung\nMD, PhD, FRCSC	\N	https://drbryanchung.ca
126	rho	bulimia-anorexia-nervosa-association-windsor	Bulimia Anorexia Nervosa Association Windsor	1500 Ouellette Avenue\nWindsor, N8X 1K7	\N	We are dedicated to the promotion and acceptance of diverse body shapes and sizes through the adoption of a healthy, balanced lifestyle.We know that having an eating disorder is a complex and distressing experience. At BANA we believe that each person coming to therapy is unique, attempts to do the best possible with the resources available, has wisdom, creativity and strength, and is the authority in their life.\nWe believe that counselling means providing a safe place for you to tell your story, for us to have a conversation and to work together. We use an integrative approach to therapy that is based in the best eating disorder practices.\nThese treatment services may include, but are not limited to:	info@bana.ca	\N	519.969.2112	N8X	\N	\N	\N	\N	https://www.bana.ca/
127	rho	burlington-psychological-and-counselling-services	Burlington Psychological and Counselling Services	2289 Fairview Street\nBurlington, L7R 2E4	\N	Burlington Psychological and Counselling Services (BPCS) is a clinical psychology practice that offers assessment and treatment services to children, adolescents and adults. It employs Ph.D. level clinical psychologists with extensive experience in cognitive-behaviour therapy (CBT) treatments for a wide variety of issues. Some clinicians have additional training in mindfulness and acceptance-oriented treatment approaches. Occasionally we also have doctoral candidates working under the direct supervision of a registered psychologist. We maintain professional relationships and work collaboratively with Family Physicians, Psychiatrists, Social Workers, Educational Consultants, Occupational Therapists, and Speech and Language Specialists.\n\nCounselling is provided in a supportive, confidential and professional environment. Treatment is collaborative and problem-focused in nature, with an emphasis on helping clients develop and practice new skills to be implemented in their daily lives. CBT treatment is designed to help clients achieve personal goals and become more confident in managing their unique areas of difficulty.	info@burlingtonpcs.com	\N	905.631.9991	L7R	\N	\N	\N	\N	https://www.burlingtonpcs.com/
128	rho	caledon-community-services	Caledon Community Services	18 King Street East\nCaledon, L7E 1E8	\N	Caledon Community Services (CCS) is a multi-service, community-based organization that addresses needs of residents in the Municipality of Caledon. Its vision is helping people help themselves. CCS services help all residents of the community pursue their growth, health and independence while seeking solutions to those barriers that interfere with any aspect of their well-being. The success of CCS is based on client-focused services program innovation, volunteerism and a myriad of partnerships, as well as on strong support from all sectors of the Caledon community.\nCCS has services specifically for: seniors, job seekers, newcomers to Canada and small business owners.	info@ccs4u.org	\N	905-584-2300	L7E	\N	\N	\N	\N	https://www.ccs4u.org
274	rho	dr-james-tyler-md-family-doctor-barrie	Dr James Tyler, MD – Family Doctor Barrie	125 Bell Farm Road\nBarrie, L4M 6L2	\N	Family Physician in Barrie, ON who has training to provide LGB health care and trans health care including hormone therapy.	\N	\N	705-792-2145	L4M	\N	\N	James Tyler\nMD	\N	https://barriefht.ca/
129	rho	camp-ten-oaks-and-project-acorn	Camp Ten Oaks and Project Acorn	251 Bank Street\nOttawa, K2P 1X2	\N	The Ten Oaks Project is a charitable, volunteer-driven organization that engages and connects children and youth from LGBTQ+ (lesbian, gay, bisexual, trans, two-spirit, queer) identities, families and communities through summer camp programs and community events.	info@tenoaksproject.org	\N	613-614-1537	K2P	\N	\N	Ontario Camps Association	\N	https://www.tenoaksproject.org
130	rho	canadian-centre-for-victims-of-torture-2	Canadian Centre for Victims of Torture	\N	\N	CCVT is a non-profit, registered charitable organization which aids survivors to overcome the lasting effects of torture and war.\nCCVT has many programs to support victims of torture and war including:  Counselling, Support groups, Crisis intervention, Coordinated professional services, Settlement services, ESL,  Language and Computer classes\nCCVT offers services in the following languages: English, French, Spanish, Dari, Farsi, Somali, Tamil, Amharic, Tigrinya, Arabic.	\N	\N	416-363-1066	\N	\N	\N	\N	\N	https://ccvt.org/
131	rho	canadian-memorial-chiropractic-college	Canadian Memorial Chiropractic College	6100 Leslie St.\nNorth York, M2H 3J1	\N	CMCC’s largest program is a second entry four-year Doctor of Chiropractic degree based on an evidence-based model of care, derived from the most recent research and best practices. Our four year Doctor of Chiropractic Program provides an integrative curriculum, aligned with CMCC’s Model of Care: Chiropractic is a primary contact health care profession with expert knowledge in spinal and musculoskeletal health, emphasizing differential diagnosis, patient centred care, and research. The curriculum ensures that beginning in Year I, and increasingly throughout the program, students learn to integrate and apply theoretical knowledge to clinical practice, patient care and management.\nTaught in a series of four modules per academic year, courses and content are layered over single or multiple modules to facilitate the essential integration of knowledge, skill and practice.\nIn Year I and Year II, students build their foundation of knowledge in basic sciences and pathology for clinical skills and decision making while also getting hands on experience through courses in chiropractic skills, diagnosis and symptomatology, orthopaedics and diagnostic imaging.\nYear III emphasizes knowledge integration through the use of case-based clinical material to prepare students for internship in the CMCC clinics.\nYear IV is a 12 month clinical internship in two of CMCC’s clinical settings where interns provide direct care and education to patients under the supervision of a licensed chiropractor. Year IV students also engage laboratory clerkships and advanced diagnostic imaging, public health and business management.	jawingrove@cmcc.ca	Monday - Saturday 8 am - 8 pm	4164822340	M2H	\N	$25	Dr. Anthony Tibbles\nDC	\N	https://cmcc.ca/
132	rho	canadian-mental-health-association	Canadian Mental Health Association	Barrie, L4N 7L3	\N	Working in partnership with the Gilbert Centre in order to provide a safe space for LGBT2SQ folks. The service provides LGBT2SQ positive 1-1 mental health and addictions therapy/counselling, emotional support for trans folks who are beginning their transition journey, LGBT2SQ family member support, LGBT2SQ relationship issues support, community referrals, and supportive coping skills related groups.	claws@cmhastarttalking.ca	\N	705 726 4225 ext. 2627	L4N	\N	\N	Charlotte Laws\nPsychotherapist, RP	\N	\N
133	rho	canadian-mental-health-association-champlain-east-branch-prescott-russel-2	Canadian Mental Health Association – Champlain East Branch (Prescott & Russel)	\N	\N	CMHA Champlain East offers a range of programs and services designed to enhance the rehabilitation, recovery and independence of individuals living with a severe mental illness or concurrent disorder (mental illness combined with substance use disorder).\n-Intensive Case Management\n-Family Support\n-Peer Resource Centers\n-Court Support & Diversion	\N	\N	613-938-0435	\N	\N	\N	\N	\N	https://www.cmha-east.on.ca/index.php
134	rho	canadian-mental-health-association-gilbert-centre	Canadian Mental Health Association/Gilbert Centre	80 Bradford Street\nBarrie, L4N 6S7	\N	Located at Gilbert Centre once a week to provide safe space for LGBT2SQ folks. Providing:\n-An LGBT2SQ affirming approach.\n-1-1 mental health and addictions counselling support.\n-Support to those folks who are beginning their transition journey, coming out, questioning, having difficulty in relationships etc.\n-Community based referrals as needed.\n-Co-facilitation of mental health based wellness groups.	claws@cmhastarttalking.ca	\N	705-726-4225 ext 2627	L4N	\N	\N	Charlotte Laws\nRP	\N	\N
135	rho	canadian-mental-health-association-nurse-practitioner-led-clinic	Canadian Mental Health Association Nurse Practitioner-Led Clinic	60 Bond Street West\nOshawa, L1G 1A5	\N	Nurse Practitioner-Led Clinics (NPLC) offer an innovative solution to improve access to high-quality health care in Ontario.\nNurse Practitioner-Led Clinics integrate health promotion, disease prevention, chronic disease management and care coordination for clients of all ages and their families. Additionally, CMHA Durham NPLC provides specialized mental health care to diagnose, monitor and treat symptoms of mental illness in a safe and supportive environment.\nNurse Practitioner Led Clinic Hours of Operation:\nMonday- Friday: 9:00am-4:00pm\nExtended Hours are offered on Tuesday: 3:30pm-6:00pm\nPotential client’s can self-refer through CMHA Durham’s Intake Services, accessible by walk-in or by phone (905-436-8760).	\N	\N	905-436-9945	L1G	\N	\N	Stephanie Skopyk\nRN(EC)	\N	https://cmhadurham.ca/primary-care/nurse-practitioner-led-clinic/
136	rho	candice-lawrence-counselling	Candice Lawrence Counselling	1001 Fanshawe College Boulevard\nLondon, N5V 2A5	\N	Service is free to all full-time Fanshawe College students. Counselling and therapeutic support, career advising and assessments. Positive Space Trainer for faculty and staff. Co-founder of the College’s grassroots Violence Prevention Initiative focusing on on-campus sexual violence.. Counselling support for eating disorders, relationship issues, sexuality concerns, gender identity, coming out, depression, anxiety, trauma, sexual abouse, community resources referrals.	clawrence@fanshawec.ca	\N	519-452-4282	N5V	\N	\N	Candice Lawrence\nM.Ed, R.S.W.	\N	https://www.fanshawec.ca/what-can-counselling-services-do-you
137	rho	capreol-nurse-practitioner-led-clinic-2	Capreol Nurse Practitioner Led Clinic	\N	\N	We provide comprehensive interdisciplinary primary care to our community	\N	\N	7058588787	\N	\N	\N	Capreol Nurse Practitioner Clinic\nNurse Practitioner	\N	https://capreolnplc.com
138	rho	cardinal-counselling	Cardinal Counselling	420 Weber Street North\nWaterloo, N2J 3H8	\N	Cardinal Counselling is a full service, privately funded counselling organization with multiple counsellors. We are experienced working with the LGBTQ+ population and provide services including individual counselling and relationship counselling. We do not have a wait list, and offer flexible appointment times.	cardinal@golden.net	Monday to Friday 9 a.m. to 7 p.m.	519-746-9062	N2J	true	\N	Joy Lang\nMSW, RSW	\N	https://www.cardinalcounselling.com
270	rho	dr-elyse-levinsky-obgyn	Dr. Elyse Levinsky – OBGYN	600 University Avenue\nToronto, M5G 1X5	\N	Dr. Elyse Levinsky is a General Obstetrics and Gynaecology Physician at Mt. Sinai hospital. She is LGBTQ affirming and will treat trans guys for pregnancy and non-pregnancy related gynecological conditions and surgery	\N	\N	416-586-4800, ext. 3108	M5G	\N	\N	Dr. Elyse Levinsky\nM.D.	\N	https://www.mountsinai.on.ca/for-physicians/physician-referral-listing/obstetrics-gynaecology
139	rho	carea-chc	Carea CHC	5-360 Bayly Street\nAjax , L1S 1P1	I can provide transition related surgery assessments for top or bottom surgeries\nI can provide secondary assessments for transition-related bottom surgeries	The Gender Care IPC team aims to create a safe, confidential, inclusive, and affirming space for trans, gender expansive, gender non-conforming, non-binary and questioning youth and adults in the Durham Region.\nThe Team includes a Nurse Practitioner and Systems Navigator who provide gender transition related care and services within a holistic framework for a time-limited length of service.\nSpecific services include social, legal and medical transition support, hormone related therapy, surgery referral support, advocacy, and health system navigation. We also offer support, education, and resources for families and caregivers of our clients.\nWe tailor our services to the needs and transition goals of our clients. Clients may retain their primary care providers while seeking gender transition related care from the team and upon completion of goals will be transferred back to their providers. Medical issues not related to gender transition will be directed back to primary care providers.\nIf you are interested in our services or would like to refer someone, please complete a Referral Form.\nPlease do not email confidential health information.  You can fax the completed form to our confidential medical fax at:  905-428-9151 or you can drop it off. Self-referrals are also accepted.	cdoughty@careachc.ca	Appointment Hours: Monday to Friday: 8:30am to 4:30pm Site Hours: Monday to Friday: 8:30am to 5:00pm	905-428-1212	L1S	\N	\N	\N	\N	https://www.careachc.ca/Clinical-Services/Primary-Care/Gender-Care-Interprofessional-Primary-Care-IPC-T
140	rho	carespace-healthwellness	CARESPACE Health+Wellness	564 Weber Street North\n##12\nWaterloo, N2L 5C6	\N	A proud member of KW’s LGBTQ community Michael’s naturopathic experience and knowledge benefits men, women and children of all ages. Areas of special interest within his practice include, but aren’t limited to, pain management, hormonal imbalance, weight management, chronic disease, men’s health, and mental health. He is certified in Precision Nutrition, a program for developing healthy eating habits, and has completed a Mind/Body Medicine Certification from Harvard Medical School. He looks forward to helping his patients attain their physical and mental best through the benefit of holistic medicines and lifestyle. Please see https://carespace.health/ for more information about treatments and services offered.	mtorreiter@carespace.health	Monday to Friday 10 AM to 6 PM	5192082273	N2L	\N	\N	Michael Torreiter\nNaturopathic Doctor	\N	https://carespace.health/
141	rho	caress-electrolysis-ltd	Caress Electrolysis Ltd	35 Larkin Dr\nNepean, K2J 2T2	\N	The professionals at Caress Electrolysis Ltd. are a team of conscientious certified electrologist’s who are dedicated to helping people rid themselves of unwanted hair permanently and as a result, improving their self-esteem. At Caress we are pleased to offer a professional clinic with state of the art equipment.\nWe provide a private, safe and comfortable ambiance and assure complete confidentiality to all clients regardless of race, gender, gender identity and/or expression or sexuality.  We will assess each client individually to determine the best treatment schedule to fit their budget, time and expectations.\nAt Caress we offer a complimentary consultation and sample treatment.  During the consultation we will explain the procedure, perform a sample treatment so we can examine your area and  provide you with a treatment plan.  Then as an informed consumer you will have the information you need to decide whether to proceed.\nAt Caress we also offer skin anomaly treatments. Thermo-coagulation, is a process that will improve your skin’s appearance by reducing or eliminating unwanted skin anomalies. The anomalies we are able to treat are skin tags, cherry angiomas, milia, angiokeratomas, traumatized pores, unwanted piercings, pigmented spots, keratoses and visible facial capillaries.\nClients are continually informing us how pleased they are that they started treatments, and the only regret is that they didn’t start sooner. So many misconceptions and fears that people have concerning electrolysis will disappear after a complimentary consultation. We promise to do our best to ensure your treatment is the most pleasant and comfortable experience.\nDon’t wait any longer to dispel your apprehension, make an appointment today.	Info@CaressElectrolysis.com	Monday 9 am to 8 pm Tuesday 9 am to 8 pm Wednesday 9 am to 8 pm Thursday 9 am to 8 pm Friday 9 am to 6 pm Saturday 9 am to 4 pm	6138252299	K2J	\N	Some health care plans cover partial payment of services performed on the face. Check with your insurance provider.	\N	\N	https://www.CaressElectrolysis.com
142	rho	carey-lawford-msw-rsw-psychotherapist	Carey Lawford, MSW, RSW / Psychotherapist	Toronto, M4C 1J7	I can provide secondary assessments for transition-related bottom surgeries		carey@careylawford.com	Virtual Sessions - Evenings/Weekends	(647) 696-5198	M4C	\N	$140.00 - $175.00	Carey Lawford\nSocial Worker - BSW, MSW, RSW	\N	https://www.psychologytoday.com/ca/therapists/carey-lawford-toronto-on/404646
143	rho	carleton-university-health-and-counselling-services	Carleton University Health and Counselling Services	1125 Colonel By Drive\nSuite 2600 CTTC Building\nOttawa, K1S 5B6	I can provide transition related surgery assessments for top or bottom surgeries\nI can provide secondary assessments for transition-related bottom surgeries	Family Medicine & Psychotherapy/Counselling for Carleton University students and permanent staff ONLY. Services include gender-affirming hormone care, mental health care, transition-related surgery assessments, care of trans youth, sexual health, PrEP, fertility planning, and comprehensive family medicine and psychotherapy for LGBTQ+ patients. MD has completed post-residency PGY3/Enhanced Skills Program focused on increased competency in LGBTQ+ Health. Book by phone; email is for cancellations only.	hcs@carleton.ca	Monday to Friday 8:30 a.m. to 4:30 p.m	613-520-6674	K1S	\N	\N	Dr. Anna York-Lyon\nMD, CCFP	\N	https://carleton.ca/health/
144	rho	carlton-and-church-walk-in-clinic	Carlton and Church Walk-In Clinic	60 Carlton Street\nToronto, M5B 1J2	\N	The Carlton & Church Medical & Walk-In Clinic is a new WALK-IN clinic located inside the Loblaws store (at Maple Leaf Gardens) beside the pharmacy. The building is located on the corner of Carlton and Church. Visit our website for full details.\nHighlights:\n– No Appointment Necessary\n– Pharmacy on site\n– Open 7 days / week\n– Underground parking	info@primacy.ca	\N	(416) 646-1890	M5B	\N	\N	\N	\N	https://www.health-local.com/clinic/walk-in-clinics/toronto/ontario/carlton-church-medical-walk-in-clinic
145	rho	carrie-l-greig-registered-psychotherapist	Carrie L. Greig, Registered Psychotherapist	Waterloo	\N	I am a Registered Psychotherapist (RP) and a Clinical Member of the Ontario Society of Psychotherapists (OSP). I am a Canadian Certified Addiction Counsellor (C.C.A.C.) and I hold membership in good standing with the Canadian Addiction Counsellors’ Certification Federation. Currently, I am enrolled in Level 2 Trauma Training with the Sensorimotor Psychotherapy Institute (SPI).\nI have a Master of Arts degree in Community Health Sciences (Brock University) and a Post-Graduate Diploma in Addicitons: Treatment & Prevention (Georgian College).\nI have over 15 years of experience in both inpatient, outpatient, and private practice settings working with individuals seeking recovery and wellness from issues related to stress and anxiety, trauma, substance use, sexual orientation and gender identity. My approach to psychotherapy is client-centered and from an anti-oppressive framework. Other areas of clinical interest include integrating mindfulness-based approaches, using the body in psychotherapy (sensorimotor psychotherapy) to heal attachment injuries and trauma.	carrielgreig@gmail.com	\N	\N	\N	\N	\N	Carrie Greig\nRP., MA, C.C.A.C.	\N	\N
146	rho	catholic-family-services-of-hamilton	Catholic Family Services of Hamilton	447 Main Street East\nHamilton, L8N 1K1	\N	At CFS of Hamilton we pride ourselves on offering high-quality, evidence-based counselling that is provided by a team of experienced counsellors and Master’s degree interns who provide counselling under supervision. All of our counsellors provide professional services in a safe, supportive and strength-based ways. All of our full-time employees have Master’s degrees and are registered counsellors in good\nstanding with the College of Registered Psychotherapists of Ontario or the Ontario College of Social Workers and Social Service Workers.\nWe believe that diversity and inclusion are key drivers of creativity and innovation. Diversity includes individuals from all nations, cultures, ethnic groups, sexual orientations, generations, backgrounds, skills, abilities, and all the other unique characteristics that make each of us who we are.	intake@cfshw.com	\N	905-527-3823	L8N	\N	\N	Julie Hansen\nIntake Coordinator	\N	https://www.cfshw.com
147	rho	cathy-callaghan-counsellor	Cathy Callaghan Counsellor	320 Danforth Avenue\nToronto, M4K 1N8	\N	Since 2003, I’ve worked with individuals around issues of addiction, gender identity, sexual orientation, oppression, mood, relationships, loss and grief, self-esteem, self-harm, body image, and trauma.\nI have a bright, comfortable office in the Danforth and Chester area and have day and evening appointments available. Many insurance companies cover my services. Fees for clinical social work services are also eligible for the Medical Expense Tax Credit.	1cathycallaghan@gmail.com	\N	416-985-1300	M4K	\N	\N	Cathy Callaghan\nMSW, RSW (Registered Social Worker)	\N	\N
148	rho	catie-canadas-source-for-hiv-and-hepatitis-c-information-2	CATIE – Canada’s Source for HIV and Hepatitis C Information	\N	\N	CATIE is Canada’s source for up-to-date, unbiased information about HIV and hepatitis C. We connect people living with HIV or hepatitis C, at-risk communities, healthcare providers and community organizations with the knowledge, resources and expertise to reduce transmission and improve quality of life.\nThe latest news about HIV and hepatitis C treatment and prevention in clear language\nResources developed in partnership with organizations across Canada\nEvents for service providers to share approaches and lessons learned:\nEducational opportunities in person and online	info@catie.ca	\N	416-203-7122 or 1-800-263-1638	\N	\N	\N	\N	\N	https://www.catie.ca/
149	rho	cbt-associates-etobicoke	CBT Associates Etobicoke	1243 Islington Avenue\nToronto, M8X 1Y9	\N	At CBT Associates we provide psychological assessment and treatment services for children, adolescents and adults.\nWe help people reach mental wellness using scientifically validated techniques to assess, diagnose and treat problems related to emotions, thoughts and behaviors.\nSpecialties:\nCognitive Behavioral Therapy, Couples Therapy, Individual Therapy, Group Therapy, Child and Adolescent Therapy, Mental Health, Psychology, Online Therapy, eTherapy	cbtaetobicoke@outlook.com	\N	437-828-2580	M8X	\N	\N	Eilenna Denisoff	\N	https://www.cbtassociates.com
150	rho	ce-counselling-psychotherapy	CE Counselling & Psychotherapy	289\nTamarack, P4N6R3	\N	CE Counselling & Psychotherapy provides a compassionate and safe space for individuals, relationships, and group therapy.  Sessions are available in person or on a secure confidential website via video platform, phone calls, or text messages.\nI work from a queer theory lens and an anti-oppressive approach with diverse clients by providing support for various reasons such as anxiety, depression, anger, career guidance, parenting, stress, chronic pain, self-esteem, communication, conflict resolution, relationships, men’s issues, LGBTQ2S+.	chantal.mann@ce-counselling.ca	Monday - Friday 10am - 7pm	705-262-0718	P4N	\N	\N	Chantal Mann\nMSW	\N	https://www.ce-counselling.ca/
151	rho	center-for-interpersonal-relationships	Center for Interpersonal Relationships	\N	\N	I offer individual short- and long-term therapy to adults with a range of presenting concerns. I have extensive clinical experience in working with individuals within the LGBT2QA community, including the assessment and treatment of gender dysphoria, as well as the intersection of mental health issues within LGBT2QA community. I am aware that psychological stressors and resulting difficulties are more prevalent within marginalized populations, including the LGBT2QA community, and thus, I have sought diverse training to meet the needs of my clients. As such, I have experience with the assessment and treatment of individuals with moderate distress as well as persistent, severe, and complex mental health concerns including trauma, anxiety, depression, psychosis, and personality disorders. While working together, I am aware of, and work directly on, systemic influences (i.e., oppression, racism, marginalization, and stigma) as well as the development of our personal identities, cultural and community connections, and resiliency.	\N	\N	\N	\N	\N	\N	\N	\N	\N
152	rho	central-community-health-centre-elgin-st-thomas	Central Community Health Centre – Elgin St Thomas	359 Talbot Street\nSt. Thomas, N5P 3T5	\N	Central Community Health Centre is a charitable organization whose purpose is the delivery of comprehensive primary care, illness prevention, health promotion and community programs and support to individuals and families in St. Thomas, Central Elgin and Southwold Township. We believe, with programming based on the social determinants of health and community needs, we can best serve the community. We provide comprehensive care through an integrated team approach to health care and prevention.\nWeekly GBLTQ support group run by Elgin Public Health hosted by CCHC. http://www.elginhealth.on.ca/index.asp?ParentID=1186& MenuID=1190	info@centralchc.com	\N	(519) 633-7989	N5P	\N	\N	\N	\N	https://www.centralchc.com/
153	rho	central-toronto-community-health-centre-queen-west	Central Toronto Community Health Centre – Queen West	168 Bathurst Street\nToronto, M5V 2R4	\N	CTCHC works as a resource to improve the health and quality of life of the communities that Queen West and Shout each serve. CTCHC achieves its mission through health promotion, education, community development, and advocacy, and through the provision of medical, nursing, dental and counselling services.\nThis community health centre provides trans specific healthcare including hormone therapy.	\N	\N	(416) 703-8480	M5V	\N	\N	\N	\N	https://www.ctchc.com/site_qw
162	rho	centrepeace-therapy-and-counselling-services	Centrepeace Therapy and Counselling Services	240 Wharncliffe Road North\nUnit 205\nLondon, N6H 4P2	\N	Counselling and Therapy for Families, Children, Teens and Adults. Affirming care for LGBT2Q+ individuals and families.\nThis practice name recently changed from “Pamela Bailey, Registered Social Worker” to “Centrepeace Counselling and Therapy Services.”\n	pamela@pamelabailey.ca	Mondays 4pm-8pm Tuesdays 10am-5pm Wednesdays 10am-8pm Thursdays 10am-5pm Alternate Saturdays 10am-2pm Closed Fridays and Sundays	5197193790	N6H	\N	$130-$180 per session	Pamela Bailey\nBSW, MSW, RSW	\N	https://pamelabailey.ca
163	rho	centretown-community-health-centre	Centretown Community Health Centre	420 Cooper St.\nOttawa, K2P 2N6	I can provide transition related surgery assessments for top or bottom surgeries	Community Health Centre	info@centretownchc.org	As per website	613-233-4697	K2P	\N	\N	Katie Maddock\nMScN, NP-PHC	\N	https://www.centretownchc.org/trans-health
154	rho	central-toronto-youth-services-ctys	Central Toronto Youth Services (CTYS)	65 Wellesley Street East\nToronto, M4Y 1G7	\N	Central Toronto Youth Services (CTYS) is a community-based, accredited Children’s Mental Health Centre that serves many of Toronto’s most vulnerable youth. We believe in building the strength and resiliency of young people in ways that are engaging, respectful and empowering.\nOur programs and services\nPride and Prejudice offers unique programs for lesbian, gay, bisexual, trans, queer and questioning youth, ages 13-24.\nThrough individual counselling and group work, our programs support youth who are challenged by a wide range of issues. Our clients may be exploring issues related to gender identity and/or sexual orientation, community, homophobia, friendships, and family. They may also need support during a life transition. We serve youth who are struggling with depression or anxiety, or confronting traumatic experiences, including childhood abuse and family violence. We help clients make sense of and cope with a variety of complex struggles. At the same time, they are encouraged to explore and embrace their own individuality and identity.\nThe Pride & Prejudice program offers a number of Groups for LGBTQ youth.\nCTYS also hosts an ongoing peer support group for parents and caregivers of transsexual and transgender youth and adults: TRANSCEPTANCE.	mail@ctys.org	\N	416-924-2100	M4Y	\N	\N	\N	\N	https://www.ctys.org
155	rho	centre-achieve-therapy-centre-2	Centre Achieve Therapy Centre	\N	\N	Speech-Language Pathologist providing voice modification therapy to transgender clients who wish to develop a voice which is more in harmony with their identities.\nOrthophoniste offrant des services de modification de la voix aux clients trans qui cherchent. À développer une voix qui est plus en harmonie avec leur identité.	sfitzpatrick@achievetherapycentre.com	\N	6132935031	\N	\N	\N	Sarah Fitzpatrick\nSpeech-Language Pathologist/Orthophoniste	\N	\N
156	rho	centre-for-abuse-and-trauma-therapy	Centre for Abuse and Trauma Therapy	234 Concession Street\nKingston, K7K 6W6	\N	The Centre for Abuse and Trauma Therapy is a non-profit, registered charity serving Kingston, Ontario and the surrounding area. The Centre provides short and long-term professional psychotherapy and support to anyone of any age who has experienced recent and/or past abuse or trauma. In addition to these services, the Centre offers community education and awareness and skills-development training to those who have experienced abuse or trauma, to the general public and to service providers in the region.	info@centrefortherapy.ca	\N	6135072288	K7K	\N	\N	Registered Psychotherapists (RP)	\N	https://centrefortherapy.ca/
157	rho	centre-for-interpersonal-relationships	Centre for Interpersonal Relationships	790 Bay Street\nToronto, M5G 1N8	\N	Centre for Interpersonal Relationships (CFIR) is an organization of independent psychologists and psychotherapists who practice scientific, evidence-based treatment interventions, such as CBT, DBT, ACT, EFT, and psychodynamic therapy.\nCFIR provides comprehensive, leading-edge mental health services to individuals, couples, groups, children, adolescents, and adults at our central downtown Toronto and Ottawa locations.\nCFIR clinicians are proud to offer services to all members of our local communities, including individuals belonging to diverse social, cultural, racial, sexual, gender and relationship identity groups.	\N	\N	1-855-779-2347	M5G	\N	\N	\N	\N	https://www.cfir.ca
158	rho	centre-for-psychology-and-emotional-health	Centre for Psychology and Emotional Health	1200 Bay Street\nUnit 403\nToronto, M5R 2A5	\N	The Centre for Psychology and Emotional Health has been providing the highest standard of evidence-based individual and couple therapy since 2003. We are also a satellite training centre for the Emotion-Focused Therapy Clinic at York University. Centrally located in downtown Toronto, we are a highly skilled team of clinicians who are committed to helping people make meaningful changes. Our therapists are compassionate, empathic, work collaboratively with you, and provide a safe therapeutic environment. Treatment is personalized and evidence-based as we use our knowledge and expertise to choose the most effective treatments to meet your unique needs.\nWe treat a wide range of psychological issues. For example, in individual therapy, we will help you deal with difficult, painful, and/or vulnerable emotions and issues, and skillfully work with you to transform them in lasting ways. In addition, if you feel stuck, unmotivated, unfulfilled, or are searching for direction or meaning, we will help you identify goals and work with you to achieve them. If you’re having issues in your relationship, in couple therapy we can help you: deal with conflict and communication issues; feel more connected; improve emotional and physical intimacy; and resolve and forgive emotional injuries.\nWe are committed to engaging in continuing education, skills training, workshops, and consultation, to ensure our knowledge is up-to-date and that we provide you with the most effective, current, evidence-based therapy for each client. We are knowledgeable and compassionate in providing services to the LGBT2Q+ community and those who are from racialized communities.\nTherapy approaches are empirically supported and include: Emotion-Focused Individual Therapy, Emotion-Focused Couples Therapy, Emotion-focused Couples Therapy for Resolving Emotional Injuries, Sex Therapy, Cognitive Behavioral Therapy, Dialectical Behavior Therapy, and Mindfulness-Based Approaches.	info@cpeh.ca	Monday to Friday - 8:00am-9:00pm Saturday - 9:00am-5:00pm Sunday - CLOSED	(416) 767-7091	M5R	\N	$200-$275	\N	\N	https://www.cpeh.ca/
159	rho	centre-for-spanish-speaking-people	Centre for Spanish Speaking People	2141 Jane Street\nToronto, M3M 1A2	\N	The Centre for Spanish Speaking People serves tens of thousands of Spanish speaking peoples in Toronto and throughout Canada each and every year. CSSP has specific programming for youth, women, settlement services, HIV/AIDS services, volunteer programming and a legal clinic.\nGeneral Information: 416.533.8545\nAIDS Program: 416.925.2800\nLegal Clinic: 416.533.0680\nWomen’s Program: 416.533.6411	\N	\N	416.533.8545	M3M	\N	\N	\N	\N	http://www.spanishservices.org/
160	rho	centrepeace-counselling-therapy-services	Centrepeace Counselling & Therapy Services	205-240 Wharncliffe Road North\nLondon, N6H 4P2	\N	Affirming counselling and therapy for children, youth, adults and families.	pamela@centrepeacelondon.ca	Mondays 1-8pm Tuesdays 1-8pm Wednesdays 9am to 5pm Thursdays 9am to 5pm Fridays 10am to 3pm	5197193790	N6H	\N	$135-$200	Pamela Bailey\nBSW, MSW, RSW	\N	https://www.centrepeacelondon.ca
161	rho	centrepeace-counselling-therapy-services-2	Centrepeace Counselling & Therapy Services	240 Wharncliffe Road North\nUnit 205\nLondon, N6H 4P2	\N	Andrew is a practitioner who works primarily with teens, young adults, and families. They also have experience working with older adults and parents of Queer youth. He is a Latinx, Non-Binary Queer person with a strong passion for helping their fellow community members of the LGBTQ2S+. Furthermore, they have extensive experience in supporting individuals who are in the process of transitioning and/or obtaining gender affirming medical care.\nHis primary interest is in helping individuals to cope and overcome challenges with emotional regulation, stress management, social skills, personal goal attainment, and self-discovery.\nAndrew takes on a mainly eclectic therapeutic approach with clients, informed by practices from a wide range of styles, including Cognitive Behavioural Therapy (CBT), Dialectical Behaviour Therapy (DBT), Emotion-Focused Therapy (EFT), Narrative Therapy (NT), and more. Their techniques are informed by a balance of evidence-based sources, a client-centered approach, critical and Queer theories, and intersectional anti-oppressive practice outlooks.\nAndrew is currently a social work PhD student at York University – specializing in advances in psychotherapy (i.e. alternative approaches) and social justice. He is registered with the Ontario College of Social Workers and Social Service Workers (OCSWSSW) as a Registered Social Worker (RSW) and is available for virtual sessions.	andrew@centrepeacelondon.ca	Flexible.	(226) 784-5477	N6H	\N	$135-$190 per session.	Andrew Raya\nMSW, BSc, RSW and PhD student.	\N	https://www.centrepeacelondon.ca/about-me/andrew/
164	rho	centretown-community-health-centre-trans-health-program	Centretown Community Health Centre Trans Health Program	420 Cooper St\nOttawa, K2P 2N6	I can provide transition related surgery assessments for top or bottom surgeries\nI can provide secondary assessments for transition-related bottom surgeries	The Trans Health Program at Centretown Community Health Centre supports trans and gender diverse individuals ages 17 and up in Ottawa and the surrounding region. We offer hormone initiation, surgical referrals, counseling, and health system navigation. We have a gender-affirming and informed consent approach, which meets the standards outlined in the Sherbourne Health Guidelines for Gender-Affirming Primary Care with Trans and Non-Binary Patients.	transhealth@centretownchc.org	Monday - Friday 9am-5pm	613-233-4443 x 2245	K2P	\N	\N	\N	\N	https://www.centretownchc.org/programs-services/lgbtq-trans-health-program/
165	rho	cf-base	CF Base	26 Somme Avenue\nKingston, K7K 7B4	\N	Providing primary care services for CF members.	\N	\N	\N	K7K	\N	\N	Shannon Charbonneau\nMD	\N	\N
166	rho	chad-clower-speech-language-pathologist-professional-corporation	Chad Clower Speech-Language Pathologist Professional Corporation	Thunder Bay , P7K0S6	\N	Funding:	chadclowerslp@gmail.com	Monday - Friday: daytime hours Weekends: flexible hours	807-630-6884	P7K	\N	Please call 807-630-6884 or email chadclowerslp@gmail.com to discuss	Chad Clower & Cara Schiedel, M.Sc., Reg. SLP\nSpeech-Language Pathology - Transgender And Non-binary Voice Services	\N	https://www.ccslppc.com
167	rho	charlie-parker-mckay-therapy	Charlie Parker-McKay Therapy	Toronto, M4P0B9	\N		charlieparkermckay@gmail.com	Monday-Friday 10 a.m. - 7 p.m.	6473674309	M4P	\N	Sliding scale range - $/Hour Minimum: 25 Maximum: 80	Charlie Parker-McKay\nHBA, RP (Qualifying)	\N	https://www.parkermckaytherapy.com
168	rho	charlotte-pidgeon-psychotherapy	Charlotte Pidgeon Psychotherapy	Toronto, M6J3H3	\N	My client-centred approach allows us to work together on a path towards growth and healing. Whether it’s overcoming current hurdles, or working through past trauma, I believe that we are all capable of making positive change.	charlotte@charlottepidgeon.com	Monday - Thursday, 11 am - 6 pm	647-691-3537	M6J	\N	140	Charlotte Pidgeon\nRP	\N	https://www.charlottepidgeon.com
169	rho	charo-villa-psychotherapist	Charo Villa Psychotherapist	Oakville	\N	Charo will help you highlight skills and strengths to help you navigate trying situations, life transitions and crisis. By releasing old patterns, behaviours and beliefs that may be holding you back from fully engaging in life, Charo will help you to facilitate healing and growth by promoting personal transformation, building self esteem, establishing healthy boundaries and learning conflict resolution skills to get your needs met.	charovillatherapy@gmail.com	\N	9053999970	\N	\N	\N	Charo Villa\nRegistered Psychotherapist	\N	\N
170	rho	chatham-kent-child-and-adolescent-clinic	Chatham Kent Child and Adolescent Clinic	202 King Street West\nChatham-Kent, N7M 1E6	\N	Paediatrician providing general consulting paediatric care. Interest in care of transgendered/gender fluid youth, including assessment of gender dysphoria. Prescribes and manages hormone therapy if appropriate. Referral from physician/nurse practitioner preferred but not required.	\N	\N	519 358 1880	N7M	\N	\N	Ian  Johnston\nM.D., F.R.C.P.C	\N	\N
171	rho	chatham-kent-community-health-centres	Chatham-Kent Community Health Centres	150 Richmond Street\nChatham, N7M1N9	\N	The Chatham-Kent Community Health Centres (CKCHC) is pleased to announce that we now provide services to transgender children and youth in the Chatham-Kent and surrounding area.\n\nServices include:\n\nDr. Ian Johnston is leading these services. Dr Johnston is a general consulting paediatrician with ten years of experience dealing with transgender children and youth in Chatham-Kent.\n\nReferrals from physicians or nurse practitioners are strongly encouraged, but we will accept persons without access to primary care.\n\nAs this is a paediatric clinic, referrals are limited to individuals 18 years of age and younger.\n\nPlease direct referrals to the attention of:\nChatham-Kent Community Health Centres\nPaediatric Transgender Clinic\nFax:  519-397-5497\n\n\nIf you have any questions regarding this service, please contact:\n\nHeather Carnahan, Director of Clinical & Client Services\nHeather.Carnahan@ckchc.ca; 519-397-5455 x110\n\nSherri Saunders, Executive Director\nSherri.Saunders@ckchc.ca; 519-397-5455 x106	Sherri.Saunders@ckchc.ca	Chatham SIte: 150 Richmond Street, Chatham ON N7M 1N9 T. 519.397.5455 Press 1 F. 519.397.5497 Telephone Health Advisory Service (After hour services) 1-866-553-7205 Office Hours: Monday to Friday 9:00 am to 4:30 pm with extended hours on Tuesdays, Wednesdays, and Thursdays until 8:00 pm Wallaceburg Site 808 Dufferin Avenue, Wallaceburg ON N8A 2V4 T. 519.397.5455 Press 2 F. 519.627.8652 Telephone Health Advisory Service (After hour services) 1-866-553-7205 Office Hours: Monday to Friday 9:00 am to 4:30 pm with extended hours on Wednesdays until 8:00 pm Walpole Island Site 785 Tecumseh Road, Unit 16, Walpole Island, ON, N8A 4K9 T. 519.397.5455 Press 3 F. 519.627.4436 Telephone Health Advisory Service (After hour services) 1-866-553-7205 Office Hours: Monday to Friday 9:00 am to 4:30 pm with extended hours on Mondays until 8:00 pm	1519397-5455	N7M	808 Dufferin Avenue, Wallaceburg, Ontario519-397-5455Directions\n785 Tecumseh Road, Walpole Island First Nation, Ontario519-397-5455Directions	\N	Dr. Ian Johnston\nPaediatrician	\N	https://ckchc.ca/
172	rho	chatham-kent-community-health-centres-2	Chatham-Kent Community Health Centres	\N	\N	The Chatham-Kent Community Health Centres are committed to providing high quality health care equally to all people, that is readily accessible when they need it. We believe all people deserve to be treated with respect in a place that is client centred, which shares the responsibility of care with the individual, appropriate interdisciplinary team members and community partners.	info@ckchc.ca	\N	519-397-5455	\N	\N	\N	\N	\N	https://www.ckchc.ca
173	rho	chelsea-derry-naturopath	Chelsea Derry Naturopath	8199 Yonge Street\nMarkham, L4J 1W5	\N	Chelsea is a Naturopathic Doctor who provides complementary and alternative therapies for a wide variety of health concerns. Services include acupuncture, clinical nutrition and supplements, botanical medicine, lifestyle counselling, and homeopathy.\nChelsea has a keen interest in all aspects of GLBTQ health, including trans wellness.	drchelseaderry@gmail.com	\N	(905) 762-1647	L4J	\N	\N	Chelsea Derry\nND	\N	https://www.drchelseaderry.com
174	rho	chettiar-counselling-and-associates	Chettiar Counselling and Associates	#2, 367 Woodlawn Road West\nGuelph, N1H 7K9	\N	Our goal as a counsellor is to help you remain resilient in the face of adversity. In our work together, we can support you to connect with a deeper part of yourself, heal from your emotional wounds, and enhance your coping capacity. Our therapists are experienced in counselling children, youth, and adults. We can help you or your loved ones with anxiety, depression, substance abuse, parenting concerns, and relationship issues. Our fees may be reimbursable based on your extended health benefits. Please visit our website to book an initial appointment and learn more about our fees structure.	clientcare@chettiarcounselling.ca	Mon - Fri: 9am - 9pm Sat - 8am - 2pm	5197668292	N1H	\N	\N	Registered Psychotherapist	\N	https://chettiarcounselling.ca
182	rho	chronic-clinic-homeopathy	Chronic Clinic Homeopathy	12 McMillan Court\nIngersoll, N5C 4H3	\N	Homeopathic treatments for all acute and chronic disease. All genders Mental as well as physical issues will be addressed. self referral; appointment required.\nHomeopath’s will become Regulated Health care professional’s approximately May 2015.	info@chronicclinic.ca	\N	519-425-1571	N5C	\N	\N	lorne moyer\nHomeopath	\N	https://www.chronicclinic.ca
175	rho	childrens-centre-thunder-bay	Children’s Centre Thunder Bay	283 Lisgar Street\nThunder Bay, P7B 2M3	\N	The Children’s Centre offers a continuum of children’s mental health services that range from a single session counselling through brief services to longer term outpatient services and intensive residential treatment. We also provide a variety of specialized services that focus on a\nOur Centre specializes in a variety of children’s mental health issues that children, parents and families experience. Some examples include,	\N	\N	807 343 5000	P7B	\N	\N	\N	\N	https://www.childrenscentre.ca/
176	rho	choice-in-health-clinic	Choice in Health Clinic	1678 Bloor Street West, Suite 301\nToronto, M6P 1A9	\N	Driven by the desire to increase access and abolish shame, CIHC recognizes that abortion is not merely permissible under the law, but essential, important, positive, and powerful. We first opened our doors in 1988 and are now a licensed and fully funded, non-profit clinic with a community-based board of directors. We receive our funding from the Ontario Ministry of Health and Long-Term Care and we are regulated as an Out-of-Hospital Premises by the College of Physicians and Surgeons of Ontario. We are also a member of the National Abortion Federation (NAF) and adhere to their standards for abortion care.\nAt CIHC, we focus on our care on you, your personal experience, and your needs. We continue to push into new frontiers; adapting to the world around us and responding to your changing needs for abortion services. Pregnant people face many invisible barriers, and we are here to identify and remove them. Because what happens next is your choice. You’re the expert.	booking@choiceinhealth.ca	You can reach us by phone: Monday 9:30 a.m.-4:30 p.m. Tuesday-Friday 9:30 a.m.-5:00 p.m. Appointment times are: Tuesday-Friday between 8:15 a.m.-3:15 p.m. We also provide abortions some Saturdays in the month. These times and dates are subject to change, give us a call for more information on available appointment dates.	647-370-3203	M6P	\N	\N	\N	\N	https://choiceinhealth.ca/
177	rho	chris-allard-rmt	Chris Allard RMT	Neeve Wellness Centre\n34 Neeve Street\nGuelph, N1H 4C1	\N	Massage Therapy is designed to promote wellness and can help with: injury/strain prevention and treatment, stress reduction, pain management, increased circulation, improved overall tissue and joint health, and much more.\nI foster a safe and comfortable environment for my clients. To best serve you, I am committed to lifelong learning and dismantling of systemic issues that contribute to stress and its impact on individual wellbeing.\nOutside of my practice I have worked in community support settings, crisis intervention and various activist communities. My 20+ year massage practice is dedicated to providing an inclusive space for 2SLGBTQ+ people with an anti-racist / anti-oppressive framework.\nI provide experienced, quality, therapeutic massage in a professional and calming environment. All treatments are client centered and tailored to address your specific concerns.	info@chrisallardrmt.com	Flexible availability, by appointment only.	5194003254	N1H	\N	Varies by length of treatment.	Chris Allard\nRMT	\N	https://www.chrisallardrmt.com
178	rho	chris-hannah-blueprint-counselling	Chris Hannah – Blueprint Counselling	London, N6B 2M2	\N	Therapy can be a part of a healing journey and I’m humbled to walk beside you in this process. As a counsellor, I do my best to create an atmosphere that promotes personal growth and acceptance through openness and non-judgement. Getting started on this journey can be hard, and reaching out can be intimidating, so congratulations on taking this step!\nI practice counselling from an Indigenous worldview which I have found to provide insightful learning tools for people of many backgrounds and life experiences.  I integrate mainstream approaches into this worldview through certain tools in cognitive behavioural therapy (CBT), narrative therapy, solution-focused therapy, internal family systems, and EMDR.\nI have experience advocating for individuals and supporting them as they navigate complex social systems, addressing and managing mental health concerns, confronting and processing past trauma, and addressing experiences of being racialized. Other areas of focus are grief and loss, life transitions, and spiritual trauma and institutional betrayal.\nI look forward to meeting with you to create a space where you feel seen, heard, and understood as we travel through this part of your journey together.	chris@bpcounselling.com	5:30pm - 8:00 pm Weeknights	2262128272	N6B	\N	\N	Chris Hannah\nMSW, RSW	\N	https://www.bpcounselling.com/
179	rho	christie-esau-counselling-and-psychotherapy	Christie Esau Counselling and Psychotherapy	444 MacLaren Street\nSuite 200\nOttawa, K2P 0M8	\N	I provide individual counselling and psychotherapy for adults 17+ in downtown Ottawa. My approach to therapy is gentle, supportive and eclectic in serving the needs of my clients. Primarily, I use a blend of person-centred therapy and feminist therapy, but I also draw from attachment theory, mindfulness, CBT and a range of other approaches.\nMy practice is trauma-informed and spiritually-informed, and I affirm and respect the diversity of gender and sexuality. I also intentionally consider the social, cultural, political and economic factors that may impact mental health.	cesau.therapy@gmail.com	Thursdays 12:00 pm to 7:00 pm Fridays 9:00 am to 4:00 pm	6136195641	K2P	\N	\N	Christie Esau\nRegistered Psychotherapist; M.A. Counselling and Spirituality	\N	https://www.christieesau.ca
180	rho	christopher-mckinnon-registered-psychotherapist-qualifying	Christopher McKinnon, Registered Psychotherapist (Qualifying)	2 Saint Clair Avenue West\n18th Floor\nToronto, M4V 1L5	\N	As a therapist, I am here to work with you to overcome the challenges that you are facing. Whether you are struggling with depression or anxiety, thoughts about suicide, challenges related to chronic illness or disability, interpersonal and relationship issues, cultural identity, immigration, sexuality, gender identity, grief and loss, or difficult emotions, I will work with you to help build up your resources and your resilience.\nMy approach to psychotherapy is rooted in neurobiology and existential philosophy. As we work together, I will draw from cognitive, behavioural, and narrative techniques to help you make sense of your experiences and your place in the world. My job as your therapist is to help you become more aware of your thoughts, feelings, and behaviour, and to help you reflect on how you might want to change, as well as what change might look and feel like.\nAs a Canadian-born mixed-race queer of Caribbean descent, I am sensitive to the ways that race, class, diaspora, sexuality, and gender shape our experiences of the world. I am drawn to this work in order to facilitate healing and growth after trauma, especially intergenerational trauma. My goal is to help you chart the course of your journey toward greater personal awareness, understanding, and healing.	hello@christophermckinnon.ca	\N	'+1 (647) 615-8983	M4V	\N	\N	RP (Qualifying), MA	\N	https://www.christophermckinnon.ca
181	rho	christy-tashjian-np	Christy Tashjian, NP	554 Beverly Street\nThunder Bay, P7B 5V2	\N	Sexual and Queer Health, including Trans hormone therapy	christymtashjian@gmail.com	Wednesdays 9am-4pm	807-344-4540	P7B	\N	$50-$150	Christy Michelle Tashjian\nNP	\N	https://www.oakmedicalarts.com/
271	rho	dr-felicia-otchet	Dr. Felicia Otchet	London, N6C 5K6	\N	Provides psychological services to adults presenting with a wide variety of health and mental health conditions.	fotchet@drotchet.com	\N	519-630-1863	N6C	\N	\N	Felicia Otchet\nPh.D., C.Psych.	\N	https://www.drotchet.com
183	rho	church-wellesley-counselling-and-psychotherapy	Church Wellesley Counselling and Psychotherapy	491 Church Street, 2nd Floor\nToronto, M4Y 2C6	I can provide transition related surgery assessments for top or bottom surgeries\nI can provide secondary assessments for transition-related bottom surgeries	Individual counselling, psychotherapy, and social work for LGBTQQ2S+ community. Sliding scale options are available.	info@cwcp.ca	Monday to Thursday: 8:30am to 9pm Friday: 8:30am to 5pm Saturday and Sunday: By Appointment	647-358-5815	M4Y	\N	$75 to $135	Adam Terpstra\nRSW, RP, CCC, OCT; M.Ed., B.Ed., B.A.	\N	https://www.cwcp.ca
184	rho	claire-salisbury-psychotherapist	Claire Salisbury, Psychotherapist	186 Albert Street\nLondon, N6A 1M1	\N	I provide individual therapy for adults, adolescents, and children (8yoa+) focusing on gender identity and gender dysphoria, sexuality and sexual functioning, mood, and anxiety difficulties.\nMy practice is particularly focused on helping transgender and gender questioning individuals. This includes parents, other family members, and partners having a difficult time coping with a loved one’s transition.\nTo this end, I offer the following individual services:\nIf you are a parent with a gender creative or trans-identified child, navigating this new terrain can be quite confusing. As such, I provide parent psychoeducation sessions on the social/medical transition in gender creative children, tailored to you and your family’s needs, and based on current research and available supports.\nIf you are another service provider or work in the school system, I provide seminars on working optimally with transgender clients in a therapeutic setting, and on understanding/navigating gender creativity in children and adolescents.	salisbury.claire@gmail.com	\N	519-520-2906	N6A	\N	\N	Claire Salisbury\nMSc, RP, CCC	\N	\N
185	rho	clare-md-therapy	Clare MD Therapy	Burlington , L7P0A4	\N	This is a virtual clinic that provides adult individual psychotherapy (GP psychotherapy) including support for gender affirming care and is covered by OHIP. Due to current OHIP requirements, initial visit for therapy will be arranged in person in the Burlington region directly with the patient.	claremdtherapy@gmail.com	Monday - Friday: 9 a.m. - 3 p.m.	905-315-3074	L7P	\N	\N	Clare Francisco Wallner\nMD	\N	https://claremdtherapy.org
186	rho	clearview-chiropractic	Clearview Chiropractic	2012 Victoria Avenue\nBurlington, L7R 1R4	\N	Chiropractic care	drpeterangerilli@gmail.com	\N	905-634-9494	L7R	\N	\N	Dr. Peter Angerilli\nB.Sc, D.C.	\N	https://clearviewchiropractic.ca
187	rho	clinical-counseling-psychotherapy	Clinical Counseling Psychotherapy	10 Zina Street\nOrangeville, L9W 1E1	\N	Psychotherapy and counseling support for LGBTQ and cisgendered families	drkersty@gmail.com	\N	519-941-5710	L9W	\N	\N	Kerstine Franklin\nM.A. and Doctorate in Human Sexuality	\N	\N
188	rho	coaching-for-vocal-health-in-transition-viva-youth-singers-of-toronto	Coaching for Vocal Health in transition – VIVA! Youth Singers of Toronto	427 Bloor Street West\nToronto, M5S 1X6	\N	We seek to encourage healthy, positive exploration of vocal health. Our excellent vocal coach and conductors are ready to support singers who are transgender. Our six diverse choirs include 3 children’s choirs and 3 adult choirs, organized by age and musical skill. We are unique in providing support to singers with disabilities in our Everyone Can Sing Choir. Our children’s choirs accept children ages 4 to 17. Experienced adult singers with excellent skills audition for our Chamber Choir. Adult beginners including retirees are welcomed without audition into our Community Choir.	charlotte@vivayouthsingers.com	\N	416-788-8482	M5S	\N	\N	Carol  Woodward Ratzlaff\nmusic and education professionals	\N	https://vivayouthsingers.com
189	rho	collaborate-counselling	Collaborate Counselling	Kitchener, N2M 5B8	\N		collaboratecounselling@gmail.com	Mondays: 2pm to 8pm Thursdays: 9am to 8pm Fridays: 9am to 6:30pm Saturdays: 12:30pm to 6pm	226 407 7173	N2M	\N	130\nSliding scale range - $/Hour Minimum: 60 Maximum: 130	Gavynn Daeuber McKay\nMSW, Registered Social Worker	\N	https://gavynnmckay.wixsite.com/collabcounselling
190	rho	collingwood-health-centre-georgian-bay-fht	Collingwood Health Centre – Georgian Bay FHT	186 Erie Street\nCollingwood, L9Y 1P6	\N	The Georgian Bay Family Health Team (GBFHT) is a regional, patient-centred, primary health care team set up to provide unparalleled collaborative health care to improve the overall health of the Georgian Bay population.\nThe GBFHT is made up of Doctors, Nurse Practitioners, Registered Nurses, a Registered Dietitian, Mental Health Counsellors, and administrative staff whose most important goal is to provide patient-centred care.  In essence, this means:\n.	\N	\N	705-444-7687	L9Y	\N	\N	\N	\N	https://www.gbfht.ca/
191	rho	colourful-nutrition	Colourful Nutrition	302 Cumberland Avenue\nHamilton, L8M 2A1	\N	Mays Ibrahim is a dynamic Registered Dietitian and owner of Colourful Nutrition she is based in Hamilton, Ontario. She specializes in weight management and chronic disease prevention. In her practice she translates complex evidenced based scientific information into practical everyday lifestyle changes that are specifically catered to her clients health needs.\nAlthough Mays is located in Hamilton, ON she provides nutritional counselling across Ontario. Appointments can be booked one-on-one, in small groups or online. Get in touch with Mays to learn more about which nutrition package is best for you.\n***Registered Dietitian Services are covered by many Extended Health Benefit Plans. They are also tax deductible ***	info@colourfulnutrition.ca	\N	5198707036	L8M	\N	\N	Mays Ibrahim\nRegistered Dietitian	\N	https://colourfulnutrition.ca
192	rho	comfort-keepers-london	Comfort Keepers London	341 Talbot Street\nLondon, N6A 2R5	\N	At Comfort Keepers, we help seniors, new parents and people with disabilities live happier, healthier lives in the comfort of their own homes by providing quality, compassionate care and safety technology solutions to preserve independence and contribute to a better life. Family members can have peace of mind knowing that Comfort Keepers is there when they are not able to be.\nOur Interactive Care solutions range from Companion care to Homemaking to Personal Care. Included are Meal Preparation, Housekeeping, Errands, Appointments, Shopping, Help with Mail, Personal Grooming, TLC calls, Hospice Care, Respite Care, Palliative Care and Assistance with Activities of Daily Living.\nOur mission is to provide our clients with the highest level of quality of life that is achievable. We shall treat each of our clients with the respect and dignity they deserve, as though we were caring for a member of our own family.\nCertified, Bonded, Insured with References, CPR, First Aid	londonwest@comfortkeepers.ca	\N	519-601-4075	N6A	\N	\N	\N	\N	https://www.comfortkeepers.ca/office-3027/
193	rho	comfort-keepers-senior-care-2	Comfort Keepers – Senior Care	\N	\N	My Comfort Keepers are trained to help seniors with their individual needs. We help people with transportation, meal preparation, housekeeping, laundry and much more.	sandradesjardins@comfortkeepers.ca	\N	705-969-1777	\N	\N	\N	\N	\N	https://www.comfortkeepers.ca
194	rho	community-care-midwives	Community Care Midwives	135 Simcoe Street North\nOshawa, L1G 4S6	\N	Providing prenatal, delivery and post part care	communitycaremidwives@bellnet.ca	\N	905-723-6088	L1G	\N	\N	Judi Brandson\nRegistered Midwife	\N	https://communitycaremidwives@bellnet.ca
272	rho	dr-francine-brill	Dr. Francine Brill	30 Prospect Street\nNewmarket, L3Y 3S9	\N	Consultation/psychiatric care for youth experiencing gender dysphoria	\N	\N	289-803-2533	L3Y	\N	\N	Francine Brill\nM.D. FRCP(C)	\N	\N
195	rho	community-care-team	Community Care Team	379 Church Street\nSuite 214\nMarkham, L6B 0T1	\N	Community Care Team is an outreach team of health care professionals from Health for All Family Health Team. We provide free services for individuals within Eastern York Region. Our Team includes: Nurse Practitioner, Social Worker, Dietician, Case Manager, Pharmacist and Health Promotor.	jbitaayi@healthforallfht.ca	Monday to Friday 8:30 am to 4:30 pm	905-472-2200 ext. 290	L6B	\N	\N	\N	\N	https://healthforallfht.ca/our-programs/cct/
196	rho	community-justice-initiative	Community Justice Initiative	49 Queen Street North\nKitchener, N2H 2G9	\N	PROGRAMS:\nMediation Services\nMediation and conflict resolution services for individuals, families, friends, neighbours, organized sports, schools, groups, organizations, and the justice system.\nRevive\nRevive provides supportive services to women and men who are healing from sexual harm.  This includes support for survivors of sexual trauma, support for people who have offended sexually to make safe healing choices, and intimate partners of both.  Facilitated Dialogues provide support for families and groups in which sexual abuse has occurred.\nStride\nStride of CJI assists women serving a federal prison sentence (FSW) to make the difficult, often traumatic transition from prison into the community by engaging and involving community volunteers.  Employing principles of restorative justice, the program focuses on building on the strengths of the women and creating safer and supportive communities to receive them in their transition from prison.  This process facilitates changes in the women’s options and the subsequent choices they make.\nFamily Centred Programs\nA culturally-sensitive process that gives the extended family and friends of children at-risk an opportunity to collaboratively develop a plan of care focused on the best interest and safety of the children.\nBackHome\nBackHome, modeled after our Stride program, is designed to assist youth with the reintegration process after a period of custody.  Using recreational programming, BackHome connects the youth with volunteer mentors who support their transition back into the community.	info@cjiwr.com	\N	519-744-6549	N2H	\N	\N	\N	\N	https://www.cjiwr.com/
197	rho	community-midwives-of-ottawa	Community Midwives of Ottawa	Ottawa	\N	Outreach midwifery care.	admin@ottawamidwives.ca	\N	613-883-2566	\N	\N	\N	Amy McGee\nRegistered Midwife MSW PhD	\N	https://www.ottawamidwives.ca
198	rho	community-midwives-of-ottawa-2	Community Midwives of Ottawa	2260 Walkley Rd\nOttawa , K1G 6A8	\N	Primary health care providers for people during pregnancy, birth, and postpartum.	admin@ottawamidwives.ca	Clinic hours Monday to Friday Midwives available and on-call 24/7	613-883-2566	K1G	\N	\N	\N	\N	http://ottawamidwives.ca
199	rho	community-midwives-of-thunder-bay-2	Community Midwives of Thunder Bay	\N	\N	The Community Midwives are committed to providing high quality, culturally sensitive maternity care to women and their families in Thunder Bay and the surrounding area. As a community based practice, we work closely with local health promotion programs to ensure you and your family receive the most relevant and current maternity care.	admin@communitymidwives.net	\N	8076222229	\N	\N	\N	\N	\N	https://www.communitymidwives.net
200	rho	community-midwives-of-toronto	Community Midwives of Toronto	344 Bloor Street West\nSuite 201\nToronto, M5S 3A7	\N	Throughout pregnancy, labour and birth and for six weeks after birth, clients and their newborns are cared for by a small group of midwives. The midwives are on call and provide all primary care services for routine obstetric and newborn care. Midwives are part of the Ontario health-care system and their services are completely funded by the Ministry of Health for residents of Ontario. You do not need a referral from a doctor to have a midwife; contact our clinic directly to request midwifery care.  Our clinic holds privileges at St Michaels Hospital and the Toronto Birth Centre.	communitymidwivestoronto@rogers.com	We offer antenatal care 24/7 but our administrative staff hours are Monday through Thursday 9:30-4:30	416-944-9366	M5S	\N	\N	\N	\N	https://www.communitymidwivesoftoronto.ca
201	rho	community-midwives-of-toronto-2	Community Midwives of Toronto	\N	\N	We are a midwifery practice located in downtown Toronto, Canada. We are a group of ten midwives: Bridget Lynch, Jennifer Goldberg, Mary Fish, Fariba Shodjaie, Dione Amsterdam, Kristen Dennis, Elena Ikonomou, Barbara Santen, Alusha Morris and Lauren McEachern.\nOntario midwives provide care under a model and philosophy which includes the belief that all people have the right to make informed choices.\nWe attend births at home, at the Toronto Birth Centre and at St. Michael’s Hospital in downtown Toronto. Pregnant individuals in Ontario under the care of a midwife choose where to give birth. Your midwife will assess your health needs and provide information to ensure you can make an informed decision about where to have your baby.\nIn Ontario, a midwife is a registered health care professional who provides primary care to low-risk individuals throughout pregnancy, labour and birth. Midwives also provide care to both the parent and baby during the six weeks following birth. They are available to clients 24 hours a day, seven days a week by pager.\nIn Ontario, if you see a midwife you will not see a physician unless there are concerns or complications. Most births are normal and there are no complications. If there are complications, midwives can consult or transfer care to a physician. Midwives provide safe and expert care to healthy pregnant individuals and newborns.\nThe midwives at our practice speak English, French, Spanish, Farsi, Greek, Japanese and Dutch.\nCommunity Midwives of Toronto provides care to LGBTQ families including trans people.	communitymidwivestoronto@rogers.com	\N	416-944-9366	\N	\N	\N	\N	\N	https://www.communitymidwivesoftoronto.ca
202	rho	connected-counselling-services	Connected Counselling Services	629 Elizabeth Street\nPembroke, K8A 7X7	\N	We provide virtual psychotherapy services that are safe and inclusive. Experienced in supporting 2SLGBTQIA+ and gender expansive people to collaboratively and compassionately work on/support/plan for “coming out”, transitioning, top/bottom surgery; work on body dysphoria, mental health concerns, relationship problems , trauma and many other issues and concerns. Welcome to one and all! Sliding scale options available.	adrienne@connectedcounsellingservices.com	9 a.m. to 5 p.m., evenings and weekends	6136022960	K8A	\N	Sliding scale range - $/Hour Minimum: 30 Maximum: 200	therapy/ counselling/ sex therapy\nMSW, RSW or registered Psychotherapists	\N	https://www.connectedcounsellingservices.com
203	rho	connexion-family-health-team	Connexion Family Health Team	8-5303 Canotek Rd\nOttawa,  K1J 9M1	\N	Our primary goal is to provide excellent patient care. As a leading academic Family Health Team that seeks to improve the health of its community, we continually focus on how we can be at our best at being not just patient-centered, but including patients in the decisions about their health at all times.\nWe offer a wide range of services to the patients of our physicians however, we do offer a wide variety of community services which include:\n-Birth Control Clinic (IUD/Implant insertion)\n-Diabetes Management Program\n-Introduction to Solid Foods Program\n-Healthy Aging Program\n-Mindfulness 101 Workshop\n-Sleep Management Workshop\n-CBT Workshop\n-Craving Change Workshop\n\nPlease visit our website for further information and learn how to enroll in our programs.	programs@connexionfht.ca	8am-4pm	613-656-3841	K1J	\N	\N	\N	\N	https://connexionfht.com/
204	rho	considracare	ConsidraCare	L14, 60 Queen Street East, Brampton, ON L6V 1A9\nBrampton, L6V 1A9	\N	ConsidraCare is a placement service for senior caregivers and home care assistance. We offer seniors across Ontario live-in senior home care and live-out care services that are both cheap and of the highest calibre. Our mission is to support Canadian elders as they age safely, comfortably, and with dignity in their own homes. Additionally, we are dedicated to delivering caregivers respectable and well-paying employment options as well as equipping them with the modern technology platform, support, and training needed to provide the highest standard of Senior Home care. Join us right away to change someone’s life! Visit Considracare.com for additional information or call us at 1-855-410-7971.	wecare@considracare.com	Hours: Tuesday 8a.m.–7p.m. Wednesday 8a.m.–7p.m. Thursday 8a.m.–7p.m. Friday 8a.m.–7p.m. Saturday 9a.m.–5p.m. Sunday 9a.m.–5p.m. Monday 8a.m.–7p.m.	1855410797	L6V	\N	\N	Dr. Saba Tauseef\nMBBS, MPH	\N	https://considracare.com/
205	rho	core-connections-physiotherapy	Core Connections Physiotherapy	363 Richmond Rd.\nOttawa, K2A 0E7	\N	Registered orthopedic and pelvic health physiotherapist\nSpecialized training in physiotherapy for gender diverse populations (“Pelvic Health Care for Trans and Gender Diverse People” instructed by Celeste Corkery, member of the Transition Related Surgeries program at Women’s College Hospital, via Pelvic Health Solutions)\n-Training in psychosocial considerations for being sensitive, inclusive and supportive of gender diverse populations\n-Preparation and recovery for gender affirming surgeries (e.g.vaginopasties, phalloplasties, upper surgeries)\n-Treatment of conditions related to gender affirming practices (e.g. pain, stiffness, bowel/bladder issues related to tucking, binding)\n	galia@core-connections.ca	Monday to Friday, Hours vary from 8am to 7pm	613-291-2956	K2A	\N	Assessment: $155-165, Treatment: $95-165 (time based), financial support fund when available	Galia Carranco Herrera\nMaster's in Physiotherapy	\N	https://www.core-connections.ca
206	rho	corinne-mccordick-rmt-doulalabour-support	Corinne McCordick RMT/Doula?Labour Support	\N	\N	I provide emotional, physical, and informational support during pregnancy and birth. Doulas understand the process of labor and birth, and provide continuous support – like massage, aromatherapy, guided breathing and relaxation, rebozo, and positions – to help birthing parents navigate their process into parenthood. As your RMT/Doula I will come to your house in early labor, and assist you with comfort measures, remaining calm and relaxed, and laboring more easily. As an RMT I have the added benefit of many years of experience working with pregnant bodies to ease pain and tension, creating an inner sense of calm and control.If you have a partner your doula will help them to support you better.\nA doula can help birthing parents access their own inner resources in order to:\nHave a shorter, easier labor\nUse less interventions\nUse less pain medications (if that is your desire)\nFeel more informed about their birth options\nHave more positive feelings about their labor and birth	CorinneRMT@gmail.com	\N	647 449 0994	\N	\N	\N	Corinne McCordick\nRegistered Massage Therapist	\N	\N
207	rho	cornerstone-physiotherapy	Cornerstone Physiotherapy	\N	\N	Cornerstone Physiotherapy offers expert physiotherapy services in Toronto.\nWe have been a strong supporter of the LGBT+ community since we first started getting people better, faster in 2008.\nOur physiotherapists are experienced and compassionate. Our receptionists knowledgeable and friendly. Our facilities clean and modern.\nWe appreciate all of our patients’ differences, which allows us to tailor our care to meet the specific needs of each person we treat.\nOur clinics offer:\nWe have 2 clinics conveniently located at Yonge and College and at University and Wellington, both steps to subway stations.\nWe look forward to helping you get better, faster!	\N	\N	\N	\N	\N	\N	\N	\N	\N
208	rho	cornerstone-physiotherapy-2	Cornerstone Physiotherapy	4789 Yonge Street\nToronto, M2N 0G3	\N	We are a physiotherapy clinic who provide physiotherapy services in orthopedics, pelvic health and vestibular therapy. We also have registered massage therapists at our clinic.	cornerstonephysio3@gmail.com	\N	647-494-4342	M2N	\N	\N	\N	\N	https://northyorkphysiotherapy.ca
209	rho	cornerstone-physiotherapy-king-university	Cornerstone Physiotherapy – King & University	55 University Avenue\nToronto, M5J 2H7	\N	Cornerstone Physiotherapy is an integral part of downtown Toronto’s medical community, providing experienced rehabilitation since 2008. We are a full service clinic providing the following services:\nPhysiotherapy, Pelvic Health, Dizziness Clinic, Massage Therapy	info@cornerstonephysio.com	\N	(416) 363-1975	M5J	\N	\N	Rosalina Mahendran\nRegistered Physiotherapist	\N	https://www.cornerstonephysio.com
210	rho	cornwall-community-hospital-assault-and-sexual-abuse-program	Cornwall Community Hospital Assault and Sexual Abuse Program	\N	\N	The ASAP provides emergency healthcare, forensic evidence collection and counselling to all victims of sexual assault and/or intimate partner violence. Emergency service is 24 hours, counselling is by appointment.	asap@cornwallhospital.ca	\N	613-932-3300 ext. 4202	\N	\N	\N	\N	\N	https://www.cornwallhospital.ca/asap
211	rho	cottage-country-family-health-team	Cottage Country Family Health Team	Unit 1 - 5 Pineridge Gate\nGravenhurst, P1P 1Z3	\N	Trans medical care and surgical planning/referral; LGBT2SQ-positive	hjamieson@ccfht.ca	\N	705-687-2794	P1P	\N	\N	Heather Jamieson\nNurse Practitioner	\N	https://ccfht.ca
212	rho	couchiching-family-health-team	Couchiching Family Health Team	119 Memorial Avenue\nOrillia, L3V 5X1	\N	We are a team of family physicians and other health professionals located in Orillia, Ontario who are dedicated to improving the health care of our community.\nWe are focused on primary care; that is, the care you receive at your first point of contact with a doctor or a health care Team member. Primary care includes disease management and prevention, disease cure, rehabilitation, palliative care and health promotion.\nWe function as a team. We offer an approach to primary health care that brings together different health care providers to co-ordinate the most accessible, convenient and high quality care on your behalf.\nWe are patient-centered. All of our work as a team is focused on providing a circle of care that is guided by the unique needs of each person we serve. All our patients enroll with a physician on the Team. Please note that enrollment is limited by the availability of Team members.\n	info@cfht.ca	\N	705-329-3649	L3V	\N	\N	\N	\N	https://www.cfht.ca/
213	rho	counselling-at-the-519	Counselling at The 519	\N	\N	The Counselling Program at The 519 offers free, solution-focused counselling to members of the LGBT community and beyond. Each service user is entitled to 6 confidential sessions with an experienced volunteer counsellor and will receive referrals to meet ongoing needs. Those interested in accessing counselling services at The 519 are asked to leave a message on our confidential voice mail at 416.392.6874 x4000 and you will be contacted by the Program Coordinator.	\N	\N	\N	\N	\N	\N	\N	\N	\N
226	rho	cynthia-galloway-psychotherapist	Cynthia Galloway Psychotherapist	\N	\N	I am a Registered Marriage & Family Therapist and a Registered Sex Therapist, providing psychotherapy to cross-dressing, transgender and gender-variant individuals, their partners and their families, as well as counselling support for eating disorders, relationship issues, sexuality concerns, and healing from trauma.	\N	\N	\N	\N	\N	\N	\N	\N	\N
214	rho	counselling-centre-of-east-algoma	Counselling Centre of East Algoma	9 Oakland Boulevard\nElliot Lake, P5A 2T1	\N	CCEA offers a safe, encouraging and friendly environment. Our professionally trained counsellors are available to emphasize your personal growth and self determined change. We are committed to providing services to individuals, couples, families and groups who are experiencing difficulties with personal issues and/or their intimate or essential relationships. Our services are independent, confidential, and voluntary – meaning you choose your path to wellness in consultation with your counsellor. In addition, our staff are available to offer employee or community presentations in a variety of subject areas. We strive to be responsive to community need and will tailor educational presentations on an as needed basis.	\N	\N	7058482585	P5A	\N	\N	Shelley Watt Proulx	\N	https://www.ccea.life
215	rho	counselling-guelph	Counselling Guelph	\N	\N	LGBTQ friendly counselling and therapy for anxiety, depression, anger management, stress, trauma, and behavioral addictions – sex, shopping, internet and video gaming.\nLGBTQ supportive relationship counselling and parenting support. Relationship counselling for anyone questioning traditional relationships.	\N	\N	\N	\N	\N	\N	\N	\N	\N
216	rho	counselling-muskoka	Counselling Muskoka	69 West Road\nHuntsville, P1H 1L4	\N	Individual, couple and family counselling for adults/youth/children. Mindfulness Based Stress Reduction (MBSR) and Mindfulness Based Cognitive Therapy (MBCT) Groups and Private Sessions. Private and group yoga sessions	CMcounsellingmuskoka@gmail.com	\N	7053490770	P1H	\N	\N	Catherine Moffat\nMSW, RSW	\N	https://www.CounselllingMuskoka.com
217	rho	counselling-services	Counselling Services	313 Danforth Avenue\nToronto, M4K 1N7	\N	I offer counselling services for 2SLGBTQ+ Communities. My practiced is grounded in anti-oppressive and intersectional frameworks and is trauma informed. Feel free to get in touch to see how I may be able to support you with your individual needs.	elawar.km@gmail.com	\N	416-930-8480	M4K	\N	\N	Kareem Elawar\nBA, TLI Dipl	\N	https://kareemelawar.weebly.com/
218	rho	counterpoint-needle-exchange	Counterpoint Needle Exchange	186 King Street\nLondon, N6A 3N7	\N	Feel free to also access our Counterpoint Needle Exchange program for all your FREE harm reduction needs.\nYou may also wish to support/join our LGBT youth via “Open Closet”. Every Friday night from 7-9 pm…for more information, support, resources or referrals call Daniel Pugh, Director of Education via ext. 230	info@hivaidsconnection.ca	\N	1-866-920-1601	N6A	\N	\N	\N	\N	https://www.hivaidsconnection.ca
219	rho	crazy-like-me	Crazy Like Me	North York, M2N0H6	\N	Peer Support Counselling for folks experiencing mental health and substance use related challenges. Additional focus includes: family estrangement, grief, bereavement, and ADHD.	crazylikejenn@gmail.com	Monday to Friday: 10am - 6pm Some evening and weekend availability by request	4169881148	M2N	\N	Sliding scale range - $/Hour Minimum: 40 Maximum: 80	Jennifer Soutar	\N	https://www.crazylike.me/
220	rho	creative-strength-psychotherapy	Creative Strength Psychotherapy	Unit 1, 944 Broadview ave\nToronto, M4K2R4	\N		sieran.yung@creativestrengthpsychotherapy.com	2 pm to 9 pm on weekdays (time negotiable)	6479379751	M4K	\N	Sliding scale range - $/Hour Minimum: 80 Maximum: 125	Sieran Yung\nRP (qualifying), MEd	\N	https://www.psychologytoday.com/ca/therapists/sieran-yung-toronto-on/998422
221	rho	creative-transitions-counselling-services	Creative Transitions Counselling Services	156 Sheppard Avenue West, Unit 3\nToronto, M2N 1M8	\N	Shirley Katz, Ph.D. (Doctorate in Counselling), Registered Psychotherapist, Certified Clinical Counsellor & Clinical Supervisor with brings over 23 years of experience providing therapy, clinical supervision and teaching experience to her collaborative work with clients, supervisees and contractors. Please see our team for more info on therapists.\n​Our services are evidence-based, using CBT, Emotion Focused Therapy (EFT) and Mindfulness for example. Some of us are trained in ACT, IFS and other models.\nWe welcome and respect diversity and are LGBTQ2S+ friendly, welcome teens and adults.  Services are supervised by a Registered Psychologist when required.  Our services are evidence-based, using CBT, Emotion-Focused Therapy (EFT) and Mindfulness for example. Some of us are trained in ACT, IFS and other models.\n​\nWe have many associates and interns, and offer services in multiple languages and at discounted and low-cost rates.	creativitycounselling@gmail.com	Monday - Friday 10:00am - 8:00pm	6472443050	M2N	\N	180\nSliding scale range - $/Hour Minimum: 50 Maximum: 180	Shirley Katz\nPhD, RP, CCC	\N	http://www.creativitycounselling.com/
222	rho	creative-wellness	Creative Wellness	23 Beckwith Street North\nSmiths Falls, K7A 2B2	\N	Creative Wellness is a community-based counselling and support service that addresses the need for proactive affordable and accessible mental health/ emotional wellness care for people in Lanark County and surrounding areas.\nAs long time residents of the Lanark, Leeds and Grenville area we understand the issues impacting\npeople living in rural areas and the pressing need for support and advocacy\nfor individuals, couples and families.\nWe organize support groups, workshops, drop in and recovery meetings and one-on-one talk therapy	info@creative-wellness.ca	\N	\N	K7A	\N	\N	Addiction and Community Service Worker, Grief and Loss Certification,- SSW	\N	https://www.creative-wellness.ca
223	rho	cross-cultural-learner-centre-newcomer-support	Cross Cultural Learner Centre – Newcomer Support	\N	\N	The London Cross Cultural Learner Centre exist to foster a more just community, both globally and locally. The Centre provides assistance to newcomers and minority groups in the London area to enable community involvement, cultural expression and enrichment and development of political, social and environment awareness.	rainbow@lcclc.org	\N	519-432-1133	\N	\N	\N	\N	\N	https://www.lcclc.org
224	rho	cultivate-counselling	Cultivate Counselling	Kitchener, N2G1P1	I can provide secondary assessments for transition-related bottom surgeries	Mandi, at Cultivate Counselling, is a Queer/ENBY therapist who provides counselling services to individuals 18 years and older on a range of issues, with specialization in gender and sexuality. Mandi has helped countless clients in their journey of self discovery, acceptance and celebration, and believes that affective and affirming LGBTQ+ mental health services honour the uniqueness of each client and their personalized goals. There is no one health gender outcome, and our experience of gender grows and develops across our lifetime as we continue to grow with the experiences of our life and circumstance. Mandi also has specialized training and experience in providing assessment for gender affirming surgery. At Cultivate Counselling you will find a safe, inclusive, and open-minded space to explore identity, relationships, trauma healing, healthy boundaries, and self-compassion. Individuals and couples are welcomed, and free consults are provided on request to determine if this may be the right fit for you!	cultivatecounsellingkw@gmail.com	Monday 11-6 Tuesday-Thursday 1-8 Friday 11-6	548-483-5512	N2G	\N	130-150	Mandi Cowan\nMSW RSW	\N	https://www.cultivatecounselling.ca/
225	rho	culturelink-speakout-newcomer-support	CultureLink SpeakOUT- Newcomer Support	\N	\N	CultureLink’s SpeakOUT program provides peer support, events and workshops for LGBTQ newcomers. Please see our website or contact us for upcoming events or to make an appointment for settlement services.	\N	\N	\N	\N	\N	\N	\N	\N	\N
227	rho	cynthia-galloway-psychotherapist-2	Cynthia Galloway Psychotherapist	\N	\N	I am a Registered Marriage & Family Therapist and a Registered Sex Therapist, providing psychotherapy to cross-dressing, transgender and gender-variant individuals, their partners and their families, as well as counselling support for eating disorders, relationship issues, sexuality concerns, and healing from trauma.	hopecounselling@me.com	\N	519-777-1906	\N	\N	\N	Cynthia Galloway\nMEd Counselling Psychology, RD, RMFT	\N	https://www.hopecounsellingcentre.ca
228	rho	daisie-therapy	Daisie Therapy	24 O'Hara Avenue\nToronto, M6K 2P8	\N	Counseling and therapy for individuals, children and families. Parenting groups.	Daisie@daisietherapy.com	\N	647-799-3477	M6K	\N	\N	Daisie Auty\nRegistered Social Worker	\N	https://Www.daisietherapy.com
229	rho	dalby-family-practice	Dalby Family Practice	21 Hamilton Street\nElora, N0B 1S0	I can provide transition related surgery assessments for top or bottom surgeries\nI can provide secondary assessments for transition-related bottom surgeries	Assistance with HRT and surgical assessment.	dalbyfamilypractice@wightman.ca	Monday to Friday: 9 am to 4:30 pm	2263690264	N0B	\N	\N	Annie Lu\nFamily Physician	\N	https://uppergrandfht.org
230	rho	dallaire-medicine-obgyn	Dallaire Medicine, OBGYN	707 Charlotte Street\nPeterborough, K9J 2X5	\N	Obstetrician/Gynecologist	\N	\N	7057499695	K9J	\N	\N	Christine Dallaire\nB. Kin MD FRCSC	\N	\N
231	rho	dan-de-figueiredo-psychotherapy-services	Dan de Figueiredo Psychotherapy Services	176 Saint George Street\nToronto, M5R 2M7	\N	Specialized Training:\nIntegrated therapy and counselling using elements of Cognitive Behavioural Therapy and psychodynamic approaches as appropriate all within a harm reduction model. Specialized training in Humanist-Existential approaches that include Dialectic Behaviour Therapy, CBT, Mindfulness, Solution-focused Brief Therapy, Motivational Interviewing, Emotionally-Focused Therapy, and Emotion-Focussed Family Therapy for couples, groups, and individuals. The focus of my practice has three specialities:\n1-LGBTTIQ issues, challenges and mental health including attachment-related issues and building healthy relationships;\n2-Addictions – substance use and behavioural addictions (gambling, sexual, spending, internet) and the mental health and life challenges that underlie them, including Mood and Anxiety;\n3-Borderline Personality Disorder and Emotion Regulation/Dysregulation, including anger management and trauma.\nPersonal Statement:\nAs a Gay man with more than 5 years of counselling experience working specifically within the LGBTTIQ community, and with the general adult populations in addictions, mental health and borderline personality disorder, I provide psychotherapy services to adult individuals, couples, and groups with mental health, addiction and life challenges. I provide a supportive environment for clients to safely explore challenges, conflicts and issues. From my Annex office, I provide counselling and therapy to help clients achieve better emotional and physical health, and satisfying personal relationships. I am a clinical social work with training and experience in general psychotherapy, relationships, personal growth and spirituality as well as specific expertise in coming-out, sexual identity, trauma, anger management, personality disorders, addictions and the underlying symptoms that contribute to addictions. Whether confronting a specific problem or helping you with longer-term understanding of yourself, I look forward to being a part of your journey of healing and growth.	dandf.psych@gmail.com	\N	416-707-0197	M5R	\N	\N	Dan De Figueiredo\nBA, BAA, MSW, RSW	\N	https://www.dandf.pschotherapy.com
232	rho	dan-sommer-massage-therapy	Dan Sommer Massage Therapy	901 Yonge Street\nToronto, M4W 2H2	\N	HEALTHQUEST is a dynamic clinic where highly trained professionals practice a holistic approach to health and well-being. Our goal is to promote the reality of living a productive and healthy lifestyle. Therapies include a non-invasive, hands-on approach to healing the body. Natural therapies have moved into a more prominent position in health care. Many people have an increase desire and need for therapies that are supportive of the body’s natural process and that encourage patient participation in their own healthcare.\nDan Sommer graduated from the Massage Therapy program at Centennial College in 2010. Both in his schooling and during his practice Dan has gained experience in working with people with a wide variety of situations and conditions. In addition to general Swedish Massage, Dan has had training in Deep Tissue massage. Currently, in addition to working in a couple of clinics downtown, he is working as an educator at Centennial College in the Massage Therapy program. Dan identifies within the LGBTQ community and has experience working with the community.	dsommerrmt@sommerhealth.ca	\N	416.923.6661	M4W	\N	\N	Dan Sommer\nRMT	\N	https://www.healthquesttoronto.com/
233	rho	daniel-farb-psychotherapy-services	Daniel Farb Psychotherapy Services	Burlington, L7S 1R3	\N	Provides integrative psychotherapy services with a trauma-focused approach.	daniel@danielfarb.com	\N	647-201-9161	L7S	\N	\N	Daniel Farb\nRegistered Psychotherapist	\N	https://www.danielfarb.com
234	rho	daniel-nightingale-physiotherapist-at-bloor-park-physiotherapy	Daniel Nightingale, physiotherapist at Bloor Park Physiotherapy	726 Bloor Street West\nToronto, M6G 1L4	\N	Our service focus is on you: that means we design our treatment plans around your unique needs and goals, adhere to best practices and consistently deliver the highest standards of quality care to attain best possible outcomes. We want to help you regain the strength, function and movement so you can enjoy an overall better quality of life.	bloorparkpt@preferredrehab.ca	\N	6473684400	M6G	\N	\N	Daniel Nightingale\nPhysiotherapist	\N	https://bloorparkphysiotherapy.ca/
235	rho	danielle-kenyon-at-south-riverdale-community-health-centre	Danielle Kenyon at South Riverdale Community Health Centre	955 Queen Street East\nToronto, M4M 3P3	\N	I am a Primary Care Nurse Practitioner with experience in medical options and referral for surgical for gender dysphoria. I have a special interest in newcomers and pregnant clients.	\N	\N	416-461-2493	M4M	\N	\N	Danielle Kenyon\nPHC-NP	\N	\N
236	rho	darren-parker-therapy	Darren Parker Therapy	Toronto, M4Y1N3	\N	Providing secure and confidential counselling for individuals across Ontario by phone or video. Darren Parker is a gay cis male counsellor passionate about supporting the 2SLGBTQ+ community and committed to providing space that is trans and non-binary affirming, anti-racist, and anti-ableist.	darren@darrenparkertherapy.com	M: 9:00am-5:00pm T: 9:00am-5:00pm W: 9:00am-5:00pm T: 1:00pm-7:00pm F 9:00am-noon	(647)503-0540	M4Y	\N	$130 for 50 minute counselling session by video or phone	Darren Parker\nMSW RSW	\N	https://www.darrenparkertherapy.com
237	rho	daru-therapy-centre	Daru Therapy Centre	345 Jerseyville Rd West\nAncaster, L9G 5C3	\N	I provide individual counselling & psychotherapy in areas of mental health such as anxiety, grief & self-esteem.\nSessions are held in a culturally safe environment and can be either online or in person with therapy in Nature.	connect@darutherapycentre.ca	Monday - Thursday 10am - 6pm	2898552732	L9G	\N	\N	Lorraine Hanley\nMACP, RP(qualifying)	\N	https://www.darutherapycentre.ca
238	rho	dave-patterson	Dave Patterson	Toronto	\N	I am a gay male interpreter, providing interpretation services between American Sign Language and English to Deaf, deafened, hard-of-hearing and hearing (non-Deaf) individuals and groups in the city of Toronto.	davipatt@yahoo.ca	\N	647 408-5221	\N	\N	\N	Dave Patterson\nBA (Hons), AEIP, AVLIC member	\N	\N
246	rho	debbie-garshon-individual-couples-and-sex-therapy	Debbie Garshon – Individual, Couples and Sex Therapy	190 Apple Blossom Drive\nVaughan, L4J 0E6	\N	Inclusive counselling / support for individuals and couples in the LGBTQ communities.	debbie.garshon@gmail.com	\N	647-991-8500	L4J	\N	\N	Debbie  Garshon\nMSW, RSW	\N	\N
273	rho	dr-irena-druce	Dr. Irena Druce	4270 Innes Road\nOttawa, K4A 5E6	\N	Gender-affirming hormone therapy (initiation and ongoing therapy) in the adult population, documentation for surgery pre-approval.	\N	\N	613-841-7009	K4A	\N	\N	Irena Druce\nMD, FRCPC	\N	\N
239	rho	dave-puzak-therapy	Dave Puzak Therapy	240 Roncesvalles Ave\nToronto, M6R 1L3	\N	I am a therapist working mainly in the Gestalt modality. My focus is on embodiment and trauma — specifically how this influences our relational patterns and identity. I have additional training in somatic embodiment and regulation strategies via Linda Thai. This in concert with my training in Gestalt therapy allows us to address trauma from not only a talk therapy perspective but also through embodiment, psychodrama, and nervous system regulation techniques. I am also a musician and incorporate this into my practice.	dpuzak@gestaltmail.ca	Weekday mornings, afternoon evenings. Weekend mornings, afternoons.	(647) 492-3693	M6R	\N	Sliding scale range - $/Hour Minimum: 60 Maximum: 100	Dave Puzak\nRegistered Psychotherapist	\N	https://www.psychologytoday.com/ca/therapists/dave-puzak-toronto-on/424704
240	rho	dave-smith-youth-treatment-centre	Dave Smith Youth Treatment Centre	112 Willowlea Road\nOttawa, K0A 1L0	\N	Located in Ottawa the Dave Smith Youth Treatment Centre (DSYTC) is a non-profit, residential, and community-based agency that is dedicated to helping youth (13-21) and families across Ontario overcome substance abuse and related issues and to achieve a healthier lifestyle. With separate evidence-based programs tailored to the specific needs of young people, it is the only Centre of its kind in Eastern Ontario.\nDSYTC programs and services include: comprehensive assessment, 3-month residential treatment, 3-month post-residential continuing care as well as family services (education, counselling, support). A professional referral is not required to attain services and there are no formal fees required to access DSYTC programming.	admissions@davesmithcentre.org	\N	613-594-8333	K0A	\N	\N	\N	\N	https://www.davesmithcentre.org
241	rho	davenport-perth-neighbourhood-community-health-centre	Davenport-Perth Neighbourhood & Community Health Centre	1900 Davenport Road\nToronto, M6N 1B7	\N	Multiservice community centre, including health centre and neighbourhood programs.\nAdult Services – for adults who may be isolated, marginalized, new to Canada, non-status, have experienced addiction issues, the psychiatric system, and/or are at risk of eviction.\nAdult Drop in – Monday, Thursday 12 noon-4 * various locations\nChildren’s Program – for children 6-12 years * summer and March break day camps * after school recreation programs and field trips * homework club\nCommunity Dining – nutritious meals Wednesday 5 pm, Friday 12 noon * nominal cost * access to community services\nCommunity Health Centre 416-658-6812 – call for appointment * individual and family medical and nursing services * palliative care * psychiatric services * counsellor therapists * mental health and addictions counsellor therapist * foot care * doctor on call Monday-Sunday 24 hours * house calls when appropriate * health education and promotion * outreach to isolated persons * community action on identified community health issues * no Ontario Health Insurance required for general services – some limitations apply\nCrisis Support and Intervention – Monday-Friday * call for times\nJob Search Workshop Program (JSW) – for new immigrants, Convention refugees and Protected Persons legally entitled to work in Canada * job search techniques workshops covering skills assessment, cover letter and resume help, labour market information, access to trades and professions, networking, mentoring, volunteering, lists of companies * extensive individual support\nOntario Early Years Centre\nPeer Street Outreach\nSeniors Program – 55 years and over * health education * advocacy * social, education and recreation activities * Italian and Portuguese women’s groups * Spanish-speaking group * arts program * fitness program * trips/outings\nSettlement Program\nYouth Program – 11-24 years	dpnc@dpnc.ca	\N	416 656-8025	M6N	\N	\N	\N	\N	https://www.dpnc.ca
242	rho	david-moulton-registered-psychotherapist-canadian-certified-counsellor	David Moulton – Registered Psychotherapist, Canadian Certified Counsellor	PO Box 21426 University of Toronto\nToronto, M5T 0A1	\N	I am a Registered Psychotherapist and Canadian Certified Counsellor in private practice, offering online virtual psychotherapy to clients in Toronto, Guelph/Kitchener/Waterloo, and across Ontario.  I help adults from the straight and LGBTQ communities and from the cisgender, trans, genderqueer and nonbinary communities with concerns including feeling stressed and anxious, feeling badly about themselves, loneliness or challenges in their relationships, challenges with being LGBTQ, sexuality, sexual orientation and gender, alternative relationships, and challenges with alternative sexualities.\nMy work is confidential and collaborative, and my office is a safe space to explore your concerns and how we can work through them together.  I address all aspects of my clients’ lives including friendships, family, culture and spirituality.  My approach to psychotherapy is cognitive behavioural, solution-focused, strengths-based and anti-oppressive – together we can work toward feeling better, managing your stress and finding balance in your life and relationships.\nMy services may be covered by most extended health benefit insurance plans.\nSpecialties: Psychotherapy, Counselling, Anxiety, Stress, Self-Esteem, Life Balance, Relationships, Couples, Alternative Relationships, LGBTQ, Sexuality, Gender, Alternative Sexualities	counselling@davidmoulton.ca	Monday, Tuesday, Thursday, Friday 9:30 AM to 4:45 PM (last appointment begins at 3:45 PM)	647-525-8268	M5T	\N	\N	David Moulton\nM.Ed., RP, CCC	\N	https://www.davidmoulton.ca
243	rho	david-razeghi-rmt-atcc	David Razeghi RMT ATC(c)	Toronto, M2N 7G6	\N	Education, Experience and an analytical perspective set David apart. He is an Athletic Therapist and a Massage Therapist with degree in Kinesiology and Exercise Science.\nFor David the needs of his patients are of extreme priority. After working for years with a variety of populations from high level athletes to non-athletes, he discovered that good communication, persistence and a setting reachable goals are essential to the recovery of his patients.\nHis focus is for patients to not stop their activities due to injury, but to use different techniques such as manual and exercise therapy to allow patients to maintain a healthy lifestyle before, during and after recovery.\nDavid is a firm believer in practicing what you preach. He loves to maintain an active lifestyle by doing weightlifting, yoga and trying new and different sports/activities in his free time. He is also a firm believer in leading a balanced lifestyle and the importance of spending time with family and friends.\nTrained on:\nDeep Tissue, Swedish and Sports Massage\nVarious Tapping and Bracing techniques\nRehabilitation and exercise techniques	david.razeghi@gmail.com	\N	\N	M2N	\N	\N	David Razeghi\nRMT CAT(c) BA Kine	\N	https://www.omegahealthandfitness.com/
244	rho	dawn-shikluna-psychotherapy	Dawn Shikluna Psychotherapy	14 Duke Street\nSt. Catharines, L2R 5W3	\N	Dawn has worked in the field of healing for over 15 years. She has Masters level education in Counselling Psychology as well as in Gender Studies and Community Development. She is also a Master level Reiki practitioner and has training and experience in energy work and Q’ero Shaman teachings and practices.\nFrom a compassionate, non-judgmental approach, Dawn offers counselling to individuals, couples and groups. Areas of specialization include stress & trauma, sexual and gender diversity, self-injury, bullying, relationships, anxiety & depression.	counselling.consulting@gmail.com	\N	905.324.7917	L2R	\N	\N	Dawn Shickluna\nMA, MEd, CCC	\N	https://www.dawnshickluna.com
245	rho	debbie-garshon-counselling	Debbie Garshon Counselling	1 Promenade Circle\nVaughan, L4J 4P8	\N	Experienced therapist providing compassionate and inclusive counselling to individuals and couples to improve their mental health, their relationships and achieve their optimal functioning and potential.	debbie.garshon@gmail.com	\N	647-991-8500	L4J	\N	\N	Debbie Garshon\nMSW RSW	\N	https://www.debbiegarshon.vpweb.ca
247	rho	deborah-weiler-registered-psychotherapist	Deborah Weiler, Registered Psychotherapist	400 Dupont Street\nToronto, M5R 1V9	\N	I am a Registered Psychotherapist and Certified Gestalt Therapist practicing in Toronto since 1999. I work with individuals. For more information, or to arrange for an initial complimentary consultation, please contact 416-588-7773 or deborahweiler@icloud.com	deborahweiler@icloud.com	\N	416-588-7773	M5R	\N	\N	Deborah Weiler\nRegistered Psychotherapist  (CRPO#001073)	\N	https://www.deborahweiler.ca
248	rho	deep-listening-therapy	Deep Listening Therapy	\N	\N	I specialize in telephone counselling for women and queer folks, with training in feminist and cross-cultural therapy. Paired with mindfulness meditation practices, this forms the basis of a precise psychotherapy as well as a deeply connected and compassionate relationship with my clients.\n(Telephone Psychotherapy has many benefits – it is convenient, accessible, and research shows it is as effective as in-person counselling.)\nWith over 25 years experience, I honour the unique challenges and needs that women and queer folks face.\nCounselling with me is collaborative, and emphasizes the health of the total person. I use a trauma-informed, holistic approach highlighting emotional, mental, physical, and spiritual health.\nI offer a free telephone consultation to see if we might be a good fit. Contact me to set this up: https://danyadaccash.com/contact-me/	danya.daccash@gmail.com	\N	\N	\N	\N	\N	Danya Daccash\nM.S.W., R.S.W.  Registered Social worker, psychotherapist	\N	https://www.danyadaccash.com
249	rho	deep-listening-therapy-2	Deep Listening Therapy	\N	\N	I specialize in telephone counselling for women and queer folks, with training in feminist and cross-cultural therapy. Paired with mindfulness meditation practices, this forms the basis of a precise psychotherapy as well as a deeply connected and compassionate relationship with my clients.\n(Telephone Psychotherapy has many benefits – it is convenient, accessible, and research shows it is as effective as in-person counselling.)\nWith over 25 years experience, I honour the unique challenges and needs that women and queer folks face.\nCounselling with me is collaborative, and emphasizes the health of the total person. I use a trauma-informed, holistic approach highlighting emotional, mental, physical, and spiritual health.\nI offer a free telephone consultation to see if we might be a good fit. Contact me to set this up: https://danyadaccash.com/contact-me/	danya.daccash@gmail.com	\N	\N	\N	\N	\N	Danya Daccash\nM.S.W., R.S.W.  Registered Social worker, psychotherapist	\N	https://www.danyadaccash.com
250	rho	derek-scott-psychotherapy	Derek Scott Psychotherapy	London, N6C 2E4	\N	Psychotherapy based on 30 years experience and using the Internal Family Systems model. Available via Skype. Please visit my website www.yourtherapist.org for a brief video outlining how I work.	derek@yourtherapist.org	\N	519 438 6777	N6C	\N	\N	Derek Scott\nRSW	\N	https://www.yourtherapist.org
251	rho	designability-program-march-of-dimes	DesignAbility Program – March of Dimes	3340 Schmon Parkway\nThorold, L2V 4Y6	\N	The DesignAbility Program uses the ingenuity and spirit of wonderful volunteers to help people living with physical limitations find solutions to everyday challenges. DesignAbility links technically skilled volunteers with people living with physical disabilities to help find solutions that make life easier. Volunteers have created many items including a remote holder that allowed a gentleman with reduced dexterity to change the channels on his TV, and an oven lift that allowed one woman to lift heavy pans from her oven to her countertop. The Thorold DesignAbility Chapter is always open to new project requests and is eager for the opportunity to help increase the independence of Niagara region residents with physical disabilities.	designability@marchofdimes.ca	\N	905-687-8484, ext 249	L2V	\N	\N	\N	\N	https://tinyurl.com/DesignAbilityNiagara
252	rho	diabetes-education-program	Diabetes Education Program	\N	\N	The program provides individual and group education on diabetes prevention and management with a nurse and dietitian.	\N	\N	\N	\N	\N	\N	\N	\N	\N
253	rho	diamond-physiotherapy	Diamond Physiotherapy	55 Pinnacle St\nBelleville , k8n 3a1	\N	We are a health team that provides Physiotherapy, Pelvic Health, Psychotherapy, and Pedorthic care.  We believe in treating people with a client led philosophy; this means that you will always have a say in how your health care is managed and provided to you.  We provide general care and wellness around mobility with our Physiotherapists for recovery post injury or to help manage pain.  Nicola is able to provide pre and post-op pelvic floor physiotherapy, and our Psychotherapy team has experience working with the trans community.  We are able to direct bill to insurance should your plan allow.	frontdest@diamondphysiotherapy.ca	M-Th 8am - 7pm, F 8am - 5pm, Sa 9am - 1pm	(613) 969-7229	\N	\N	Fees for service vary by practitioner general range of $85-$150 CAD.	\N	\N	https://www.diamondphysiotherapy.ca/
254	rho	diana-jaskolka-endocrinologist	Diana Jaskolka – Endocrinologist	2130 North Park Drive, Unit 38\nBrampton, L6S 0C9	I can provide transition related surgery assessments for top or bottom surgeries	Endocrinologist at Brampton Civic Hospital	\N	Monday/Wednesday ***Please note I currently am not accepting referrals as I will be on maternity leave from October 2021-June 2022***	\N	L6S	\N	\N	Diana Jaskolka\nMD, FRCPC	\N	\N
255	rho	dingwall-medical-clinic	Dingwall Medical Clinic	40 Goodall St.\nDryden, P8N 2Z6	\N	I provide gender affirming care including hormone therapy, assessment and referral for gender affirming surgery.	doctalk@drhc.on.ca	Monday -Thursday 8:30 – 4:30 Friday 8:30 – 1:00 Saturday Closed Sunday Closed	(807) 223-6683	P8N	\N	\N	Dr. Francois Doiron	\N	https://www.dingwallmedicalclinic.ca/
256	rho	dino-paoletti-counselling	Dino Paoletti Counselling	816 Pape Avenue\nToronto, M4K 3T3	\N	Individual counselling services for LGBT community members and allies. I’ve been a service provider in our community since 1991. I also do training and facilitation work for service providers (anti-homophobia work, HIV/AIDS work, diversity training). My work also involves consulting to community agencies in the areas of strategic planning, community consultations and program evaluation. For further information, please contact me by email or voicemail and I’d be very happy to elaborate.	dinopaoletti@hotmail.com	\N	(416) 406-6227	M4K	\N	\N	Dino Paoletti\nMEd	\N	\N
257	rho	diversity-ed-safer-spaces-canada	Diversity Ed. – Safer Spaces Canada	179 Christina St. N\nSarnia, N7T 5T8	\N	We are a federally incorporated community-based organization focused on helping make the world around us a happier and safer place for 2SLGBTQAI+ folx, their families and allies. With the help of our tireless staff and volunteers, we organize educational forums for youth, service providers and the community, exciting community-building events, and in-depth diverse programming for the intersectional 2SLGBTQAI+ community.\nWe also run QT Camp & Forum which is a 2SLGBTQAI+ overnight camp from August 3-7 for youth across Ontario. Camp is completely funded.\nWe also host educational workshops for a variety of sectors including justice, healthcare, social services, private business, education,  corporate and government.	crystal@diversityed.ca	Monday to Friday: 10 a.m. to 6 p.m. Some evenings and weekends for structured programming.	5489975428	N7T	\N	\N	\N	\N	http://www.diversityed.ca
258	rho	divinely-felt-spiritual-direction	Divinely Felt – Spiritual Direction	Toronto, M1N 3M2	\N	My work is a work of hospitality. It is soul care. It is a way of accompanying another as they seek for meaning, It is not counseling or psychotherapy but a relationship of pilgrims looking for the holy in the ordinary.\nSpiritual direction is the practice of being with people as they attempt to deepen their relationship with the divine, or to learn and grow in their own spirituality. Divinely Felt is inclusive and honours each journey as sacred and unique.\nPlease visit my website www.divinelyfelt.com or my Facebook page.	divinelyfelt@gmail.com	\N	647 438-8204	M1N	\N	\N	Nicole  Bourassa-Burke\nAcredited Spiritual Director -Jubilee Associates	\N	https://divinelyfelt.com
259	rho	dora-jackson-rmt-registered-massage-therapist	Dora Jackson RMT – Registered Massage Therapist	246 Garden Avenue - back door\nToronto, M6R1J3	\N	Hello, my name is Dora and I’m a Registered Massage Therapist in Toronto, Ontario (Roncesvalles/High Park area).\n2022 marks my 20th year in practice as an RMT and I love it. I run a home-based clinic that is self-contained, private and pet-free. I have a number of treatment options available, but I can adapt on the fly no matter which one you choose. To learn more about my education, experience, philosophy of care and what you can expect, please visit my website here.\nI hope you find all the information you need but you’re welcome to drop me a line via email or through my contact page if you’re having trouble.\nAnd yes, I’m fully vaccinated!	dorajacksonrmt@gmail.com	Monday, Tuesday, Friday: 9 a.m. to 5 p.m. Wednesday: 3:30 p.m. to 8 p.m. Thursday: 9 a.m. to 1 p.m. Saturday: 9 a.m. to 10:30 p.m. Sunday: closed	416-560-3469	M6R	\N	Varies by treatment length - please refer to my website for details or copy/paste the following link - https://www.dorajackson.com/office-visits-fees/	Dora Jackson\nRMT	\N	https://www.dorajackson.com
260	rho	dorothys-place	Dorothy’s Place	33 East Road\nToronto, M1N 1Z9	\N	Dorothy’s Place is a program for LGBTQ2S+ seniors. We offer a weekly lunch and social program where delicious food, interesting speakers and friendly connections as well as educational and entertaining programming are offered.	dorothysplace4u@gmail.com	\N	6473605767	M1N	\N	\N	\N	\N	https://www.bbuc.ca/dorothysplace
261	rho	dr-ashraf-ahmed	Dr. Ashraf Ahmed	2 Carlton Street\nSuite 1823\nToronto, M5B 1J3	I can provide transition related surgery assessments for top or bottom surgeries\nI can provide secondary assessments for transition-related bottom surgeries	I work with LGBTQ children, adolescents, adults, and families on a multitude of issues including gender and sexual orientation concerns, depression, anxiety, relationship difficulties, substance use, etc.	drashrafahmed@gmail.com	Monday, Tuesday, Thursday and Friday By appointment	647-215-4050	M5B	\N	\N	Ashraf Ahmed\nPh.D.	\N	https://www.ashrafahmed.ca/
262	rho	dr-brad-hutt-at-dr-johal-associates-optometry	Dr. Brad Hutt at Dr. Johal & Associates Optometry	2960 Kingsway Drive\nFairview Park Mall\nKitchener, N2C 1X1	\N	Eye doctor providing comprehensive eye examinations including ocular health care, vision assessment, spectacle and contact lens prescriptions.	fairviewparkeye@hotmail.com	Office Hours: Monday 11:00 am - 6:00 pm Tuesday 11:00 am - 6:00 pm Wednesday 11:00 am - 6:00 pm Thursday 11:00 am - 6:00 pm Friday 11:00 am - 6:00 pm Saturday 10:00 am - 5:00 pm Sunday 11:00 am - 5:00 pm Dr. Hutt Clinic Hours: Sunday 11:00 am - 5:00 pm Saturday 10:00 am - 5:00 pm Sunday 11:00 am - 5:00 pm	5197489308	N2C	true	Comprehensive Eye Examination - $130 - OHIP covered for certain populations	Brad Hutt - Optometrist\nDoctor of Optometry - O.D.	\N	https://local.lenscrafters.ca/eyedoctors/on/kitchener/2960-kingsway-drive.html
263	rho	dr-brad-hutt-at-optical-design-of-optometry	Dr. Brad Hutt at Optical Design of Optometry	84 Wellington Street\nStratford, N5A2L2	\N	Eye doctor and optician staff providing comprehensive eye examinations including ocular health care, vision assessment, spectacle and contact lens prescriptions.	info@opticaldesign.ca	Office Hours: Tuesday - Friday: 10:00 a.m. - 4:00 p.m. Saturday: 10:00 a.m. - 2:00 p.m. Sunday and Monday: closed Clinic Hours: Wednesday and Friday: 11:00 am - 2:00 pm	5192717171	N5A	\N	Comprehensive Eye Examination - $100 - OHIP covered for certain populations	Brad Hutt - Optometrist\nDoctor of Optometry - O.D.	\N	https://www.opticaldesign.ca/index.html
264	rho	dr-brian-rotenberg	Dr. Brian Rotenberg	268 Grosvenor St\nLondon, N6A 4V2	\N	I can assist patients looking for feminization procedures of the face.  Specifically:	brian.rotenberg@sjhc.london.on.ca	9-5	5196466320	N6A	\N	Depends on procedure being requested. Some would be insured by OHIP, others would not be.	Brian Rotenberg\nMD MPH FRCSC	\N	https://www.brianrotenberg.com/
265	rho	dr-carmen-weiss-associates	Dr. Carmen Weiss & Associates	5195 Harvester Road\nBurlington, L7L 6E9	\N	We are an LGBTQ+ practice offering comprehensive psychological services, including assessment, support, and counselling. We are qualified under the MOHLTC guidelines to conduct Sex Reassignment Surgery assessments and provide letters of recommendation for these surgeries.	intake@drcarmenweiss.ca	\N	289-427-5577	L7L	\N	\N	Carmen Weiss\nPh.D., C.Psych.	\N	https://www.drcarmenweiss.ca
266	rho	dr-cyndi-gilbert-nd	Dr Cyndi Gilbert ND	166 Montrose Avenue\nToronto, M6J 2T8	\N	Hi! I believe in acknowledging and addressing the parts of health too frequently neglected in medicine – the mental/emotional pieces, the sociocultural aspects, the environment around you, and the patterns of relationship between it all.\nThrough a patient-centered and collaborative approach, I focus on assisting you to identify the source of your concerns, remove obstacles to your health, and support your body’s innate ability to heal using individualized nature therapy and naturopathic medicine. I am committed to a harm reduction and anti-oppression model of care that affirms you, and respects your first-hand knowledge of your own health.\nPlease see my website or contact me for more information.	cyndi@cyndigilbert.ca	Tuesday-Thursday: 9 a.m. to 3 p.m.	(416)817-2385	M6J	\N	Sliding scale range - $/Hour Minimum: 120 Maximum: 180	Cyndi Gilbert\nND	\N	https://www.cyndigilbert.ca
267	rho	dr-daniel-paluzzi	Dr. Daniel Paluzzi	491 Church Street\nToronto, M5B 1Z4	\N	Family doctor specializing in the care of persons living with HIV and the LGBTQ2 community. I provide gender-affirming care including hormone therapy and referrals for surgery.	info@cwhealth.ca	\N	416-463-1500	M5B	\N	\N	Daniel Paluzzi\nMD	\N	https://www.cwhealth.ca/
268	rho	dr-ed-weiss	Dr. Ed Weiss	523 The Queensway\nToronto, M8Y 1J6	\N	**Please note that as of September 2019 I am not accepting new patients, sorry!**\nI provide full-spectrum family medicine care for children and adults. LGBTQ patients are welcome, and I am happy to provide ongoing care for transgender people, including hormone therapy.\nToronto West Medical is situated at the corner of The Queensway and Park Lawn Road in Etobicoke. We have ample free parking, and the clinic is TTC-accessible via a bus from Old Mill station. The Mimico GO station is also nearby. There are ten family physicians currently working here, and we are part of the Metro West FHO, with after-hours care provided daily during the week.	\N	\N	416 760 8367	M8Y	\N	\N	Edward Weiss\nMD, CCFP	\N	\N
275	rho	dr-jennifer-huynh	Dr. Jennifer Huynh	2525 Old Bronte Road\nUnit 580\nOakville, L6M4J2	I can provide transition related surgery assessments for top or bottom surgeries	Dr. Huynh is an adult endocrinologist. She has expanded her practice to encompass transgender medicine, including gender affirming hormone therapy. A prior diagnosis of gender dysphoria is not a requirement for referral. Dr. Huynh will use her discretion if an additional assessment for gender dysphoria is required.\nDr. Huynh has also completed the Transition Related Surgery Assessment training course through Rainbow Health Ontario and will apply for OHIP funding on behalf of the patient. Her goal is to provide local, comprehensive care to the transgender and gender non-binary community in the Halton region.\n	\N	Monday -Thursday 10-4pm	905 338 0550	L6M	\N	\N	\N	\N	https://www.drjhuynh.com
276	rho	dr-jessica-salituri	Dr. Jessica Salituri	Barrie, L4M 0H9	\N	Rheumatologist	info@sems.ca	Monday- Friday: 8:30 a.m. - 4:30 p.m.	7058819810	L4M	\N	\N	\N	\N	https://doctors.cpso.on.ca/DoctorDetails/Salituri-Jessica---Marie/0323185-114309
277	rho	dr-kamala-sivasankaran-nd	Dr. Kamala Sivasankaran, ND	2 College Street\nToronto, M5G 1K2	\N	Toronto Naturopathic Doctor practicing at Yonge & College with special interest in autoimmune conditions, anxiety & stress management, insomnia, hormonal health and digestive concerns. Focus on empowering patients through education and providing safe and compassionate care to the LGBTQ community.\nWith a background in biology and health sciences, I value a combination of both traditional and conventional approaches to medicine, and often suggest natural therapies that work together with any conventional treatment you may be taking. Treatment plans can include therapies such as acupuncture, herbs, specific foods, rehabilitation exercises, cupping, natural supplements, hydrotherapy, counselling and more.	kamala@drkamaland.com	\N	647-361-5191	M5G	\N	\N	Kamala Sivasankaran\nNaturopathic Doctor, Personal Trainer (CSCS)	\N	https://www.drkamaland.com
278	rho	dr-kate-gerster-obstetrician-gynecologist-dallaire-medicine	Dr. Kate Gerster, Obstetrician/Gynecologist, Dallaire Medicine	707 Charlotte Street\nPeterborough, K9J 2X5	\N	Obstetrician/Gynecologist	\N	\N	7057499695	K9J	\N	\N	Dr. Kate Gerster\nBsc MD FRCSC	\N	\N
279	rho	dr-kate-whitehead-toronto-grace-hospital-palliative-care	Dr. Kate Whitehead – Toronto Grace Hospital – Palliative Care	47 Austin Terrace\nToronto, M5R 1Y6	\N	Provide Palliative Care (care of those with a terminal illness) for people in hospital. Home visits are possible in special cases.	kwhitehead@torontograce.org	\N	416 925 2251 x271	M5R	\N	\N	Kate Whitehead\nM.D.	\N	\N
280	rho	dr-katie-cuttini-family-physician	Dr. Katie Cuttini, Family Physician	Midland, L4R 4P4	\N	Family physician providing primary care in Midland, with a special interest in reproductive and trans health.	contact.by@telephone.only	Monday to Friday 9:00-5:00	705-526-5825	L4R	\N	\N	\N	\N	http://www.acgdoctors.com/
281	rho	dr-kim-abog-naturopathic-doctor	Dr. Kim Abog, Naturopathic Doctor	181 Eglinton Avenue East\nSuit 207\nToronto, M4P 1J4	\N	Providing integrative fertility and reproductive health care	kimabognd@gmail.com	Mondays 2-7PM Tuesdays 8AM-4PM Wednesdays 8AM-4PM Thursdays 8AM-4PM Fridays 8AM-3PM Saturdays 8AM-1PM	email only	M4P	true	$50-200	Dr. Kim Abog, Naturopathic Doctor\nND	\N	https://www.kimabog.com
282	rho	dr-kris-kuciel-nd	Dr. Kris Kuciel, ND	Toronto, M4E2E1	\N	Dr. Kris Kuciel, ND (he/they) is your friendly board certified virtual Naturopathic Doctor in Ontario. They provide a holistic and natural approach to your health in conjunction with conventional medicine, while also being heavily research based. Major conditions they treat are autoimmune diseases and digestive health concerns. They proudly service the 2sLGBTQ+ community.	drkriskuciel@gmail.com	Virtual Appointments Tuesdays - 12pm-7pm Wednesdays - 10am-6pm Thursdays - 10am-6pm In-Person hours coming soon.	647-492-2040	M4E	\N	Check website: https://drkriskucielnd.janeapp.com/	Dr. Kris Kuciel\nNaturopathic Doctor, ND	\N	https://www.drkriskuciel.com/
283	rho	dr-kyla-ludlow-and-dr-michelle-bartens-halton-mcmaster-family-health-centre	Dr. Kyla Sorensen (formerly Ludlow) and Dr. Michelle Bartens, Halton McMaster Family Health Centre	1221 Lakeshore Road\nBurlington, L7S 0A1	\N	We are family physicians who work in an academic teaching centre. We share a practice with one another, and we teach family medicine residents. These physician residents are with us for two years, until they start their own practices. We actively see our own patients, as well as supervise residents seeing our patients. Also, Dr. Sorensen (formerly Ludlow) is an instructor with McMaster University in the Department of Family Medicine in Mental Health and Behavioural Sciences.\nWe offer all aspects of family medicine care, including preventative health care, and diagnosis and treatment of medical conditions. We endeavour to create a safe space for all comers, and provide care to LGBTQ families and their children. Further, we are also happy to assist with transitioning for patients using the Sherbourne Trans Health Care Model. We do not purport to be experts in this, but caring physicians who wants to help all our patients with their health care.\nAs a member of a family health team, our patients also have access to social work counselling, a dietitian, occupational therapy, psychiatry (via physician consult), after hours clinic (via appointment), and a mental health nurse.\nInitial appointments are meet and greets, in which you get a chance to learn about the clinic and our booking practices, and we can generate a chart with your medical history. It is NOT a screening of potential patients. Once a meet and greet appointment is given you are accepted as a patient. It is however also not an initial medical appointment, and often people book a follow up appointment for health concerns after the initial meet and greet.	\N	\N	9053338222	L7S	\N	\N	Dr. Kyla Sorensen (formerly Ludlow)\nBSW, MD, CCFP	\N	https://www.burlingtonfht.com
284	rho	dr-larry-baer-psychologist	Dr Larry Baer, Psychologist	692 Euclid Avenue\nToronto, M6G 2T9	\N	The goal of my practice is to provide a safe, non-judgemental and empathic space where you can grow to become your best self. I work in a primarily cognitive behavioural therapy (CBT) framework, within an environment of compassion, collaboration and trust that facilitates the work of psychotherapy. As a member of the LGBTQ+ community, I am especially sensitive to the specific issues that our community faces that can affect our mental health. Please check out my website and book a free phone consultation.	drlarrybaer@gmail.com	\N	647-873-5889	M6G	\N	\N	Larry Baer\nPhD, C.Psych.	\N	https://www.drlarrybaer.com
327	rho	emma-sutton-therapy	Emma Sutton Therapy	521 Colborne Street\nLondon , N6B 2B7	I can provide secondary assessments for transition-related bottom surgeries		emma.sutton@risinginsightcounselling.com	Availability Monday-Friday for both in-person and virtual counselling sessions.	(226) 286-4305	N6B	\N	$130\nSliding scale range - $/Hour Minimum: 100 Maximum: 130	\N	\N	https://www.risinginsightcounselling.com/emma-sutton
351	rho	family-therapy-ottawa	Family Therapy – Ottawa	4019 Carling Avenue\nOttawa, K2K 2A3	\N	Family-Therapy offers you professional and confidential counselling in Ottawa. We are independent therapists who can address child and teen therapy, family and step-family challenges, individual, and couple therapy issues.	info@family-therapy.ca	\N	613-287-3799	K2K	\N	\N	Shelley Colter\nRegistered Psychotherapist; CRPO Lic#003720	\N	https://family-therapy.ca
285	rho	dr-laura-hoffmann-naturopathic-doctor	Dr. Laura Hoffmann, Naturopathic Doctor	3 Waterloo Street\nNew Hamburg, N3A 1S3	\N	Dr. Laura Hoffmann, ND, helps people of all ages to reduce pain, manage their hormones, and optimize the pillars of health: sleep, digestion, exercise and energy!\nDr. Laura has been trained in evidence-based medicine, hormone replacement therapy, and acupuncture. She uses blood work and body composition analysis to thoroughly assess and monitor disease progression. She is skilled in checking for any medication-supplement interactions to ensure safe treatments.\nHer practice includes treating a variety of health concerns with a focus on pain management, arthritis, fibromyalgia, diabetes, and blood pressure management. She has a special interest in hormonal health and menopause hormone therapy and has completed advanced training in safety and prescribing. She enjoys helping people to feel their best no matter which stage of life they are in!\nAccessible and affordable health care is important to Dr. Laura so she offers the community acupuncture program with reduced rates for visits, check out the acupuncture tab of the clinic’s website to learn more.\nBorn and raised in Stratford, and now living in Kitchener, she is thrilled to be a part of Affinity Health Clinic in New Hamburg and serving the Region of Waterloo community.	wecare@affinityhealthclinic.ca	Tuesday 10 a.m. - 4 p.m. Wednesday 3 p.m. - 7 p.m. Thursday 9 p.m. - 1 p.m.	5196622123	N3A	\N	Initial visit (virtual or in person): $180; follow up visit (virtual or in person): $95. Community acupuncture available for $40 per visit	Naturopath\nND	\N	https://affinityhealthclinic.ca/
286	rho	dr-laura-von-hagen-nd	Dr. Laura von Hagen, ND	1937 Gerrard St E\nToronto, M4L 2C2	\N	As a Naturopathic Doctor, Laura loves her job because she treats people, not illnesses. She listens carefully to their concerns, and employs evidence-based treatment options not previously considered by conventional medicine. Laura fundamentally believes in empowering patients to regain control over their health, and helping them achieve their greatest health goals. She focuses on individualized treatment plans that address the mental, emotional and physical levels of healing.\nLaura has a special interest in hormonal disorders, reproductive health and family planning. During her fourth-year internship, Laura was selected for the highly competitive Fertility and Reproductive Health Focus shift, where she received additional training in adjunctive fertility care. She incorporates acupuncture, herbal medicine, nutrition counselling and lifestyle support in her practice.\nOutside of clinic, she likes to spend my free time biking, running, swimming, kayaking, basically anything outdoors! Laura has travelled to over two dozen different countries and enjoys experimenting in the kitchen, especially if it involves dark chocolate.	info@lauravonhagen.com	Wednesday 8 am -7 pm Thursday 2 pm -7 pm	(416) 627-5006	M4L	\N	\N	Laura von Hagen\nB.sc. Kinesiology, M.Sc. Clinical Anatomy, Doctor of Naturopathy (ND)	\N	https://lauravonhagen.com/
287	rho	dr-leah-zalan-ph-d-c-psych	Dr. Leah Zalan, Ph.D., C. Psych.	Virtual Psychological Services\nToronto, M5M2K3	\N		drleahzalan@protonmail.com	9-4pm, Monday to Friday	416-949-1290	M5M	\N	225$ per session (1 hour) - My fees are covered under many extended health benefits plans, please check with your provider if applicable.	Dr. Leah Zalan\nPh.D., C. Psych.	\N	https://www.psychologytoday.com/ca/therapists/dr-leah-zalan-phd-c-psych-north-york-on/226787
288	rho	dr-lukanathan-family-doctor	Dr Lukanathan – Family Doctor	26 Hospital Drive\nPeterborough, K9J 7C3	\N	Dr. Vanita Lokanathan is a family doctor that joined the Peterborough Clinic in 2008.  Vanita completed her medical degree at McGill University in 1993 and her Family Practice Residency at Memorial University of Newfoundland in 1995.  She had a family practice in British Columbia from 1996 until her relocation to Peterborough in 2008.\nVanita and her wife Sheena have two boys whom they love spending quality time with.	vlokanathan@ptboclinic.com	\N	(705) 740-6867	K9J	\N	\N	\N	\N	https://www.ptboclinic.com/
289	rho	dr-marco-hernandez-naturopath-at-jaya-integrative-health-centre	Dr. Marco Hernandez Naturopath at Jaya Integrative Health Centre	527 Bloor Street West\nToronto, M5S 1Y5	\N	Toronto based Naturopathic Doctor with a special focus on mental health, emotional wellness, stress management, and skin conditions. The back-to-basics lifestyle and dietary approach that he employs along with mind-body medicine techniques help to address the root cause of illness and allow for healing to occur at a deeper physical, mental, emotional, and spiritual level.\nHis clinical practice is an all-inclusive, safe, and open environment that is free of judgment and discrimination, allowing for healing, health education, and personal growth to take place. He makes sure to provide a space where patients feel comfortable to share their thoughts and ideas. As a proud member of the LGBTQ community, he is honoured to help folks from diverse cultural backgrounds and ethnicities, genders, and family systems. He enjoys connecting with patients from all walks of life and strives to build strong working relationships that are based on trust.\nServices provided include: acupuncture, botanical medicine, clinical nutrition, homeopathy, hydrotherapy, nutritional and lifestyle counselling, physical medicine, and Traditional Chinese Medicine.\nFor more information about Dr. Marco please contact him or visit his website: www.drmarcond.com	marco@drmarcond.com	\N	647-715-6313	M5S	\N	\N	Marco Hernandez\nNaturopathic Doctor	\N	https://www.drmarcond.com
290	rho	dr-matt-sandre-dermatologist	Dr. Matt Sandre – Dermatologist	2075 Bayview Ave Room M1-700, Toronto, ON\nToronto, M4N 3M5	\N	I am a board-certified medical and cosmetic dermatologist working primarily out of Bertucci MedSpa in Woodbridge, and the Sunnybrook Dermatology Clinic in Toronto.\nAs a member of the 2SLGBTQ community myself, I am committed to ensuring my patients have a safe, comfortable, and supportive environment to feel at ease while having their medical and cosmetic dermatology concerns addressed.\nI accept referrals for Dermatology medical concerns such as acne, rosacea, skin lesion/mole checks etc… at the Sunnybrook Dermatology Clinic. Patients do need a referral from another physician or nurse practitioner and these services are covered by OHIP.\nAt both Sunnybrook Dermatology and Bertucci MedSpa I perform a large range of non-OHIP covered aesthetic services including benign lesion removal such as skin tags (referral may be required for initial assessment), scar treatment, Botox, injectable fillers, laser hair removal and other laser procedures. For these services you are able to telephone the clinic yourself and request an appointment directly with me or the aesthetician/laser tech.\nFeel free to call either clinic to ask any questions or to book an appointment.\nIG:@drmattdermatology	\N	Hours of Operation: 9-4pm	416-480-6897	M4N	L4L 8E2905-850-4415Directions	Varies for cosmetic services. Medical appointments are covered by OHIP.	\N	\N	https://www.instagram.com/drmattdermatology/?hl=en
291	rho	dr-matt-tribe	Dr. Matt Tribe	110 Anne St S, Unit 3\nUnit 3\nBarrie, L4N 2E3	\N	Providing spinal health and chiropractic care including acupuncture to all residents of Barrie and the surrounding area. Trained in manual, Activator, Graston, Thompson, and manual release techniques. Provides safe, comfortable care that suits the needs and treatment styles of all patients.	info@dynamicmovement.ca	Mon 2:30-6pm Tue and Thur 8-12:30pm Wed 2:30-7pm Fri 1:30-6pm	705-9864582	L4N	\N	\N	Dr. Matt Tribe\nBSc, DC	\N	https://www.dynamicmovement.ca
292	rho	dr-michael-berenstein-chiropractic	Dr Michael Berenstein Chiropractic	33 Hazelton Avenue\nToronto, M5R 2E3	\N	Dr. Michael Berenstein works at Satori Urban Wellness in Yorkville, downtown Toronto where he practices as a chiropractor, manual therapist and wellness coach.\nDr. Berenstein administers evidence-based, integrated treatment to provide patients with the best care in the areas of pain management, acute and chronic injury care, physical rehabilitation, and wellness. Dr. Berenstein blends the hands-on approach of chiropractic and manual therapy with advanced laser therapy, exercise and education to help each patient achieve their goals. Custom orthotics, shoes, and referrals to Satori’s complementary therapy providers can all be integrated into each patient’s treatment when necessary.\nSatori is a health-care facility with a dedicated team of holistic healthcare practitioners in Yorkville, downtown Toronto. In addition to Dr. Berenstein, Satori has an excellent team including a naturopath, osteopath, acupuncturist and massage therapists.\nSo, whether you have been putting up with pain for many years, recently suffered an injury, or are seeking optimal wellness Dr. Berenstein and Satori’s team of therapists have a treatment option for you. Call us today and we can develop a health plan specific for your needs.	DrB@MichaelBerenstein.com	\N	4169729355	M5R	\N	\N	\N	\N	https://www.MichaelBerenstein.com
293	rho	dr-michael-richardson	Dr Michael Richardson	790 Bay Street\nToronto, M5G 1N8	\N	Family doctor with a focus in care for people living with HIV and the LGBTQ+ community. I provide gender-affirming care including hormone therapy and referrals for surgery.	\N	\N	416-926-0101	M5G	\N	\N	Michael Richardson\nFamily Doctor	\N	\N
294	rho	dr-patrick-luke-urologist	Dr Patrick Luke – Urologist	800 Commissioners Road East\nLondon, N6A 5W9	\N	Patrick Luke is a Professor of Surgery and the Co-Director of the Multiorgan Transplant Program at the London Health Sciences Centre. Dr Luke has worked with trans clients and is respectful and gets good reviews.	\N	\N	(519) 685-8500	N6A	\N	\N	\N	\N	https://www.lhsc.on.ca/
295	rho	dr-peter-vlaovic-urologist	Dr Peter Vlaovic – Urologist	825 Coxwell Avenue\nToronto, M4C 3E7	\N	Trans-positive urologist located in East Toronto that performs Orchiectomy surgery for trans women.	\N	\N	(416) 461-8272	M4C	\N	\N	\N	\N	https://www.tegh.on.ca/bins/content_page.asp?cid=4874
296	rho	dr-rosemary-plastow	Dr. Rosemary Plastow	Windsor, N9B3P4	I can provide secondary assessments for transition-related bottom surgeries	I support trans and gender diverse students with medical, legal, and social transitions including documentation for HRT.	scc@uwindsor.ca	8:30-4:30	519-253-3000 x4616	N9B	\N	\N	\N	\N	https://www.uwindsor.ca/wellness/351/dr-rosemary-plastow
297	rho	dr-suki-hon-nd-naturopathic-consults-acupuncture	Dr. Suki Hon, ND (Naturopathic Consults And Acupuncture)	409 Roncesvalles Ave.\n489 College St. Suite 301\nToronto, M6G 1A5	\N	Services offered\nAccessibility offered\nSuki is an ND with a focus on stress/burnout (+ stress-related concerns), as well as tackling modern-day conditions (i.e. low mood, anxiety, sleep concerns, digestive issues, insulin resistance, irregular and painful periods etc).By addressing the key pillars of health (nutrition/digestion, movement, stress, sleep), Suki believes that we can build the foundations we need to lead a healthy and well-balanced lifestyle.Suki is passionate about creating equal health opportunities by increasing accessibility to naturopathic care. In considering the physical, mental, environmental, socioeconomic, cultural, and racial aspects, Suki strives to help you find sustainable healthcare solutions that work for you.\nPlease visit www.sukihon.com for more info	hello@sukihon.com	Mondays at Urban Wellness (College location): 2 p.m. to 8 p.m. Wednesdays and Fridays @ The Herbal Clinic & Dispensary (Roncesvalles location): 10 a.m. to 6 p.m.	6479806280	M6G	\N	\N	Suki Hon\nNaturopathic Doctor	\N	https://www.sukihon.com
298	rho	dr-t-lacroix	Dr. T. Lacroix	110-265 N. Front St\nSarnia, N7T7X1	\N	Consulting pediatrician who offers puberty suppression and gender affirming hormone therapy.	sarniapeds@gmail.com	Monday to Thursday 9:30 AM to 4 PM	5193444868	N7T	\N	\N	Dr. Tom Lacroix\nMD, CM, FRCPC Pediatrics	\N	https://www.sarniapeds.com
299	rho	dr-william-singer-endocrinologist	Dr. William Singer – Endocrinologist	Toronto	\N	Dr. William Singer is an endocrinologist who will also prescribe hormones to trans folks in consideration with the endocrine system and hormonal imbalances due to issues such as diabetes, thyroid issues etc. He works at MCI Doctors Office as well as St. Michael’s Hospital.	\N	\N	416.368.6787	\N	\N	\N	Dr William Singer\nM.D.	\N	https://mcithedoctorsoffice.ca/
300	rho	dryden-area-family-health-team	Dryden Area Family Health Team	40 Goodall Street\nDryden, P8N 1V8	\N	The Dryden Area Family Health Team is a primary care organization that is comprised of health care professionals that deliver accessible, high quality services to the community for the purpose of improving health. We celebrate innovation and excellence in care with dedicated leadership supporting comprehensive and compassionate care. The Dryden Area Family Health Team is dedicated to the community and reflects this practice in our integration and collaborative relationships with supporting agencies. The Dryden Regional Health Centre provides the governance of the Dryden Area Family Health Team.	info.fht@dh.dryden.on.ca	\N	807-223-7406	P8N	\N	\N	\N	\N	https://drydenfht.ca/
301	rho	dundas-dental-hygiene-clinic	Dundas Dental Hygiene Clinic	4154 Dundas Street West\nToronto, M8X 1X3	\N	We provide oral health care, preventative scaling and periodontal treatment, stain removal, teeth whitening, fluoride treatment, nutritional education	dundasdentalhygieneclinic@gmail.com	\N	416 233 1933	M8X	\N	\N	Toni Lombardo\nRegistered Dental Hygienist	\N	https://www.dundasdentalhygieneclinic.com
302	rho	durham-college-campus-health-centre	Durham College – Campus Health Centre	2000 Simcoe Street North\nOshawa, L1G 8C4	\N	The Campus Health Centre is pleased to offer a variety of services for you to choose from. All services are confidential and comprehensive. Our team consists of physicians, nurses, chiropractors, massage therapists,  mental health professionals, administrative staff and nutritionist working together to assist you in managing your healthy lifestyle.\nThe medical clinic and ancillary services (chiropractor, massage, etc) are available to the public. Our mental health services are only available to students registered with Durham College or UOIT.  There is a dental clinic with dentists in the College but not affiliated with the Health Centre.  They do see the public. www.durhamcollege.ca/services/campus-services/dental-clinic	healthcare@durhamcollege.ca	\N	905.721.3037	L1G	\N	\N	\N	\N	https://www.durhamcollege.ca/services/campus-services/health-and-medical
303	rho	durham-hospice	Durham Hospice	1650 Dundas Street East\nWhitby, L1N 2K8	\N	We are dedicated to providing palliative care and bereavement services to individuals and their families in Durham Region. Our palliative and bereavement services are available free of charge whether you have OHIP coverage or not and are available to anyone without discrimination because of race, ancestry, place or origin, colour, ethnic origin, citizenship, creed, sex, sexual orientation, gender identity/presentation, age, marital status, family status, diagnosis or disability.Our services are available to individuals living at home, in the hospital, long-term care centers, retirement facilities and shelters.	rblum@durhamhospice.com	\N	905-240-4522	L1N	\N	\N	\N	\N	https://www.durhamhospice.com
304	rho	durham-pflag-canada	Durham PFLAG Canada	509 Cubert Street\nOshawa, L1J 4B4	\N	PFLAG used to stand for Parents and Friends of Lesbians and Gays. Today PFLAG Canada is a brand name inclusive to all sexual orientations and gender identities/expressions. PFLAG Durham Region is a not for profit organization that is a Chapter of the national charity organization PFLAG Canada. We operate independently, yet are in the family and are much like an Affiliate or a Franchise. We follow the principles, guidelines and guidance of the National Organization and are recognized for these standards.\nPFLAG Durham Region provides support, education and resources on issues of sexual orientation and gender identity/expressions for gay, lesbian, bisexual, transgender, transsexual, two-spirit, intersex, queer, and questioning persons and their families and friends.\nOur peer-to-peer support teams are available by phone or email to talk with you about anything you want to discuss about your own sexuality/gender expressions or the gender/sexuality of members of your family or friends.	support@pflagdurhamregion.com	\N	905.231.0954	L1J	\N	\N	\N	\N	https://pflagdurhamregion.com/
305	rho	dvoras-full-spectrum-doula-services	Dvora’s Full Spectrum Doula Services	949 Cavan Street\nOttawa, K1Z 5T1	\N	Birth and postpartum doula services for LBGTQIA community as well as other marginalized women and women of color.	dvora@dvora.ca	\N	6132821060	K1Z	\N	\N	Dvora Rotenberg\nBirth Doula	\N	https://www.dvora.ca
306	rho	dwight-e-a-thompson-rsw	Dwight E.A. Thompson, RSW	5989 Third Line Road North\nOttawa, K0A 2T0	\N	LGBTQ Couples and Individual Counselling\nBody Image Related Issues, Concerns and Challenges (not specifically focused on eating disorders)	613gfc@gmail.com	\N	613-620-1265	K0A	\N	\N	\N	\N	\N
307	rho	e-ruth-cummins-counsellor	E. Ruth Cummins Counsellor	Thunder Bay	\N	30 years of helping practice. Since 1995, I have been in full-time private practice. As a therapist, I provide counselling for individuals and families specializing in work with trauma issues, critical incident stress, addictions and motor vehicle accidents. I also provide individual, couple and family therapy for general issues and issues specific to sexual orientation. I travel to Northern communities and First Nations when requested to provide clinical or consultation services. My clinical services are covered by most third party payers including auto insurance, non-insured health benefits and group health plans. I welcome all questions and inquiries about my counselling and consulting practice.	ruthcummins@tbaytel.net	\N	807-344-1717	\N	\N	\N	E. Ruth Cummins\nMSW, RSW	\N	https://www.findasocialworker.ca
308	rho	earthsea-acupuncture	Earthsea Acupuncture	715 Bloor St West\nToronto, M6G1L5	\N		earthseaacupuncture@gmail.com	Tuesdays 11a.m. - 8 p.m. Wednesdays 10 a.m. - 5 p.m.	647-687-6622	M6G	\N	$95 initial, $85 follow-up, Sliding scale with inquiry & provided there are available SS spots open	Adrienne Mak\nR. Ac	\N	https://www.earthseaacupuncture.ca/
309	rho	ease-osteopathy-and-health	Ease Osteopathy and Health	327 Ottawa St. N\nHamilton, L8H3Z8	\N	I provide a non-invasive, full body assessment and treatment that seeks to identify and remove mechanical dysfunction through manual therapy allowing the body to self heal and self regulate.	nboweosteopathy@gmail.com	M-F 8:00am-5:00pm	905-928-2768	L8H	\N	Sliding scale range - $/Hour Minimum: 30 Maximum: 50	Osteopathic Manual Therapy\nM.OMSc	\N	https://www.easehealth.ca
310	rho	east-end-community-health-centre	East End Community Health Centre	1619 Queen Street East\nToronto, M4L 1G4	\N	East End CHC provides primary care services and health promotion programs to south-east Toronto. To see our catchment area, please visit our website at: www.eastendchc.on.ca\nA unique aspect of our mandate is to reach out to people in our community who may have difficulty accessing healthcare due to factors such as language, culture, discrimination, poverty or the lack of health insurance.\nOur doctors and nurse-practitioners focus on the whole person in our approach and recognize that factors such as income, education, relationships and housing may play a role in overall health.	\N	\N	416-778-5858	M4L	\N	\N	\N	\N	https://www.eastendchc.on.ca
311	rho	east-mississauga-community-health-centre	East Mississauga Community Health Centre	2555 Dixie Road\nMississauga, L4Y 4C4	\N	Our clinical, or primary health care services, are available to people living within our catchment areas who currently do not have a family doctor. We provide access to family medicine for our clients.\nWe provide services to everyone and we make increased efforts to make our services available to isolated seniors, racialized individuals and communities, people living in poverty, immigrants and refugees, and LGBT individuals and communities.\nAs a client, you have access to the following health care providers:\nEast Mississauga CHC also has many community programs including:\nQX – QX is a drop-in social and support group for queer and trans adults over the age of 18 who live in Peel Region. The group provides opportunities for peer support, social networking, discussion and social events\nPFLAG Peel Region	qxposure.emchc@gmail.com	\N	905-602-4082	L4Y	\N	\N	\N	\N	https://www.eastmississaugachc.org
312	rho	east-toronto-therapy	East Toronto Therapy	658 Danforth Ave\nUnit 406\nToronto, M4J 5B9	\N	I am a registered social worker focusing on helping people address relationships concerns, sex and sexuality, infertility and family building, as well as anxiety and depression. I offer relationship and sex therapy to individuals and romantic partners. I welcome members of the 2SLGBTQ+ community, all relationship structures, including non-monogamy and polyamory, and am committed to fostering an anti-oppressive, sex/kink-positive, trauma-informed practice.	elisa@easttorontotherapy.com	Wednesday 11:00 am - 8:00 pm Thursday 11:00 am - 8:00 pm Saturday 11:00 am - 5:00 pm	(437) 999-2770	M4J	\N	$130-$225	Elisa Gores\nMSW, RSW	\N	https://easttorontotherapy.com/
313	rho	eastern-ottawa-psychological-centre	Eastern Ottawa Psychological Centre	1455 Youville Drive\nOttawa, K1C 2X8	\N	Individual, group, and couple services.	joseefitzpatrick@gmail.com	\N	613-424-5700	K1C	\N	\N	JosÃ©e Fitzpatrick\nPh.D., C.Psych	\N	https://www.cpeottawa.ca
314	rho	ebt3-evidence-based-therapy-training-testing	EBT3 – Evidence-Based Therapy, Training & Testing	2 Carlton St.\nSuite 1803\nToronto, M5B 1J3	\N	The overall mission of EBT3 is to provide high-quality psychological services that have been found to work based on scientific research (i.e., evidence-based). There are three types of evidence-based services that we offer, including therapy, training clinicians in psychological assessment and treatment, and psychological testing and comprehensive assessment. We strive to provide these services with a client-centered focus that takes into account issues of individual diversity.\nConnection, trust, and comfort are key ingredients in a good relationship with a therapist. Evidence-based therapy is no different; therapists strive to see your unique perspective and understand exactly where you are coming from. What is often overlooked, however, are the specific kinds of treatment a clinic or particular therapist has to offer.\nWhen people think of therapy, they may imagine the popular notion of digging deep into their past, or analyzing their relationships with their parents. While these methods can be helpful, they are not always relevant and often require a long term commitment that lasts months or even years. Since time, money, and concrete results are often priorities, evidence-based therapies can be the most efficient and effective options.\nWhat does it mean to say that therapies are “evidence-based” or “scientifically tested?” It means that large groups of people have received these therapies from trained therapists who work closely with researchers. These researchers analyze how well the therapy works during the course of treatment and in the weeks, months and sometimes years following the end of therapy. By analyzing the results of these studies, researchers and therapists are able to figure out what worked in a particular therapy and what didn’t. Suggestions for improving the therapy are made and are then implemented in new studies where the results are again tested. This is the essence of evidence-based therapy; the “evidence” is simply the scientific evidence that these therapies can work. While there is never a guarantee that a particular therapy will be effective for a particular person, using evidence-based approaches greatly increases the chances of success.\nNot all mental health services are evidence-based and, thus, are not equally effective. For this reason, it is in your best interest to be educated when searching for a therapist. Psychologists at EBT3 use techniques that are based on recent research evidence. Since therapies are constantly evolving and changing as more research is done, we make sure to continually update our skills and knowledge. This allows us to select the techniques that are most likely to help our clients address their specific problems. Therapists using evidence-based approaches also carefully assess their clients’ progress over the course of therapy to make sure that the treatment plan is leading to desired outcomes. These assessments are also evidence-based, meaning that research has shown that the assessment tools reliably measure what they are intended to measure.\nEvidence-based therapy is generally short-term and problem-focused, with positive changes often experienced within 8 – 20 sessions. At EBT3, clinicians have training and expertise in several evidence-based therapies.	intake@ebt3.com	9:00 am - 7:00 pm	416.628.4336	M5B	The Coach House, 7 Admiral Rd, Toronto, ON M5R 2L4(416) 716-4003Directions	Sliding scale range - $/Hour Minimum: 175 Maximum: 300	\N	\N	https://www.ebt3.com
315	rho	ecce-psychotherapy	Ecce Psychotherapy	PO Box 2924\nElora, N0B 1S0	\N	I provide inclusive psychotherapy and mental health counselling. I provide both individual and relational services, and my specialization is with trans and gender-expansive populations. I also specialize in the areas of spirituality, sex therapy, and self-harm.	rachel@eccepsychotherapy.com	Monday, 10am-6pm Tuesday, 10am-6pm Wednesday, 10am-6pm Thursday, 10am-6pm	(226) 784-5487	N0B	\N	Sliding scale range - $/Hour Maximum: 150	Psychotherapy\nMSc, Registered Psychotherapist (Qualifying)	\N	https://www.eccepsychotherapy.com
381	rho	giselle-gos-therapy	Giselle Gos Therapy	\N	\N	As a Therapist-in-Training at the Toronto Institute for Relational Psychotherapy, I see clients under faculty supervision for reduced rates.\nMy practice is located at the Village Healing Centre at 240 Roncesvalles, a short streetcar ride or 15 min walk from Dundas West.\nAffordable rates. Sliding scale available. Saturday appointments.	\N	\N	\N	\N	\N	\N	\N	\N	\N
316	rho	ed-santana-psychotherpist	Ed Santana Psychotherpist	195 College Street\nToronto, M5T 1P9	\N	In private practice, I work with individuals and couples facing life’s challenges. I am also Executive Director of the Ontario Association for Marriage and Family Therapy, and previously I supervised several LGBTQ programs at Central Toronto Youth Services. I am a Clinical Member of the Ontario Society of Psychotherapists and the Canadian Association for Psychodynamic Therapy.\nI bring a unique and blended background to my work as a therapist–driven from my personal passion to support the growth and development of others. Primarily, I am a psychotherapist for individuals and couples. In addition, for many years I have been providing organizational and executive development support. For more information, please visit my website at www.edsantana.com. Thank you for your interest and I hope you will be in touch.	edsantana@mac.com	\N	(416) 900-0345	M5T	\N	\N	Ed Santana\nMA, Psychotherapist	\N	https://www.edsantana.com
317	rho	egale-canada-human-rights-trust	Egale Canada Human Rights Trust	185 Carlton Street\nToronto, M5A 2K7	\N	Egale Canada Human Rights Trust (Egale) is Canada’s only national charity promoting lesbian, gay, bisexual, and trans (LGBT) human rights through research, education and community engagement.\nEgale has many helpful online resources including: tips for travelling as a trans or gender variant person, making a LGBTI refugee claim in Canada, LGBTI Youth suicide prevention toolkit.\nMyGSA.ca is a website dedicated to Gay-Straight Alliances and creating safe spaces in schools. Egale also does out reach to various school boards throughout Canada to train teachers on making schools safer places.	\N	\N	416-964-7887	M5A	\N	\N	\N	\N	https://egale.ca
318	rho	egale-youth-outreach	Egale Youth Outreach	290 Shuter Street\nToronto, M5A 1W7	\N	We operate on a scheduled appointments and drop in basis. Counsellors are available for ongoing support as well as same day counselling during our drop-in hours for crisis support. There is currently no waitlist for service.\nWe have LGBTIQ2S Support Workers to help with practical needs ranging from housing, food access, access health care, navigating government services, filling out forms, applying for odsp/ow, employment, transition support, etc.\nWe are located at 290 Shuter St, Level 1 in Toronto, Ontario. Hours of Operation are Monday-Thursday 10am-2pm for Booked Appointments and Drop-in: 2pm-8pm Friday 10am-2pm for Booked Appointments and Drop-in 2pm-6pm. We are Closed: Tuesdays 12-2pm.\nIf you have an questions please feel free to respond on this email or at outreach@egale.ca	outreach@egale.ca	\N	1 (416) 964 7887 ext 9	M5A	\N	\N	\N	\N	https://egale.ca/outreach
319	rho	elena-abel-social-worker	Elena Abel Social Worker	424 Catherine Street\nOttawa, K1R 5T8	\N	Minwaashin Lodge’s Two Spirit Program is designed to support the journey of our Two Spirit community, as well as share education and awareness on Two Spirit identity and history.\nThe term “Two Spirit” is a cultural term used to describe Aboriginal people who may also identify as Gay, Lesbian, Bisexual, Transgender, Queer or Questioning. The term “Two Spirit” acknowledges the gender inclusiveness of our traditional Aboriginal cultures and some also describe it as a balance of male and female spirit. Prior to colonization, most Aboriginal nations understood gender beyond male or female, and those who were “Two Spirited” held special roles within their community, such as mediators, teachers and visionaries. Today, the Two Spirit movement is working towards reclaiming our cultural teachings and restoring a place of honour for all Two Spirited people.\nThe Two Spirit program schedule includes both afternoon and evening activities each week. Recent programming has included:\nMinwaashin continues to provide a safe and welcoming space for the Two Spirit community through a wide range of cultural and recreational programming. New referrals are always welcome.	eabel@minlodge.com	\N	613-741-5590	K1R	\N	\N	Elena Abel\n.	\N	https://www.minlodge.com/programs/twoSpirit/
320	rho	elevate-nwo	Elevate NWO	574 Memorial Avenue\nThunder Bay, P7B 3Z2	\N	Leading HIV/AIDS support organization in the region, providing advocacy, support services for those living with HIV/AIDS, education as well as clinical care. Hep C education and outreach program also available. Harm reduction philosophy including needle exchange site. We are a member of Imagine Canada Ethical donating. We are a welcoming organization.\nPlease note – We are open at 9:30 am everyday and we close at 4:30 pm on Mondays, Tuesdays, Thursdays and Fridays.	info@elevatenwo.org	\N	807 345 - 1516	P7B	\N	\N	\N	\N	https://www.elevatenwo.org
321	rho	elke-sengmueller-registered-dietitian	Elke Sengmueller, Registered Dietitian	745 Danforth\nSuite 311\nToronto, M4J 1L4	\N	Experienced and compassionate LGBTQ2S+ trauma-informed, weight neutral, nutritional counselling for disordered eating/eating disorders, problematic relationships with food, mental health concerns, digestive concerns. Weight loss counselling/diets are not provided. No referral required. All counselling is temporarily being conducted virtually per provincial health order and the College of Dietitians of Ontario.	elke@danforthpsychology.ca	Wednesdays 9 AM- 5 PM Saturdays 9 AM-5 PM	905-713-5209	M4J	\N	\N	\N	\N	https://www.danforthpsychology.ca/
322	rho	emily-bennett-nd	Emily Bennett, ND	204 Spadina Avenue\nToronto, M5T 2C2	\N	Emily is a Toronto naturopath and birth doula, with the goal of teaching and empowering her patients so they can comfortably restore their health naturally. She aims to create a space that is free from judgment, where your concerns are taken seriously and you are treated like the unique and spectacular individual you are. Anyone is welcome to contact Emily about working together and she has particular interest in working with trans* folks interested, preparing, or currently on hormonal therapy.	emilybennettnd@gmail.com	\N	416 705 6364	M5T	\N	\N	Emily Bennett\nNaturopathic Doctor & Birth Doula	\N	https://www.emilybennettnd.ca/
323	rho	emily-brennan	Emily Brennan	140 Oxford Street East\nLondon, N6A 5R9	\N	Endocrinologist	\N	\N	\N	N6A	\N	\N	Emily Brennan\nMD, FRCPC	\N	\N
324	rho	emily-murphy-centre	Emily Murphy Centre	67 Barron Street\nStratford, N4Z 1G9	\N	Emily Murphy Centre is Second Stage Housing for abused women with or without children.	info@emilymurphycentre.com	\N	1-888-826-8117	N4Z	\N	\N	\N	\N	https://www.emilymurphycentre.com
325	rho	emily-schurter-msw-rsw-counselling	Emily Schurter MSW RSW Counselling	276 Frederick Street\nKitchener, N2H 2N4	\N	LGBT2S+ Friendly services, providing supportive counselling. Experience with individuals questioning gender identity.	emilyschurter@gmail.com	\N	226-260-4980	N2H	\N	\N	Emily Schurter\nMSW RSW	\N	https://www.eschurtercounselling.ca
326	rho	emma-sutton-counselling-rga-psychological-counselling-services	Emma Sutton Counselling (RGA Psychological & Counselling Services)	153 Huron Street\nStratford, N5A 5S9	I can provide secondary assessments for transition-related bottom surgeries	Emma is a Registered Social Worker (MSW) working out of RGA Psychological & Counselling Services. She is a queer-identified therapist and provides affirming and wholistic mental health care.	emmasutton.rga@gmail.com	Wednesdays and Thursdays (in office and virtual sessions), 10 a.m. to 7 p.m.	(519) 273-2522	N5A	\N	120\nSliding scale range - $/Hour Minimum: 50 Maximum: 120	Emma Sutton\nMSW, RSW	\N	https://www.rgapsych.com/emma-sutton
328	rho	emma-woolley-individual-therapy	Emma Woolley: Individual Therapy	Toronto, M6R 1Z7	\N	I’m a Registered Social Worker (RSW/MSW) whose practice focuses on resilience, flexibility and strengths. I support adults 18+ in reconnecting with their values, re-telling their stories and moving through life’s difficulties. I bring authenticity, humour and an anti-oppressive stance to therapy, grounded in a LGBTQ2S sex-positive approach. I’m experienced in working with anxiety, depression, ADHD, self-identified harmful behaviours, life transitions, grief, existential crises, perfectionism, inner criticism, trauma, stress management and relationship challenges.\nMy approach is integrative, collaborative, trauma-informed, compassionate and experiential. I draw from Narrative Therapy, Mindfulness, Acceptance and Commitment Therapy (ACT), and Dialectical Behavioural Therapy (DBT) in unique ways to support each individual’s goals. To learn more about me and my practice, please visit my website (www.emmamwoolley.com).	emwtherapy@gmail.com	Variable	647-872-8912	M6R	\N	\N	Emma Woolley\nRSW/MSW	\N	https://www.emmamwoolley.com
329	rho	endocrinologist	Endocrinologist	140 Oxford Street East\nLondon, N6A 5R9	\N	Endocrinologist – providing hormone care	\N	\N	519-850-3234	N6A	\N	\N	Julia Creider\nMD, FRCPC, Cert Endo	\N	\N
330	rho	enrique-garcia-counselling-and-psychotherapy	Enrique Garcia Counselling and Psychotherapy	12 Birch Avenue\nSuite 205\nToronto, M4V 1C8	\N	Providing face to face and confidential psychotherapeutic counselling to members of the LGBT+ community.\nI use an integrative humanistic approach (including person-centred, Gestalt, existential, transactional analysis and relational therapy).\nI specialize in alternative relationships, sexuality, family, relationships, identity, career, etc.\nSessions are 50 minutes.	contact@enriquegarciacounselling.com	\N	4373457486	M4V	\N	\N	Enrique Garcia\nMember CAPT and BACP, PgD, MA	\N	https://www.enriquegarciacounselling.com
331	rho	equal-care-massage-therapy	Equal Care Massage Therapy	Midland, L4R 3P2	\N		info@equalcaremassagetherapy.ca	By appointment only.	(705) 245-0778	L4R	\N	\N	Panthea Self-Davoodian\nRMT	\N	https://www.equalcaremassagetherapy.ca/
332	rho	eren-deran-rsw-msw	Eren Deran, RSW, MSW	951 Wilson Avenue Unit 15\nNorth York, M3K 2A7	\N	Hello, I am Eren; my pronouns are he/him. I am a queer and registered social worker & mental health counsellor in Ontario. I provide in-person and online counselling for adults and young adults. As a racialized and queer service provider, I use trauma-informed, client-centred, anti-oppressive, and anti-racist lenses.\nAs a queer social worker, I volunteered at several organizations such as The 519 and supported 2SLGBTQ+ newcomers. I worked at Across Boundaries – An Ethnoracial Mental Health Centre as a Registered Social Worker and a Team Lead for almost two years and had an essential part in developing the 2SLGBTQ+ program. I supported queer young adults in group and individual counselling sessions at Stella’s Place.\nIn my work at a private practice as a cis gay social worker, I advocate and support queer folks; I provide safe space to 2SLGBTQ & QTBIPOC service users.\n	erenderan@gmail.com	I work Monday to Friday from 9 a.m. to 7 p.m. I provide in-person counselling every Thursday from 9 a.m. to 7 p.m.	647 568 2161	M3K	true	\N	Eren Deran	\N	https://www.erenderan.com
333	rho	erin-johnson-msw-rsw	Erin Johnson MSW RSW	88 Ontario St\nCollingwood, L9Y1M3	\N	Provides identity affirming psychotherapy/counselling services to 2SLGBTQIA individuals 16+. Sliding scale available.	erin@turningpt.ca	Evenings and Saturdays	705-443-8535	L9Y	\N	125\nSliding scale range - $/Hour Maximum: 125	Erin Johnson\nMSW RSW	\N	https://www.psychologytoday.com/ca/therapists/erin-johnson-collingwood-on/851293
334	rho	erin-poole-therapist	Erin Poole, Therapist	200 Main Street East\nHamilton, L8N 1H3	\N	I am a Registered Psychotherapist in private practice and take a relational, client-centered approach that creates space for both meaning-making and a diverse range of identities. I have over 12 years of experience in a multi-faith health care context, working with people journeying through a variety of life circumstances. I have also worked with LGBTQ+ and gender variant people in group settings and individually. Please search ‘Erin Poole’ at https://therapists.psychologytoday.com/rms for more details.	erinpoolecounselling@gmail.com	\N	\N	L8N	\N	\N	Erin Poole\nRP, M.Div.	\N	https://therapists.psychologytoday.com/rms
335	rho	erin-united-church-and-ballinafad-united-church	Erin United Church and Ballinafad United Church	115 Main Street\nErin, N0B 1T0	\N	We welcome LGBTQ2 people to our worship services and our church activities, and our Minister would love to start a PFLAG support group in our communities of Erin and/or Ballinafad, Ontario.	urbanski_felicia@yahoo.com	\N	519-833-9727 (Erin) and 905-877-4743 (Ballinafad)	N0B	Directions	\N	Felicia Urbanski\nOrdained United Church of Canada Minister; completed 4 units of advanced Clinical Pastoral Education.  Our denomination ordains LGBTQ2 people and has an Affirming Congregation program.	\N	https://www.erinunitedchurch.org
336	rho	etobicoke-childrens-centre	Etobicoke Children’s Centre	65 Hartsdale Drive\nToronto, M9R 2S8	\N	The Etobicoke Children’s Centre  (The ECC) is an accredited child and youth mental health centre located in West Toronto. The ECC and its Staff, Management, Board of Directors  and Consultants are committed to addressing the needs of children and youth with mental health needs or autism and their families. The ECC has been serving children and their families in this community for over thirty years.\nThe ECC provide mental health  and autism services to children and youth and their families. Eligiblity criteria, including age, depends on the program. Based on an assessment of need, our trained and skilled staff will make recommendations for service.\nFrom counselling to autism intervention, we offer a number of different services to help you:	ecc@etobicokechildren.com	\N	(416) 240-1111â€¨	M9R	\N	\N	\N	\N	https://www.etobicokechildren.com
337	rho	etobicoke-counselling	Etobicoke Counselling	4195 Dundas Street West\nToronto, M8X 1Y4	\N	As an Individual & Relationship Therapist, I connect with each person in an accepting way that draws on their strengths and supports their values and personal integrity. I provide both short and long term counselling and integrate a variety of therapy approaches to meet each person’s particular needs.\nHaving completed extensive training in Couple and Family Therapy, I can help with parenting dilemmas, especially around parental differences in raising gender independent children.\nI welcome any conversation about the influence of gender, sexual identity and sexual orientation on child’s well-being.	jana@etobicokecounselling.ca	\N	647.209.9215	M8X	\N	\N	Jana Brankov\nMSc, RP, RMFT	\N	https://etobicokecounselling.ca
350	rho	family-services-york-region	Family Services York Region	\N	\N	York Rainbow Support: provides Individual, Couple and Family Counselling Services for Lesbian, Gay, Bisexual, Transgender, Two Spirit, Queer & Questioning.\nFSYR is proud host and lead agency for the York Rainbow Network and York Rainbow Information, Referral and Support Line 1-888-York-LGBT (1-888-967-5542). The York Rainbow Network was established through a Trillium Grant to reduce barriers and build capacity to serve the LGBTTQ Community.\nFSYR identifies as a safe space and requires all staff to attend LGBTTQ sensitivity and awareness training. In addition FSYR has professional counsellors who are members of the LGBTTQ community.\nFSYR is also offering the following LGBTTQ Groups: FREE to BE and a Transgender Support/Drop in Group	\N	\N	\N	\N	\N	\N	\N	\N	\N
338	rho	everworth-counselling-services	Everworth Counselling Services	Guelph, N1L 1S8	\N	I specialize in working 1-1 with adults who are wanting to heal from trauma, explore difficult relationships, shed light on the patterns that are no longer serving them, and cope with anxiety.\nI believe we’re all doing the best we can with what we know in the moment. When we face trauma or hardship, the brain does a brilliant job of adapting to keep us safe, and it adopts whatever beliefs and behaviours are necessary to get us through. If you’re reading this, it’s likely that you’ve notice some of your own beliefs and behaviours holding you back from the life you really want to live. You are far from alone in this. Often, the beliefs and behaviours that keep us safe and functioning at one point in our lives stop being helpful, and may even start wreaking havoc on our ability to be the person we really want to be.\nI’m passionate about walking alongside you in your search for meaning and change. I look forward to hearing your story, and compassionately supporting you to understand the patterns that have you feeling stuck. Together, we can uncover how your experiences have shaped how you show up in the world today, process the things that have happened to you, explore your current emotions and relationships, and navigate towards a life that feels fulfilling.\nI aim to provide a warm, safe, and comfortable environment for connection, self-exploration, and sharing of your authentic self. I strive to meet you where you’re at, fostering a therapeutic relationship of collaboration and acceptance. I adopt anti-oppressive, trauma-informed, strengths-based, and client-centred approaches in my work.	info@everworthcounselling.ca	9am-4pm daily	5484904617	N1L	\N	$150 per 50 minute session	Megan Gauthier\nMSW, RSW	\N	https://www.everworthcounselling.ca
339	rho	evolution-psychotherapy	Evolution Psychotherapy	Toronto, M2K3C2	\N	Providing online and over the phone counselling and psychotherapeutic support to individuals, couples and families.	info@evolutionpsychotherapy.ca	Monday to Friday 9am to 8pm	6475075200	M2K	\N	Sliding scale range - $/Hour Minimum: 50 Maximum: 145	\N	\N	https://www.evolutionpsychotherapy.ca/
340	rho	evolve-womens-health	Evolve Women’s health	707 Charlotte Street\nPeterborough Ontario, K9J2X5	\N	We are a group of obstetrician/gynecologists with a diverse set of special interests and skills. We strongly believe that healthcare should be personalized and we provide evidence- based, compassionate and informed care for women, children, adolescents, seniors, people with vulvas and trans people for a variety of different concerns.	evolvewomenshealth@themedicalcentre.net	0900-1730	7058764530	K9J	\N	\N	\N	\N	https://www.evolvewomenshealthcare.com/
341	rho	exhale-wellness-registered-massage-therapy	Exhale Wellness Registered Massage Therapy	112 McClintock Way\nOttawa, K2L 2A4	\N	Conveniently located in Katimavik, Kanata, Exhale Wellness offers professional Registered Massage & Myofascial release therapy in a comfortable and relaxed atmosphere.	Lisa@exhalewellness.ca	\N	613-614-0059	K2L	\N	\N	Lisa Corbin\nRegistered Massage Therapist	\N	https://exhalewellness.ca
342	rho	express-aid-pharmacy	Express Aid Pharmacy	477 Grove Street East\nBarrie, L4M 6M3	\N	We are Barrie’s LGBTQ+ friendly pharmacies. All of our pharmacy team has been trained in supporting the community and the pharmacies are a designated Safer Space. We provide specialization in LGBTQ+ health and medications.	andrew@expressaidpharmacy.ca	\N	705-720-2262	L4M	\N	\N	Andrew Schonbe\nBSc Phm	\N	https://www.expressaidpharmacy.ca
343	rho	expressions-counselling	Expressions Counselling	1528 Stittsville Main Street\nOttawa, K2S 1B8	\N	Individual counselling and art therapy for all ages.	Sandra@expressionscounselling.ca	\N	6132972602	K2S	\N	\N	Sandra  Grew\nMA, RP, art therapist, CCC	\N	https://www.expressionscounselling.ca
344	rho	ezra-cake-psychotherapy	Ezra Cake Psychotherapy	489 College Street\nToronto, M6G 1A5	\N		ez@ezracake.com	Monday 11:00 am - 5:00 PM Tuesday 11:00 am - 5:00 PM Wednesday 11:00 am - 5:00 PM Thursday 11:00 am - 5:00 PM	647-992-2253	M6G	\N	\N	Ezra Cake\nRegistered Psychotherapist, BA (Hons)	\N	https://www.ezracake.com
345	rho	family-matters-counselling	Family Matters Counselling	209 Limeridge Road East\nHamilton, L9A 2S3	\N	Family Matters provides private, comfortable, confidential and respectful counselling to youth and their families struggling with sexual orientation and gender identity. We have flexible hours both day and evening appointments.	lesley@familymatterscounselling.ca	\N	289-921-8002	L9A	\N	\N	Lesley Greig\nCTW (Cert) OACYC	\N	https://www.familymatterscounselling.ca
346	rho	family-service-thames-valley	Family Service Thames Valley	125 Woodward Avenue\nLondon, N6H 2H1	\N	Family Service Thames Valley provides a wide-range of counselling and support services for individuals, families, and organizations. We proudly provide LGBT2Q+ affirming therapy and support groups. We also provide, Coming Out Over Coffee, a casual open discussion group for individuals over the age of 19 who identify as lesbian, gay, bisexual, trans*, two-spirit, queer, or who are questioning; for those starting their journey to those who are out & about. Come join us for a discussion & support with other LGBT2Q+ folks every 2nd & 4th Tuesdays of the month from 6:30pm – 8:00pm at Family Service Thames Valley, 125 Woodward Ave. No registration necessary.	fstv@familyservicethamesvalley.com	\N	519.433.0183	N6H	\N	\N	\N	\N	https://www.familyservicethamesvalley.com
347	rho	family-service-toronto	Family Service Toronto	Toronto	\N	Family Service Toronto (FST) helps people face a wide variety of life challenges. For over 100 years, we have been assisting families and individuals through counselling, community development, advocacy and public education programs. Our services are available to everyone who lives or works in Toronto.\nDavid Kelley Services is a program area of FST that provides individual, couple, family counselling and group services to individuals who identify as lesbian, gay, bisexual, trans or queer and to persons living with or affected by HIV/AIDS.\nPlease call for more information.	dks@familyservicetoronto.org	\N	(416) 595-9618	\N	\N	\N	\N	\N	https://www.familyservicetoronto.org/programs/dkslesgay.html
348	rho	family-services-ottawa-2-2	Family Services Ottawa	\N	\N	We offer counselling and support services to anybody in Ottawa who needs it. No matter what it is that you’re dealing with, we’re here to listen. We offer a safe space, and will help you work through whatever is troubling you.\nOur programs are run by counsellors who are highly skilled and trained in each of our service areas. Family services staff and clients who have already benefited from our services are also involved in making our programs as helpful and successful as they are. We’re here. We’re available and we’re open.\nLGBTTQ+ Around the Rainbow is a community-based program  which provides a full range of education, counselling and support services offered by Family Services Ottawa.  We support the  lesbian, gay, bisexual, trans, two spirit, queer and questioning (LGBTTQ+) communities and allies.	fsfo@familyservicesottawa.org	\N	613-725-3601	\N	\N	\N	\N	\N	https://familyservicesottawa.org/
349	rho	family-services-windsor-essex	Family Services Windsor-Essex	235 Eugenie Street West\nWindsor, N8X 2X7	\N	Strengthening and supporting families in the Windsor Essex Area	info@fswe.ca	\N	519-966-5010	N8X	\N	\N	\N	\N	\N
352	rho	farzana-doctor-social-worker	Farzana Doctor Social Worker	47 Wyndham Street\nToronto, M6K 1R9	\N	Since 1993, I’ve worked with youth, adults, couples and families around issues of addiction, gender identity, sexual orientation, oppression, mood, relationships and trauma. I also provide online counselling (see www.farzanadoctorcybercounselling.wordpress.com for more information)	farzanadoctor@rogers.com	\N	647-899-8974	M6K	\N	\N	Farzana Doctor\nMSW, RSW (Registered Social Worker)	\N	https://www.farzanadoctor.com
353	rho	fife-house	Fife House	490 Sherbourne Street\nToronto, M4X 1K9	\N	Fife House is an innovative, client-focused provider of secure and supportive affordable housing and services to people living with HIV/AIDS in the Greater Toronto Area.\nFife House is recognized as a North American leader in its delivery of services, which are focused on enhancing quality of life, building on individual strengths and promoting independence – recognizing that access to secure and affordable housing is a key determinant for the health and well-being of people living with HIV/AIDS.\nIn 2014/2015 Fife House served 600 residents & clients. We provided support services to more than 200 residents/clients through our Supportive & Transitional Housing Programs and to an additional 360 clients, including families, through our Homeless Outreach Program.	\N	\N	416-205-9888	M4X	\N	\N	\N	\N	https://www.fifehouse.org/
354	rho	follicles-and-dermis	follicles and dermis	450 Campbell St.\nUnit 8A\nCobourg, K9A 4C4	\N	Offering permanent & temporary hair removal services in an inviting & inclusive space.	beth@follicles.ca	Tuesday to Thursday: 12-9 p.m. Friday to Saturday: 10 a.m. - 2 p.m.	905.373.6728	K9A	\N	\N	Elizabeth Boileau\nCertified Electrologist	\N	https://www.follicles.ca/
355	rho	follikill-electrolysis-toronto	Follikill Electrolysis Toronto	\N	\N	Follikill provides truly permanent hair removal using electrolysis. Treatments are provided using a surgical microscope to ensure precision. I guarantee my work.	\N	\N	\N	\N	\N	\N	\N	\N	\N
356	rho	form-function-health-performance-wellness-centre	Form & Function: Health, Performance, Wellness Centre	8500 Warden Avenue\nMarkham, L6G 1A5	\N	We are professional health practitioners work on the advancement of health care and developing extensive health internship programs for medical enthusiasts. We provide various clinical services in Markham including Physiotherapy, Chiropractic, Acupuncture, Massage, Naturopathy, Foot Care, tech therapy and Custom bracing. We are dedicated to provide quality, innovative, futuristic programs which includes Weight Loss, Sports Performance, Health & Wellness, Work & Study and Women’s Health programs that inspire multidisciplinary professionals to shape the future of health and well-being. Book an appointment to avail our services today!	info@formfunctionclinic.com	\N	'+1 905-604-9355	L6G	\N	\N	Stephen Halverson\nWellness Centre	\N	https://www.formfunctionclinic.com
357	rho	forouz-salari-counselling-consultation-services	Forouz Salari Counselling & Consultation Services	65 Wellesley Street East, Suite 402\n65 Wellesley Street East, Suite 402\nToronto, M4Y 1G	\N		forouz.salari@outlook.com	Mondays to Thursdays 10:30am to 7:30pm Fridays 10:30am to 6pm Appointments available: Mondays to Thursdays at 11am, 1pm, 4pm and 6pm Fridays at 2pm and 4pm	437-886-6476	\N	\N	$150 - $175	Forouz Salari\nMA, MSW, RSW	\N	https://www.forouzsalaritherapy.ca/
358	rho	forte-massage-therapy	FORTE Massage Therapy	555 Bloor St W\nSuite 5\nToronto, M5S 1Y6	\N	FORTE Massage Therapy excels at providing focused, deep, intentional and intuitive massage therapy treatment in a warm and inviting atmosphere – located at Bloor and Bathurst.	corey@fortemassage.ca	Monday, Thursday, Friday 1pm - 7pm, Sunday 10am - 4pm	6478761232	M5S	\N	$105-$200	Corey Elmore\nRMT	\N	https://www.fortemassage.ca
359	rho	frances-fitzgibbon	Frances Fitzgibbon	267 O'Connor Street\nSuite 600\nOttawa, K2P 1V3	\N	I provide a safe and supportive space in my private practice for all member of the LGBTQ+ spectrum and their families and allies. I work with general mental health, mood disorders, relationship issues, sexuality, identity, emotional regulation, trauma and anxiety. I also have extensive experience working with personality disorders and interpersonal struggles.\nI aim to help foster enduring change and growth with my clients to achieve their goals and support them in the life they want to lead. Working with adults and older youth, I work with both individuals and couples. I work from an integrative approach, which means that I tailor therapy to your specific needs and pull from various frameworks such as: psychodynamic/psychoanalytic, attachment, ACT, DBT, CBT, MI and EFT.\nI pride myself on cultural competence and working from the worldview and value-system of my clients. I am a registered provider of mental health to the Indigenous community under the Non-Insurance program (NIHB). Rates range from $160 and I am located centrally in downtown Ottawa. Video therapy also available upon request.	frances.fitzgibbon@cfir.ca	\N	1.855.779.2347 extension: 742	K2P	\N	\N	Frances Fitzgibbon\nRegistered Psychotherapist	\N	https://cfir.ca/OttawaTeam.php
360	rho	francoqueer	FrancoQueer	465 Yonge Street\nToronto, M4Y 1X4	\N	FrancoQueer est une association bénévole sans but lucratif, qui vise à rassembler et représenter les personnes LGBTQIA* d’expression française, à leur offrir des activités, des services et des programmes adaptés, ainsi que des moyens de célébrer leur diversité dans une ambiance francophone.\nEnsemble, fiers et fières de notre communauté et de notre diversité !\nFrancoQueer is a not-for-profit, volunteer base association of French-speaking LGBTQIA Lesbian, gay, bisexual, bi-spiritual, queer, questioning, intersex and allies in Toronto and Ontario.\nOur mission is to gather, represent our community and provide services, programs and activities, and also celebrate our diversity in French.\nServices and activities are – Information and Referrals, – Support groups for LGBTQ new comers (immigrants and refugees) as well as for gay and bisexual men, – ApÈro Arc-en-ciel, a monthly social gathering for LGBTQI and allies, and we are responsible for Franco fierte (French content during Pride Week in Toronto).	info@francoqueer.ca	\N	416-214-4862	M4Y	\N	\N	\N	\N	https://www.francoqueer.ca
361	rho	friends-advocates-peel	Friends & Advocates Peel	239 Queen Street East\nBrampton, L6V 1B9	\N	Friends & Advocates is a non-profit adult mental health social rehabilitation Organization. Our mission is Member Directed Social Rehabilitation Services. This philosophy encompasses providing a variety of activities, events and services to those who have experienced and are recovering from mental/emotional distress, which has led to social isolation. Friends & Advocates offers numerous social opportunities which encourages the development of leadership, interpersonal and social skills for our membership, who reside primarily in the communities of Brampton, Mississauga, Etobicoke and Dufferin. In addition another one of our programs, the Consumer Survivor Network is dedicated to bringing the voices of Mental Health and Addiction service users to funding bodies and share stories of recovery.	erozas@fapeel.org	\N	905-452-1002	L6V	\N	\N	Andrea Noorani	\N	https://www.fapeel.org
382	rho	gloria-murrant-psychotherapist	Gloria Murrant Psychotherapist	741 Broadview Avenue\nToronto, M4K 3Y3	\N	Provide individual and relationship psychotherapy.	gmurrant@gmail.com	Tuesdays 12 - 8 Wednesdays 8 - 12 Thursdays 12 - 8	(416) 436-0670	M4K	\N	\N	Gloria Murrant\nPsychotherapist	\N	https://www.torontopsychotherapygroup.com/therapists/gloria-murrant-registered-psychotherapist/
362	rho	full-spectrum-doula	Full Spectrum Doula	Toronto	\N	Giselle is a full spectrum doula who supports all outcomes of pregnancy. Their practice is evidence based, non- judgemental, inclusive & works within an anti-oppression framework.\nCurrent services include birth, postpartum, pregnancy and infant loss & abortion support.\nGiselle is also available for private childbirth education classes, group prenatal classes for 2SLGBTQ folks and private yoga.	touchbase@fullspectrumdoula.ca	\N	6476099979	\N	\N	\N	Giselle Johnston	\N	https://www.fullspectrumdoula.ca
363	rho	full-spectrum-doula-2	Full Spectrum Doula	\N	\N	Giselle is a full spectrum doula who supports all outcomes of pregnancy. Their practice is evidence based, non- judgemental, inclusive & works within an anti-oppression framework.\nCurrent services include birth, postpartum, pregnancy and infant loss & abortion support.\nGiselle is also available for private childbirth education classes, group prenatal classes for 2SLGBTQ folks and private yoga.	touchbase@fullspectrumdoula.ca	\N	6476099979	\N	\N	\N	Giselle Johnston	\N	https://www.fullspectrumdoula.ca
364	rho	gabriella-switzer-therapy	Gabriella Switzer Therapy	Toronto, M6C2N3	\N		gabriellaswitzertherapy@gmail.com	Flexible	N/A	M6C	\N	Sliding scale range - $/Hour Minimum: 85 Maximum: 115	Gabby Switzer\nMSW, RSW	\N	https://www.psychologytoday.com/ca/therapists/gabriella-switzer-toronto-on/874907
365	rho	gaela-mintz	Gaela Mintz	20 De Boers Drive\nToronto, M3J 0H1	\N	I am a a Registered Social Worker who provides psychotherapy to children, youth, adults and families. I also provide workshops and trainings to diverse audiences on a number of topics. I work from a cognitive-behavioural framework and work with the strengths of each of my clients.\nCommon issues that are brought to my practice include: life transitions, trauma, supporting and advocating for gender diverse children and youth, behaviour concerns, overwhelming feelings of anxiety, family conflict, grief and loss issues, difficulties regulating emotions, school avoidance, peer/friendship difficulties, parenting concerns, communication challenges, gender identity and expression issues, and coming out issues related to sexual orientation.\nPopular workshops that have been requested are: Building Positive Climates; Creating Gender Affirming Spaces for Children and Youth; Parenting Workshops; Healthy Relationships; Social Media and Relationships; Understanding and Responding to Children/Youth Sexual Behaviours; Talking to Children about Sex and Sexuality; LGBTQ+ Inclusivity; Topic specific workshops, such as Supporting and Coping with ADHD and Anxiety.	gaelamintz@gmail.com	Day and evening appointments available.	416-889-8056	M3J	\N	\N	Gaela Mintz\nMA/MSW, RSW	\N	https://www.gaelamintz.com
366	rho	gail-nielsen-counselling	Gail Nielsen Counselling	Strathroy, N0M	\N	Gail Nielsen is the founder of The Move Mountains Group – an executive and athletic peak performance company. The firm provides a range of in-person and telephonic professional life coaching services to individuals in business and sport who are seeking to perform at their best both professionally and personally. Gail is co-author of The Control Freak’s Guide to Living Lightly Manifesting a Life of Total Trust and is also a Registered Professional Counsellor. She works with individuals, couples and families in her private counselling practice near London, Ontario.	info@extraordinarymoves.com	\N	519-289-1040	\N	\N	\N	\N	\N	https://www.controlfreakseries.com
367	rho	gateway-community-health-centre	Gateway Community Health Centre	\N	\N	Our staff is a highly skilled interprofessional team of physicians, nurse practitioners, nurses, pharmacist, social worker, dietitian, early childhood educator, Community Development/Outreach Worker and others who collaborate to provide services and programs to our clients. Working together, this team responds to the factors that impact the health and well-being of clients including oral care. They ensure that clients receive the best possible care. Gateway CHC is LGBTQ affirming.\nClient focus is on youth at risk and lower resourced individuals and families. Must be a registered client to access primary care, other individuals can access programs.	lgriss@gatewaychc.org	\N	(613) 478-1211	\N	\N	\N	\N	\N	https://www.gatewaychc.org
368	rho	gay-york-region	Gay York Region	10909 Yonge Street\nRichmond Hill, L4E 3M7	\N	GayYorkRegion provides a regional website, as well as a toll-free information/support line and social group, for LGBT residents of York Region, Ontario.\nThe www.gayyorkregion.com website offers local news stories, event details, support advice, a discussion forum and a comprehensive directory of the region’s LGBT-relevant organizations, services, businesses and social venues.\nThe 1-888-YORKLGBT information and support line provides information and toll-free access to key health and support services in York Region.\nGayYorkRegion also operates the GYRSG social group (www.gyrsg.com), which hosts regular social events at venues across the region.	'@gayyorkregion.com	\N	1-888-YORKLGBT	L4E	\N	\N	\N	\N	https://www.gayyorkregion.com
369	rho	gayle-baker-toronto-registered-psychotherapist-and-couples-counsellor	Gayle Baker – Toronto Registered Psychotherapist and Couples Counsellor	400 Dupont Street\nToronto, M5R 1V9	\N	I am a Registered Psychotherapist offering individual psychotherapy and couples counselling.\nLGBTQ friendly therapy focusing on:	gaylebaker@gestalttherapy.ca	\N	416-788-1200	M5R	\N	\N	Gayle Baker\nGestalt Psychotherapist	\N	https://www.gestalttherapy.ca
370	rho	gender-journeys-canadian-mental-health-association-halliburton-kawartha-and-pine-ridge	Gender Journeys – Canadian Mental Health Association – Halliburton, Kawartha and Pine Ridge	466 George Street North\nPeterborough, K9H 3R7	\N	Gender Journeys, offered through the Canadian Mental Health Association, Haliburton, Kawartha, Pine Ridge, provides programming, education, and support services for transgender, 2-spirit, gender expansive, and questioning individuals. Services are also offered for families, partners and loved ones.\nWe offer the following groups and programming:\n• Gender Journeys Core Group\n• Youth Gender Journeys Group\n• Beyond Gender Journeys Group\n• Family Support Group\n• Partner Support Group\n• Peer-to-Peer Support\nAll Gender Journeys groups and programs are respectful of the diversity of gender identities.\nWorkshops and Education for Allies\nTo decrease isolation and increase connection in the community, Gender Journeys offers workshops and education to organizations interested in developing awareness and sensitivity skills. These educational sessions help build capacity to support transgender individuals and families.\nAllies are those who take action in support of the rights of transgender and queer people.\nThese services are offered for workplaces, community organizations, health professionals, schools or any group. For more information about programs and scheduling, please contact us.\n	genderjourneys@cmhahkpr.ca	Monday-Friday	705-748-6711 ext. 2100	K9H	\N	\N	\N	\N	https://cmhahkpr.ca/programs-services/gender-journeys/
371	rho	genesissquared-psychotherapy-counselling	GenesisSquared Psychotherapy & Counselling	47 Queens Park\nToronto, M5S 1K6	\N	Psychotherapy, counselling, and coaching to help members of the community manage change and transitions in their lives personally (gender, relationship, mental health) and professionally.\nWe specialize in Anxiety Management.	Todd@GenesisSquared.com	\N	18006993396	M5S	\N	\N	Todd Kaufman\nB.A., B.F.A., M.Div., RP	\N	https://www.GenesisSquared.com
372	rho	genevieve-leblanc-m-ed-registered-psychotherapist-qualifying	Genevieve LeBlanc, M.ED., Registered Psychotherapist (Qualifying)	265 Carling Avenue\nOttawa, K1S 2E1	\N	Individual psychotherapy services that are trauma informed and client centered. An affirming therapy space for people of various gender and sexual identities including transgender, non-binary, genderqueer, bisexual, pansexual, intersex people and more. Also confident in providing a judgement free space for non-monogamous and polyamorous people. Anti-oppressive and anti-racist.	genevieve.leblanc@centrefortreatment.com	Monday to Thursday	6138620313	K1S	\N	$140	Genevieve LeBlanc\nRegistered Psychotherapist (Qualifying)	\N	https://www.centrefortreatment.com/genevieve
373	rho	geoff-straw-psychotherapy	Geoff Straw Psychotherapy	St. Catharines , L2R 5Z4	\N	Psychotherapy practice providing support to the queer community, particularly  gay and bi men located in St. Catharines. Virtual sessions available.	strawpalace@hotmail.com	Flexible	905-685-8605	L2R	\N	$120	Geoff Straw\nM.A., Registered Psychotherapist	\N	https://www.strawtherapy.com
374	rho	georgette-dunn-permanent-makeup	Georgette Dunn Permanent Makeup	232 Main Street South\nNewmarket, L3X1Z8	\N	Georgette Dunn offers cosmetic tattooing including feminizing procedures of the face ie/brows, lips and eyeliner.  Georgette offers areola tattooing for masculine or feminine appropriate areola aesthetics.	georgette@eyebrowsink.com	Everyday: 9 a.m. - 5 p.m.	9058060743	L3X	\N	various	Georgette Dunn\nUSA board certified	\N	https://georgettepmu.com/
375	rho	georgian-bay-integrative-medicine	Georgian Bay Integrative Medicine	1 Huron Street\nCollingwood, L9Y 1C3	\N	GBIM is a collaborative health clinic offering naturopathic medicine, acupuncture, nutritional counselling, psychotherapy, and aqua (pool exercise) therapy. We also host informational workshops and have LGBTQ knowledgable practitioners.\nWalk-ins welcome!	info@georgianintegrative.com	\N	7054447866	L9Y	\N	\N	Rehan Lakhani\nNaturopathic Doctor	\N	https://www.georgianintegrative.com
376	rho	giiwedno-mshkikiiwgamig-north-bay-indigenous-hub	Giiwedno Mshkikiiwgamig (North Bay Indigenous Hub)	1040 Brookes St.\nNorth Bay, Ontario, P1b 2n6	\N	The North Bay Indigenous Hub (NBIH) will provide a wide range of programming services including traditional healing, primary care, health promotion, chronic disease management, family-focused maternal/child health care, mental wellness care, diabetes care, and a culturally integrated licensed child care facility. All of the programs are to be delivered in a culturally safe manner to the local urban Indigenous population in addition to our partner First Nations, Nipissing, Temagami, and Dokis First Nations.\nOur staff will work in collaboration with you and/or your family member to support the healing path of your choice. We will work hard to ensure that you will be in control of your health and wellness plan. If you choose, your health provider will collaborate with the traditional healing team, so that you also have access to traditional Indigenous medicines and practices.\nAll services will be available to First Nations, Inuit, Métis people, without distinction of status, non-status or residence.\nAll services are 2SLGBTQIA+ friendly	info@gmghub.ca	Monday to Friday- 8:30am-4:30pm Closed daily from 12:00pm-1:00pm	705-995-0060	\N	\N	\N	\N	\N	https://www.giiwednomshkikiiwgamig.ca
377	rho	gillians-place	Gillian’s Place	15 Gibson Place\nSt. Catharines, L2R 0A3	\N	How Gillian’s Place helps: If you are a woman who thinks you might be being abused, Gillian’s Place can help. All of our services are confidential and free of charge. Abused women do not need to stay at our shelter to access any of our services.  Our facility is fully accessible and translation services are available. Gillian’s Place is the only shelter and supportive services agency for abused women and their children in Grimsby, Lincoln, West Lincoln, Niagara-on-the-Lake, St. Catharines and Thorold.\nEmergency Shelter: Emergency safe shelter, meals and clothing are provided. Planning for safety of the family is reviewed with each woman as they enter the program. Our 24/7 support line, 905.684.8331 is there to support women of all ages, as well as friends and family that are seeking advice for their loved ones.\nCounselling: Qualified and experienced staff provide immediate assistance through our 24/7 support line, 24-hour support counselling; one-on-one and group counselling.\nHelp with finding or training for a job: We can refer abused women to employment agencies and education and training programs that will help them achieve their employment goals.\nHelp with applying for financial assistance: As part of their efforts to create financial stability, abused women may need income support. Gillian’s Place will assist abused women through the process of applying for financial assistance.\nTransitional and Housing Support: Gillian’s Place will help abused women find safe, affordable housing. We help them fill out housing applications and provide them with landlord and tenant information. The Transitional Worker will link women to support services in the community such as housing, day care, educational upgrading, employment, income support and health and wellness services.\nLegal Services: Gillian’s Place has a family law lawyer on staff to help abused women in dealing with police, lawyers, Family Court and/or the criminal justice system. From advising on how to leave their partner safely, to helping them fill out and review legal documents including child interim custody and access, support and property. Our staff lawyer can help abused women deal with the legal problems they face and help them to know their rights.\nChild and Youth Support: Children in the household are impacted by the abuse. We can provide supports such as recreational activities, family violence education and activities designed to help explore feelings and build self-esteem. We can also provide abused women with referrals to community agencies that specialize in various aspects of child and youth care.\nImmigrant and refugee support : If an abused woman is new to Canada or Canada is not their first home, we are sensitive to the extra struggles they may face. In addition to all of our other services, we can provide them with referrals to community agencies that specialize in immigrant and refugee support, as well as translation services in any language.	linda@gilliansplace.com	\N	905-684-4000 ext. 221	L2R	\N	\N	\N	\N	https://www.gilliansplace.com/
378	rho	gingers-physiotherapy-place	Ginger’s Physiotherapy Place	612 Colborne Street\nLondon, N6B 2V2	\N	Physiotherapy services including concussion management, WSIB claims, and motor vehicle accidents.	info@gingersphysio.com	\N	519-850-9292	N6B	\N	\N	Emily McKenzie-Picot\nMPT	\N	https://www.gingersphysio.com/
379	rho	gisele-harrison-msw-rsw	Gisele Harrison MSW, RSW	1983 Ambassador Drive\nWindsor, N8Y 2J9	\N	I am a straight cis-gendered registered social worker that has spent over 30 years actively seeking training and support to create an anti-oppressive social work practice that is inclusive and includes advocacy.\nI am a certified EMDR therapist and an EMDR Consultant in Training under the direction of the Beyond Healing Center. My approach integrates somatic psychology with attachment therapy, neurobiology and polyvagal theory from an anti-oppressive lens.\nI have worked with people at all stages of the transition process.\nI specialize in helping people to successfully address anxiety, depression, stress, relationship problems, and trauma including trauma due to sexism, racism, ableism, ageism, heterosexism….\nI also teach meditation and yoga.\nIf private practice is not in your budget – I am happy to help you find a public service that will work for you.	giseleharrison@bell.net	Monday to Friday	519-816-2701	N8Y	\N	\N	Gisele Harrison\nMSW, RSW	\N	https://www.giseleharrison.com
380	rho	gisele-harrison-therapist	Gisele Harrison – Therapist	2246 Hall Avenue\nWindsor, N8W 2L7	\N	I am a social work therapist in private practice. I mostly work with individuals and couples and have extensive experience working with people who have a history of trauma. I have a daily meditation practice and incorporate mindful meditation; eye movement desensitization and reprocessing; and emotional freedom technique whenever possible. I am a social justice activist and am an occasional guest columnist for the Windsor Star on issues related to racism; sexism; heterosexism and other forms of oppression.	resistersister@sympatico.ca	\N	519-816-2701	N8W	\N	\N	\N	\N	\N
401	rho	hamilton-trans-health-coalition	Hamilton Trans Health Coalition	Hamilton, L8R 3K1	\N	A group composed of family physicians, other health care providers and trans Hamiltonians working together to increase the capacity of Hamilton’s health care system to deliver high-quality healthcare to Trans Hamiltonians.	info@hamiltontranshealth.ca	\N	\N	L8R	\N	\N	\N	\N	https://hamiltontranshealth.ca
383	rho	good-call-counselling-services	Good Call Counselling Services	PO Box 34\nBeachburg, ON, K0J 1C0	\N	Good Call Counselling Services inspires individuals and families to fulfill their personal and professional sense of purpose through affirmative identity building, effective coping, wholistic healing, and self-determining across relevant life areas and relationships. Sole-proprietor Julianna Morin, MSW/RSW, offers completely virtual counselling and psychotherapy services at sliding-scale pricing to clients throughout the Province of Ontario.\nClients are supported to reframe their strengths, challenges, and opportunities for growth in order to develop a comprehensive wellness plan with timely, achievable goals in mind. Together, we will regularly evaluate this plan in order to ensure it meets your unique healing and wellness needs, usually with a focus on community development, social justice, and radical authenticity of self.	contact@goodcallcounselling.ca	Sundays to Thursdays, 10am-8pm	613-703-9663	K0J	\N	Sliding scale range - $/Hour Minimum: 75	Julianna Morin\nMSW, RSW	\N	https://goodcallcounselling.ca/
384	rho	graham-beaton-doctor-of-naturopathic-medicine	Graham Beaton – Doctor of Naturopathic Medicine	102 Lewis Street\nOttawa, K2P 0S7	\N	Graham is a licensed naturopathic doctor providing alternative and complementary care to patients. Services provided include: acupuncture, clinical nutrition, botanical medicine, and lifestyle counselling. Graham is experienced working with people with HIV and was a supervisor at the Sherbourne Community Naturopathic Clinic for People Living with HIV/AIDS in Toronto. In addition, Graham has extensive experience treating people from the LGBTQ+ community.	gbeaton@ottawand.com	\N	6132906115	K2P	\N	\N	Graham Beaton\nDoctor of Naturopathic Medicine	\N	https://www.ottawand.com
385	rho	graig-moriarty-registered-psychotherapist-rp	Graig Moriarty Registered Psychotherapist (RP)	Toronto	\N	We all need help and support at times in finding relief, clarity and well-being. I have been in private practice in Toronto for 20 years serving LGBTQ and other communities. I am skilled at working with both individual clients and couples stay present, grounded and focused.\nMost of us have heard variations on the benefits of being present and mindful – Be Here-Now! I can help you with being present; which is where cognitive and emotional self-awareness is accessible. I find that being present, with oneself and others, is the only place from which effective, conscious, lasting choices and changes can be made.\nMy approach is non-judgemental, client-centered and grounded in the client’s emotional, cognitive and physical present moment reality.\nRespectful and compassionate therapeutic interventions [that include support, encouragement and gentleness balanced with the appropriate amount of challenge] are what I strive to bring to each session. Creativity, intuition, and playfulness are often close at hand.\nDuring my 20 years in private practice I have had the privilege of working with people with different personalities, orientations, cultural backgrounds, experiences and concerns.	gm@graigmoriarty.com	\N	416 966 5100	\N	\N	\N	Graig Moriarty\nRegistered Psychotherapist(RP) | Clinical Hypnotherapist(C.Hyp) | Psychotherapeutic Bodymind Work	\N	https://www.graigmoriarty.ca
386	rho	grand-river-community-health-centre	Grand River Community Health Centre	363 Colborne Street\nBrantford, N3S 3N2	\N	At the GRCHC, we have a team of health professionals dedicated to client-centred care. This includes physicians, nurse practitioners, nurses, a social worker, registered dietitian, counsellor, chronic disease specialist, and community support facilitator/advocate. Our registered clients have access to this team who work with them towards helping them achieve better health and wellness.\nGRCHC hosts the Safe Spaces program which aims to reduce harassment, bullying and discrimination toward LGBTQ people within Brant and Brantford county.\nGRCHC run a LGBTQ social the first and third Tuesday of the month also runs Gender Journeys support group for trans and non-binary individuals, for both of these programs you do not need to be a GRCHC client.	info@grchc.ca	\N	519-754-0777	N3S	\N	\N	\N	\N	https://grandriverchc.ca/
387	rho	grand-river-community-health-centre-2	Grand River Community Health Centre	363 Colborne Street\nBrantford, N3S 3N2	I can provide transition related surgery assessments for top or bottom surgeries	The Gender Affirming Clinic at Grand River CHC offers services to individuals with regard to issues related to gender identity and expression, including gender expansive, trans and non-binary identities.\nFor individuals, consultation and support may include:	info@grchc.ca	Gender Affirming Clinic currently on Fridays	519-754-0777	N3S	\N	\N	Dr. Beverly Jones\nMD	\N	https://grandriverchc.ca/
388	rho	granite-house-retirment-community	Granite House Retirment Community	311 Central Avenue\nLondon, N6B 2E1	\N	Our retirement community is supportive independent living within an intimate environment, located in the heart of the city. We offer one bedroom apartments, meals, an activity program, a wellness program, an emergency response system (24hrs a day) with on site resident managers and Chauffeured transportation. Call for a tour-519-432-8200 or email Christine Williams at christine_williams@srgroup.ca.	christine_williams@srgroup.ca	\N	519-432-8200	N6B	\N	\N	Christine Williams\nBA.RSSW, RPN	\N	https://www.granitehouse.ca
389	rho	guelph-community-health-centre	Guelph Community Health Centre	176 Wyndham Street North\nGuelph, N1H 8N9	\N	Community Health Centre that provides primary health care as well as many services and programs.\nWe are committed to working with our community to provide access to health programs and services and create opportunities for people to improve their well-being.\nWe believe that health is a resource for life and that many things – education, housing, social status, gender, access to health services, our sense of being included or excluded from society, employment and others – impact on our health. Health isn’t just about not being sick it is about being able to make choices and live with them. It’s about having a voice in our community, it’s about being able to hope and help your kids hope.	info@guelphchc.ca	\N	(519)821-6638	N1H	\N	\N	\N	\N	https://www.guelphchc.ca/
390	rho	guelph-midwives	Guelph Midwives	Guelph	\N	Pregnancy, labour & birth, postpartum care. Client-centred and inclusive.	\N	\N	\N	\N	\N	\N	Sarah  Anderson\nRegistered Midwife	\N	\N
391	rho	guelph-midwives-2	Guelph Midwives	\N	\N	Guelph Midwives offers personalized, professional and evidence-informed prenatal care to families in Guelph, Fergus and the surrounding area. Midwives provide comprehensive primary care during pregnancy, labour, birth and up to six weeks postpartum for low risk clients and infants.	info@guelphmidwives.com	\N	519-823-9785	\N	\N	\N	\N	\N	https://www.guelphmidwives.com
402	rho	hammond-psychotherapy-services-inc	Hammond Psychotherapy Services Inc.	Kingston, K7P1N3	\N	We provide mental health counselling for individuals, families, and couples. Registered Psychotherapists with over 40 years combined experience; specializing in couples counselling, substance use, anxiety, youth, trauma, and burnout.\nWe keep it down-to-earth and authentic, we like to use plain language and work from YOUR place of growth. Resolution focused therapy in Kingston by Psychotherapists who know what it’s like to be on the other side.	Amanda@HammondPS.ca	Monday to Friday, 9 a.m. to 7 p.m., Saturday by appointment.	343-344-3066	K7P	\N	$160	\N	\N	https://www.hammondpsychotherapy.com/
392	rho	guiomar-campbell-shiatsu-and-acupuncture	Guiomar Campbell Shiatsu and Acupuncture	Toronto	\N	Lotus Arts and Wellness is committed to educate women and youth in the areas of gynecology, Obstetrics and Pregnancy by providing quality services through the healing arts of Shiatsu, Acupuncture and Essential Oils. Special attention is given on self care and home remedies.\nOne treatment session lasts from 60-90 min and includes:\n. Client’s history and assessment of their condition\n. Correction of posture\n. Shiatsu and acupuncture treatment combined\n. Application of handcrafted certified organic massage oils, for deep relaxation.\nMeridian and energy healing workshops and classes- Participants learn how to balance body, mind, heart and spirit in playful and relaxing explorations of meridian stretching, yoga, affirmations, Brazilian drumming, creative dance and self massage.\nClasses on Shiatsu acupressure for pain management and mental relaxation. Students learn simple tecniques of self-acupressure to be used at home as home remedies.	guiomar@lotusshiatsutherapy.com	\N	416 986-9270	\N	\N	\N	Guiomar Campbell\nShiatsu Therapist C.S.T. R.N	\N	https://www.lotusartswellness.com
393	rho	gulin-aydin-counselling	Gulin Aydin Counselling	1190 King Street East\nKitchener, N2G 2N4	\N	Her counseling approach is the brain based mindfulness therapies for treatment of emotional/physical health issues such as depression, anxiety, chronic pain and post traumatic stress disorder.\nOne of the therapies that she uses in her practice is EMDR (Eye Movement Desentization and Reprocessing). Traumatic experiences tend to stay locked in our bodies and minds until they can be released. EMDR has been found to be particularly effective at facilitating healing and growth. It is remarkable for its ability to move disturbing memories into the past so they no longer affect the person. It is focused on bringing together the images, thoughts, feelings, and body sensations of person’s experience. Working with the body and mind together is key in overcoming trauma. She received her Level I and II trainings in Boston and Chicago from EMDR Humanitarian Assistance Program.\nShe believes in a holistic approach and encourages clients to supplement their therapy with exercise, yoga, nutrition awareness and mindfulness based practice. As a holistic therapist, her goal is to help clients uncover their true potential and discover greater confidence and self-awareness along their journey. She has been fortunate to work with many diverse clients over the years, each of whom has contributed to her learning and development.	gulinaydin.msw@gmail.com	\N	226-9897504	N2G	\N	\N	Gulin Aydin\nMSW, RSW	\N	https://www.gulinaydin-msw.blogspot.com
394	rho	gundel-lake-psychotherapy	Gundel Lake, Psychotherapy	329 Frank Street\nOttawa, K2P 0X7	\N	Located in Ottawa, Ontario, Gundel offers individual psychotherapy to people 18 years of age and older. Her areas of specialty include trauma, addiction, domestic and/or (childhood) sexual violence, grief, depression, sexuality, and family of origin issues.\nGundel’s approach to psychotherapy is deeply rooted in feminist and structural analyses that contextualizes individual “problems” in our social environments. She practices from a strengths-based perspective, challenging clients to connect with their authentic selves and to enhance empowered coping skills.\nGundel holds a Masters degree in Social Work and has been practicing in the field for over fifteen years.	info@gundellake.com	\N	613-325-8186	K2P	\N	\N	Gundel Lake\nMasters of Social Work, R.S.W.	\N	https://www.gundellake.com
395	rho	h-e-a-l-t-h-clinic-voice-found	H.E.A.L.T.H Clinic Voice Found	1 Nicholas Street\nOttawa, K1N 7B7	\N	H.E.A.L.T.H is a primary health care clinic that is opening February 22nd 2018 in Ottawa. This clinic is funded to serve those at risk, those experiencing, and those who have experienced human trafficking (all forms).	health@voicefound.ca	\N	613-796-2268	K1N	\N	\N	Tara Leach\nPrimary Health Care Nurse Practitioner	\N	https://voicefound.ca
396	rho	haliburton-youth-wellness-hub	Haliburton Youth Wellness Hub	12 Dysart Ave.\nHaliburton, K0M1S0	I can provide transition related surgery assessments for top or bottom surgeries	The Haliburton County Youth Wellness Hub is a one stop shop for youth ages 12-25. Providing mental health supports, employment, housing and recreational programs.  Our Registered Nurse Practitioner provides primary care including sexual health and trans health services.	haliburtonhub@pointintime.ca	Monday 8:30-4:30 Tuesday 8:30-6:30 Wednesday 8:30-4:30 Thursday 8:30-6:30 Friday 8:30-4:30 Subject to change as of June 2021	7054572727	K0M	\N	\N	Lindsay Meller\nPHC-NP (Primary Health Care Nurse Practitioner), MN (Masters in Nursing)	\N	https://www.youthhubs.ca/en/sites/haliburton/
397	rho	hamilton-family-health-team	Hamilton Family Health Team	123 James Street North\nHamilton, L8R 2K8	\N	The Hamilton Family Health Team (HFHT) located in downtown Hamilton, serves part of the Local Health Integration Network 4 (LHIN 4 Hamilton, Niagara, Haldimand and Brant) region and is the largest Family Health Team in Ontario.\nThe Hamilton Family Health Team includes:\nThese clinicians work together in a collaborative environment using various tools and resources to get patients the care they need and keep them healthy.	\N	\N	905-667-4848	L8R	\N	\N	\N	\N	https://www.hamiltonfht.ca/
398	rho	hamilton-health-sciences	Hamilton Health Sciences	1200 Main Street West\nHamilton, L8S 2A5	\N	I provide both medical and surgical options for Transgender and Non-binary patients, including Masculinizing and Feminizing Hormone Therapy, as well as Bottom Surgery (Hysterectomy +- Salpingoophorectomy). We also strive to provide trans-competent care for patients with other gynecological concerns. There is the option of being seen in a therapy-type setting for consultations where a greater degree of privacy is requested, however many patients are seen alongside other cisgender patients.\nIn addition, as an LGBT physician and parent, we will gladly see LGBT Families for obstetrical care for those who wish or need to see and obstetrician.	\N	\N	905-521-2100 x76248	L8S	\N	\N	Dustin Costescu\nMD FRCSC	\N	https://www.costescu.ca
399	rho	hamilton-prep-clinic	Hamilton PrEP Clinic	300-25 Charlton Avenue East\nHamilton, L8N 1Y2	\N	We provide assessment, initiation and follow up of Pre-Exposure Prophylaxis for HIV prevention	\N	\N	905-522-1155, xt 35053	L8N	\N	\N	Kevin Woodward\nMD, FRCPC	\N	https://hamiltonprepclinic.ca
400	rho	hamilton-psychotherapy	Hamilton Psychotherapy	Hamilton, L9H 4B9	\N	Counselling/Psychotherapy services available to the LGBTQ Community in the Greater Hamilton area as well as in Downtown Toronto.\nAs an LGBTQ person myself I work for our Community from within our Community.\nMany psychotherapists, psychologists and counsellors, both here in Hamilton and in Toronto as well, openly advertise that their services are available to LGBT2SQ+ persons but sometimes its just nice to know the person sitting in the other chair really “gets you” on another level.\nWe are all individuals, of course. Your personal journey is your own. No one else’s life experience will be quite what yours has been but know that I am not only qualified but willing, able and experienced enough to be truly present in this journey with you.	hamiltonpsychotherapy@gmail.com	Mondays 11:00 - 20:00 HRS (Toronto Office) Wednesdays 11:00 - 20:00 HRS (Hamilton/Dundas Office) Remote / Online video sessions available	1-289-527-4427	L9H	\N	Sliding scale range - $/Hour Maximum: 110	Robert Feeney\nRegistered Psychotherapist; BSc.; AEAPC; CTP Dipl	\N	https://hamiltonpsychotherapy.ca
403	rho	hands-to-heel	Hands to Heel	4187 Sutherland Crescent\nBurlington, L7L 5G3	\N	Are you looking to sleep better, reduce stress, take care of tired feet or hands? Maybe there is something you are wanting to address more holistically. At Hands to Heel there are many different sessions to nurture and support you. Reflexology will have you feeling good, help your body function better, and you’ll have a spring in your step knowing you’re on a path of wellness!	michelle@handstoheel.com	\N	9054648076	L7L	\N	\N	Michelle Hache\nReflexologist	\N	https://handstoheel.com/
404	rho	hannah-e-peck-psychotherapy	Hannah E. Peck Psychotherapy	Kingston, K7L 1X4	\N	I have many years of experience working with queer and trans adults, and I have a special focus on treating trauma, including childhood abuse and neglect. I primarily use Internal Family Systems therapy (IFS), and incorporate Eye Movement Desensitization and Reprocessing (EMDR), and attachment theory.\nPlease visit my website for more information, or reach out to book a free consultation.	hep.therapy@gmail.com	Monday - Thursday: 9 a.m. - 5 p.m.	613-801-8056	K7L	\N	$150	Hannah E. Peck\nM.Ed., R.P.	\N	https://www.heptherapy.com
405	rho	hassle-free-clinic	Hassle Free Clinic	Toronto	\N	Patient registration ends when all slots are filled, generally early in clinic hours\nMen/Trans-Identified — Mon, Wed 4 pm-8 pm; Tue, Thu 10 am-3 pm; Fri 4 pm-7 pm; Sat 10 am-2 pm * closed Sun and holidays\nWomen/Trans-Identified — Mon, Wed, Fri 10 am-3 pm; Tue, Thu 4 pm-8 pm * closed Sat, Sun and holidays\nOffice phone answered during clinic hours only * answered with recorded messages after hours or when busy\nSexual health counselling and related medical services, including birth control, testing and treatment for sexually transmitted infections, and anonymous HIV testing and counselling\n* partners welcome\n* confidential\n* no Ontario Health Insurance required\n* schedules for women/trans and men/trans clinics differ — see Hours above\n* clinic space limitedMen/Trans-Identified clients — drop-in for sexually transmitted infection (STI) testing and treatment\n* Hepatitis A and B vaccinations\n* free condoms available\n* by appointment — anonymous HIV testing, counselling and treatment information\n* sexuality and safe sex counselling\n* sexual assault counselling, testing and follow-up\n* outreach to bathhousesWomen/Trans-Identified clients — drop-in for sexually transmitted infection testing and treatment\n* free condoms available\n* emergency contraception/Plan B\n* by appointment — counselling on safer sex, sexually transmitted infections (STI), birth control, sexuality and healthy relationships\n* pregnancy testing and counselling\n* abortion counselling, referral and follow-up\n* fertility awareness\n* anonymous HIV testing, counselling and treatment information\n* support for HIV positive women and trans people\n* sexual assault counselling, testing and follow-up	admin@hasslefreeclinic.org	\N	416-922-0566	\N	\N	\N	\N	\N	https://www.hasslefreeclinic.org
406	rho	hatty-wong-registered-psychotherapist	Hatty Wong, Registered Psychotherapist	Toronto, M4P 1G8	\N	Have you ever experienced periods in your life where you are so troubled by stress, anxiety relationship difficulties, and/or depressed mood but is uncertain who to turn to talk about the issues in fear that you’ll be misunderstood or that others simply just won’t get what you’re going through? If so, I would be happy to work with you to explore the issues troubling you. As a Psychotherapist, I have worked with a number of individuals ranging from ages 7 – 65+ from various ethnic backgrounds to help them work through a variety of issues. I have experience working with those in the LGBTQ community and marginalized groups.\nI have close to 10 years of experience working in various settings (hospital, private practice, correctional facilities). I normally approach much of my work from a Cognitive Behavioral or Dialectical Behavioral approach – but as each client and their concerns are unique in its’ own way, I am also quite versatile in my approach.\nOne of the most difficult yet courageous steps when seeking therapy is reaching out. I strongly believe that no significant therapeutic progress can be achieved without first having a strong therapeutic relationship with your client. I offer a free brief telephone consultation to help us decide if we would be a good fit to work together.\nSpecialties:	info@hattywongpsychotherapy.com	Monday: 9:00 am - 5:00 pm Friday: 9:00 am - 6:00 pm Saturday: 9:00 am - 1:00 pm Appointments outside of operating hours may be accommodated	6479989059	M4P	\N	Sliding scale range - $/Hour Minimum: 100 Maximum: 150	Hatty Wong\nM.Psy, R.P	\N	http://www.hattywong.com
407	rho	hatty-wong-rp	Hatty Wong (RP)	Toronto, M2N 7K4	\N	I am a Registered Psychotherapist who provides services to adolescents and adults. My approaches to psychotherapy include CBT, DBT, ACT, Mindfulness, and Solution-Focused to list a few. My framework can be described as one that is trauma-informed, culturally sensitive and anti-oppressive when it comes to working with clients. In psychotherapy, my highest priority is in establishing and maintaining a positive and trusting therapeutic relationship with all of my clients and approach the concerns in an empathic and compassionate manner	hattyhtwong@alumni.utoronto.ca	\N	6479989059	M2N	\N	\N	Hatty Wong\nM.Psy (RP)	\N	\N
408	rho	haven-therapeutic-massage	Haven Therapeutic Massage	390 Dupont St. Suite 201\nToronto, M5R 1V9	\N	Registered Massage Therapy for women & the LGBTQ+ community living with anxiety.	chantel@haventherapeuticmassage.com	Monday 10a.m.–8p.m. Tuesday 11a.m.–7p.m. Wednesday 10a.m.–6p.m. Thursday 10a.m.–5p.m. Friday Closed Saturday Closed Sunday 10a.m.–6p.m.	6472705846	M5R	\N	$115 60 minutes / $155 90 minutes / $220 120 minutes	Chantel Patricio\nRMT (Registered Massage Therapist)	\N	https://www.haventherapeuticmassage.com
409	rho	hayley-darychuk-psychotherapy	Hayley Darychuk Psychotherapy	717 Bloor Street West\nToronto, M6G 1L5	\N	I am a queer identified Registered Social Worker who provides psychotherapy and system navigation services in the Toronto area. I have a Masters of Social Work Degree from The University of Toronto, and Bachelors of Social Work degree from McGill University.\nI specialize in supporting individuals experiencing social and general anxiety, depression, drug and alcohol addiction and navigating life transitions. I am also skilled in system navigation, and can help you determine what health and other social services might be the best fit for your needs.\nMy practice is trauma informed, LGBTTQ2S affirming and grounded in anti-oppressive principles. I draw on my training in Cognitive Behavioural Therapy, Dialectical Behavioural Therapy, Narrative Therapy and Mindfulness Approaches to meet my clients where they are at.\nI offer online and in person counselling. All services are offered on a sliding scale, and covered under most insurers. I am located at a ttc accessible office space in the Annex.	hayleydarychukpsychotherapy@gmail.com	\N	14165540889	M6G	\N	\N	Hayley Darychuk\nRegistered Social Worker	\N	https://hayleydarychuk.com
486	rho	kathy-payne-therapy	Kathy Payne Therapy	46 Westmorland Ave\nOrangeville, L9W 3B6	\N	Kathy Payne provides a client-centred and solution-focused practice helping people to improve their relationships in individual, couples, and family counselling of all types.\nAreas of expertise:  depression, anxiety, bereavement/grief, life transitions and more\nVirtual practice:  phone or video, booking  link below\nhttps://oab.owlpractice.ca/kathypaynetherapy/booking\n	kathypaynetherapy@gmail.com	Tuesday and Thursday: 10 am to 8 pm Wednesday and Friday: 10 am to 6 pm	519-939-7575	L9W	\N	120.00	Kathy Payne\nMA Counselling Psychology	\N	https://www.kathypaynetherapy.ca
410	rho	healing-for-everybody-psychotherapy-msw-rsw	Healing for Everybody psychotherapy MSW, RSW	240 Roncesvalles Avenue\nToronto, M6R 1M3	\N	Hello, I am Tracey Jastinder Mann MSW, RSW (OCSSSW # 832771. I am a practicing psychotherapist and a queer femme of colour who is working to support collective healing and liberation by offering individual counselling; group facilitation and workshops. My work is centred in an intersectional feminist approach to therapy and facilitation. I focus on creating a healing space where we can explore the emotional dimensions of life changes, experiences of trauma, grief and loss while also attempting to understand how experiences of marginalization, privilege and power influence our lived experiences.\nI have over 15 years of experience as a social worker offering therapeutic services. I also have 20 years of organizing experience working with communities within collectives focusing on the following issues : anti-globalization; migrant justice; indigenous solidarity; environmental justice; healing justice; transformative justice; prison abolition; sex worker rights; queer liberation; housing justice and harm reduction. In addition in have worked in the social service and environmental sector on the front lines and also in a leadership capacity.\nI have experience in the following areas:\nsupporting survivors of sexual/interpersonal/structural violence\nharm reduction and substance use\ngrief and loss\nanxiety, depression and BPD\nPTSD\nhealing from racial trauma\nnavigating interpersonal relationships\nworkplace bullying\nLGBTQIAA identities\nexploring kink\npoly relationships\nsex work\nmigrant justice\nEco-therapy\nnavigating gender journeys.\nRates: a 50 min session is $125 for students and low income folks; $150 for those with full time employment. My sliding scale options are currently at capacity. My work is covered by most insurance companies.\nI offer a free 15 min phone consultation so that you can understand more about my work and to determine if my services match you needs.	healingforeverybody@gmail.com	\N	647-955-0524	M6R	\N	\N	Tracey Mann\nMSW, RSW	\N	https://www.healingforeverybody.ca
411	rho	healing-house-naturopath	Healing House – Naturopath	9 Melrose Avenue\nOttawa, K1Y 1T8	\N	Personalized health care, with emphasis on preventative medicine and the unique physical, mental, and emotional needs of each and every individual.	naomi@healinghouse.ca	\N	\N	K1Y	\N	\N	Naomi Johnson\nND	\N	https://www.healinghouse.ca
412	rho	healing-path-homeopathy	Healing Path Homeopathy	717 Bloor Street West\nToronto, M6G 1L5	\N	Are you looking for a way to improve your health naturally, gently and effectively?\nYou have come to the right place. Welcome to the fascinating world of homeopathy!\nI am a Homeopath in downtown Toronto, ON, who uses classical homeopathy to improve health and treat disease. I use individualized homeopathic medicines to stimulate and support my patients’ abilities to heal themselves.	info@healingpathhomeopathy.com	\N	416-726-3506	M6G	\N	\N	Annabelle Menezes\nHomeopath (Hom.)	\N	https://www.healingpathhomeopathy.com
413	rho	healing-roots-therapy	Healing Roots Therapy	30 Village Centre Place, Suite 208\nMississauga, L4Z 1V9	\N	Providing online and in-person counselling and psychotherapeutic support to individuals, couples and families.	sara@healingrootstherapy.ca	My hours of service are Mondays & Wednesdays 3-9pm, Tuesdays 10am-4pm.	905-755-0008 Ext: 2	L4Z	\N	Free 15-minute phone consultation, $145+HST (individual therapy) and $150+HST (couple’s therapy)	Sara Scott\nMACP, RP	\N	https://healingrootstherapy.janeapp.com/#/staff_member/30
414	rho	health-counselling	Health Counselling	Peterborough, K9H3R9	\N	Em is a queer and disabled Registered Social Worker, offering virtual therapy for 2SLGBTQ+ people across Ontario and in the Peterborough area.	em@healthcounselling.ca	Daytime and evening appointments available	226-349-7937	K9H	\N	$155\nSliding scale range - $/Hour Minimum: 0 Maximum: 155	Em Osborne\nMSW	\N	https://www.healthcounselling.ca/meet-em
415	rho	health-sciences-north	Health Sciences North	Greater Sudbury, P3E 5J1	\N	This unit is designed specifically for children and adolescents who, as a result of a situational crisis or psychiatric illness, are acutely ill and require short-term hospitalization. Admission to this unit is on the recommendation of a psychiatrist or by their designate. Family members are encouraged to take part in the assessment and treatment planning for their child or adolescent.	\N	\N	705.523.7100 ext. 8012	P3E	\N	\N	Inpatient Psychiatry- Crisis Stabilization	\N	https://www.hsnsudbury.ca/portalen/Programs-and-Services/Mental-Health-and-Addictions/Child-Adolescent-and-Family-Services
416	rho	healthone	HealthOne	110 Harbour Street\nSouth Core District Toronto\nToronto, M5B 1J3	\N	HealthOne provides you with multiple Health Services, Our team of health experts are specialized to handle different types of physical and mental challenges faced by our patients. Here is our list of services;\n	info@healthone.ca	At HealthOne You can always book and appointment to your doctor via our webpage https://healthone.ca/ Medical Tel: 416 613 0333 Email: medical@healthone.ca Fax: 647 689 6503 Monday 9 am – 8 pm Tuesday 9 am – 8 pm Wednesday 9 am – 8 pm Thursday 9 am – 8 pm Friday 9 am – 6 pm Saturday 10 am – 3 pm Sunday Closed Dental Tel: 416 613 6233 Email: dental@healthone.ca Fax: 416 613 8578 Monday 10 am – 6 pm Tuesday 9 am – 7 pm Wednesday 10 am – 6 pm Thursday 9 am – 7 pm Friday 10 am – 6 pm Saturday 10 am – 3 pm Sunday Closed Rehab & Orthotics Tel: 416 613 5633 Email: rehab@healthone.ca Fax: 416 613 8577 Monday 10 am – 7 pm Tuesday 10 am – 7 pm Wednesday 10 am – 7 pm Thursday 10 am – 7 pm Friday 10 am – 6 pm Saturday 10 am – 4 pm Sunday Closed Mental Health Tel: 416 613 5633 Email: wellness@healthone.ca Fax: 416 613 8577 Monday 10 am – 7 pm Tuesday 10 am – 7 pm Wednesday 10 am – 7 pm Thursday 10 am – 7 pm Friday 10 am – 6 pm Saturday 10 am – 4 pm Sunday Closed Wellness Tel: 416 613 5633 Email: wellness@healthone.ca Fax: 416 613 8577 Monday 10 am – 7 pm Tuesday 10 am – 7 pm Wednesday 10 am – 7 pm Thursday 10 am – 7 pm Friday 10 am – 6 pm Saturday 10 am – 4 pm Sunday Closed Optometry Tel: 416 613 6433 Email: optometry@healthone.ca Fax: 416 613 8576 Monday 11 am – 6 pm Tuesday 11 am – 6 pm Wednesday 11 am – 6 pm Thursday 11 am – 6 pm Friday 11 am – 6 pm Saturday 10 am – 2 pm Sunday Closed Medispa & Skin Clinic Tel: 416 613 5433 Email: skinclinic@healthone.ca Fax: 416 613 8579 Monday 10 am – 6 pm Tuesday 10 am – 6 pm Wednesday 10 am – 6 pm Thursday 10 am – 6 pm Friday 10 am – 6 pm Saturday By Appointment Only Sunday Closed Pharmacy Tel: 416 221 5433 Email: pharmacy@healthone.ca Fax: 416 784 5757 Monday 9:00 am – 8 pm Tuesday 9:00 am – 8 pm Wednesday 9:00 am – 8 pm Thursday 9:00 am – 6 pm Friday 9:00 am – 6 pm Saturday 10 am – 3 pm Sunday Closed HealthOne Hub Tel: 416 784 5433 Email: thehub@healthone.ca Monday 10 am – 6 pm Tuesday 10 am – 6 pm Wednesday 10 am – 6 pm Thursday 10 am – 6 pm Friday 10 am – 6 pm Saturday 10 am – 3 pm Sunday Closed	416 663 5433	M5B	\N	\N	\N	\N	https://healthone.ca/
417	rho	heaven-scent	Heaven Scent	169 Wortley Road\nLondon, N6C 3P6	\N	Our clinic offers:\nAllergy Testing\nAcupuncture – in many forms\nReiki\nReflexology\nNatural Fertility\nBiofeedback\nRubimed\nIonic Foot Detoxes\nInfra Red Sauna\nFire Cupping\nChakra Balancing\nIridology\nCrystal Healing\n13 styles of Massage\nIdeal Protein\n	store@heavenscent.ca	10 - 5:30 pm Tuesday to Saturday	5194333434	N6C	\N	each service has a different cost. Our web site is very transparent about our pricing. Each and every service is listed with the cost per treatment.	Christine Ricahards	\N	https://www.heavenscent.ca
418	rho	heavenly-hands-doula-service	Heavenly Hands Doula Service	Kitchener	\N	Providing professional and experienced postpartum doula services for families in Kitchener, Waterloo, Cambridge and surrounding areas. We offer a wide variety of services that can be utilized and tailored to meet your specific needs. Some examples of services that are provided include, but are not limited to:\n*Providing emotional, physical and educational support for parents and their family during the postpartum period and beyond\n*Empowering parents with gentle guidance and support\n*Breastfeeding and chestfeeding education, assistance and support\n*Expert newborn care instruction for parents including bathing, diapering, feeding, swaddling, sleeping tips and much more\n*Creating a nurturing atmosphere and providing newborn care which allows parents the opportunity to eat, shower, nap, run errands and/or have personal time for themselves\n*Providing a safe environment for parents to discuss their thoughts and emotions revolving around their pregnancy, birth and postpartum experiences\n*Light housekeeping and baby laundry\n*Simple preparation of meals and snacks including ensuring that parents are well nourished and hydrated\n*Running small errands including grocery shopping\n*Assisting with household organization to best accommodate parents and baby’s needs\n*Assisting with multiples and post-Cesarean care\n*Providing care for older siblings in order to allow parents the time that they need to focus on and tend to their newborn\n*Providing local resources for parents including access to community support services\n*Support via telephone and email during the contracted period\n*Infant Massage training (additional fees may apply)\nFor more information, visit: www.heavenlyhandsdoulas.com	info@heavenlyhandsdoulas.com	\N	519-807-4834	\N	\N	\N	Anita Bocian\nCertified Postpartum Doula	\N	https://www.heavenlyhandsdoulas.com
419	rho	heidi-argyle-psychotherapy	Heidi Argyle Psychotherapy	745 Bridge St W\nunit 6\nwaterloo, N2V 2G6	\N	Thinking about therapy but not sure about all that “talking”? I got you!\nArt Therapy is a unique and well-studied style of Psychotherapy, which is: the process of working on your thoughts, feelings and emotions to be the best version of you!\nWhat I love about Art Therapy as an approach to your wellbeing, is it’s not a box (because neither are you), and we can build a plan of care that supports your wants, your needs and critically what’s most important to you.\nI have to say, art and creativity helped me through some pretty harsh times throughout my life and to this day I still turn to the canvas to process lessons, changes and hardships; because it’s mine, it’s what is meaningful to me. I also don’t have to hold a conversation with a stranger for a whole hour (EXHAUSTING!).\nThe other thing I really like about art therapy is that creative expression of our struggles or dis-ease helps to be seen and heard; art and art therapy allow us to see into our thoughts or feelings, to externalize our inner experiences, all while strengthening growth and resilience.\n**Sex therapy!?** Talking about sex and sexuality is not something we often consider when we begin therapy. Yet, these are very important part of ourselves and relationships. I take a values based approach to talking about sex, so that you can feel more comfortable bringing that Whole Self into the therapy room, and feel confident your therapist has the skills to support you. I work with all identities and relationship styles (LGBTQ2S+, Polyamory, Kink, etc.)\nIf you’re curious to know more about how art therapy or sex therapy might be a fit for what ails ya – please book a consultation or send me an email! I look forward to meeting you and growing with you!\nCheers,\nHeidi\n#Certifications\nHeidi is a Registered Psychotherapist (RP) and a Registered Canadian Art Therapist (RCAT), an Associate member of the Board of Examiners in Sex Therapy and counselling in Ontario (BESTCO).\n#Areas of Special Interest\nADHD, Borderline Personality Disorder (BPD), DID, teens and youth (14+), self-esteem, gender and identity development, sexual and relationship minorities, LGBTQ2S+	heidi@alignedhealth.ca	Monday 2 p.m. to 7 p.m. Wednesday 2 p.m. to 7 p.m. Thursday 2 p.m. to 7 p.m. Friday 11 a.m. to 3 p.m.	647-496-6775	N2V	\N	$150	Heidi Argyle\nRegistered Psychotherapist	\N	https://www.arttherapywaterloo.ca/
420	rho	heidi-mehta	Heidi Mehta	Online\nToronto, M4W 1A8	\N	I have a Master’s Degree in Social Work – Health and Mental Health Specialization – (MSW, RSW). I hold 25 years of relevant professional experience working in post-secondary education, health care, and community settings. I currently offer therapy and consulting services online  across Ontario and BC.\nI work from an anti-oppressive, trauma informed approach. I draw from Sensorimotor Psychotherapy, CBT, DBT, Narrative Therapy, ACT, Yoga, Mindfulness, Motivational Interviewing, TFCBT, CPT, IFS, EMDR, etc.\nI identify as a queer femme of colour. I am trauma-informed, having worked for many years with survivors of sexual, state-based, and intimate partner violence. I have worked on anti-racist models of mental health and recognize that racism is a social determinant of health, am knowledgeable of the healthy immigrant effect and have been part of a refugee mental health community of practice. I also led a program to offer Black, Indigenous and women of colour violence prevention workshops that won an award from the Quebec Ministry of Health. I have worked extensively in LGBTQ communities from running Positive Space to working on building Queer and Trans resilience. I am registered with NIHB and the IFHP to offer free counselling services to eligible Indigenous and refugee clients respectively.\nTo learn more about my offerings as a therapist and a consultant, please visit: heidimehta.wixsite.com/therapy .	heidi.mehta@therapysecure.com	Mondays-Fridays, some evenings.	6477833365	M4W	true	Registered with the NIHB and IFHB.	Heidi Mehta\nMSW, RSW (Registered with the OCSWSSW & the BCCSW) Social Worker-Psychotherapist	\N	https://www.heidimehta.wixsite.com/therapy/
421	rho	heidi-prosserman-psychotherapy	Heidi Prosserman Psychotherapy	51 Rose Green Drive\nVaughan, L4J 4R8	\N	I offer support for people struggling in relationships and who have been unconsciously part of an abusive past; sexual, physical or emotional. I also offer support for people transitioning from a heterosexual marriage/relationship into a gay relationship/life style. It is important to release shame and to recognize that we are both spiritual beings and human beings and we are interconnected through our mind, body and soul. Sometimes we are too much in our mind and not enough in our body. Our bodies never lie, they speak our truth. If we are to heal, we have to accept our past and make it conscious. We must stop blaming it and acting out. Our past needs to be recognized, accepted, forgiven and put to rest, so we may rest. Through my education and life experience I have learned many different modalities assisting people in changing and growing to achieve more fulfillment and balance within their lives. My techniques will help reduce anxiety and depression and relieve stress and tension through emotional and physical release.	heidiprosserman@rogers.com	\N	416 878-5667	L4J	\N	\N	Heidi Prosserman\nPsychotherapist	\N	\N
422	rho	helen-hargreaves-msw-rsw-therapy	Helen Hargreaves MSW RSW – Therapy	Toronto	\N	Sign up for our email newsletter to get news about RHO's work and LGBT2SQ health in Ontario.	helen@helenhargreaves.com	\N	647 667 7241	\N	\N	\N	Helen Hargreaves\nRegistered Social Worker, Masters of Social Work	\N	https://www.helenhargreaves.com
423	rho	helena-frecker-md	Helena Frecker, MD	658 Danforth Avenue\nToronto, M4K 1R2	\N	I am an Obstetrician & Gynecologist working in Toronto. In addition to my specialist training, I have done a fellowship in Minimally Invasive Gynecologic Surgery and a Masters Degree in Quality Improvement and Patient Safety.\nI have a particular interest in providing safe and inclusive care for the LGBTQ+ community, particularly for gender diverse patients. I have given city-wide educational presentations to healthcare providers regarding care for gender diverse individuals and done a surgical observership at GRS Montreal.\nI offer Gender Confirming Surgery in the form of hysterectomy BSO for transmale patients and provide post-operative care to trans individuals who have had other Gender Confirming Surgeries, including vaginoplasty, phalloplasty, metoidioplasty, etc.\nBeing an Obstetrician, I also offer safe and inclusive prenatal and labour & birth care. I deliver babies at Michael Garron Hospital (formerly Toronto East General). At MGH, we are striving to make our labour & birth unit as inclusive for the LGBTQ+ community as possible through education of our staff and creation of a safe and gender-inclusive space.	openarmobgyn@gmail.com	\N	416-466-2360	M4K	\N	\N	Helena Frecker\nMD FRCSC MSc(HQ)	\N	\N
424	rho	helix-healthcare-group	Helix Healthcare Group	102 Yorkville Avenue\nToronto, M5R 1B9	\N	Located in downtown Toronto, Helix Healthcare Group is an innovative provider of treatment services for those facing mental health, trauma and/or addiction issues. As the first of its kind in Canada, the 4000 sq. ft. world-class treatment facility offers a unique, holistic approach that pairs traditional methods of care with cutting-edge therapies to help clients achieve lasting change.	info@helixhealthcaregroup.com	\N	4169212273	M5R	\N	\N	Jesse Hanson\nPsychotherapist, MA, PhD	\N	https://helixhealthcaregroup.com/
442	rho	inclusive-with-carling-therapy	Inclusive with Carling therapy	13 Water St\n3A\nCambridge, N1R 3B2	\N	Tim and Carling are Registered Psychotherapists who work from an anti-oppressive and feminist informed perspective. We work with everyone of different romantic and sexual orientations. Carling and Tim have experience working with polyamorous, nonmonogamous and relationship anarchist clients. Additionally, Carling worked at an HIV and Transgender Heath Clinic for a few years.	contact@inclusivewithcarling.com	Monday to Friday, 9 am to 9 pm.	519-504-8279	N1R	\N	140 - 160 + HST\nSliding scale range - $/Hour Minimum: 100 Maximum: 160	Carling Mashinter\nTim Mccurdy-myers	\N	https://www.inclusivewithcarling.com/
425	rho	helping-hands-mobile-massage	Helping Hands Mobile Massage	Stouffville, L4A 1V3	\N	Does your pain limit the amount of time you spend doing the things you love? Do you struggle to find time and childcare so that you can commute to your appointments? Do you want a healthcare practitioner who strives to respect your individual needs based on your health, life experiences, culture and beliefs, disabilities, and sexual/gender orientation?\nThese are just a few of the reasons Helping Hands has been inspired to offer mobile massage in your home.\nMobile massage caters to moms and dads, infants, children and teens, athletes, the elderly, individuals with various disabilities, mobility aids, and mental illnesses, patients with terminal illness, grieving souls, and homebodies alike.\nMobile massage is about meeting you wherever you are in your life. It’s about listening, understanding and respecting your wants and needs, and working with you to create a treatment plan that will aid you in fulfilling your goals, whether they be to recover from an injury, to increase your mobility, to work through emotional pain trapped inside the body, to practice self-care or body acceptance, or simply to find peace is a tumultuous time.\nRediscover accessible massage in the comfort and convenience of your own home.\nHelping Hands Mobile Massage serves families within the regions of York and Durham, Ontario.	keeleyshantzrmt@gmail.com	By appointment any day of the week, 10am-8pm.	6479289709	L4A	\N	\N	Keeley Shantz\nRMT	\N	https://www.helpinghandsmobilemassage.com
426	rho	hershel-russell-psychotherapy	Hershel Russell Psychotherapy	Toronto	\N	A sturdy warmth, a sharp mind, excellent therapeutic skills and a sense of humour.\nI have worked with individuals and couples in Private Practise since Jan 1989, primarily LGBT clients and their families, though many straight and cisgendered people come in too–who am I to discriminate? Providing support to the parents, partners, adult children and families of LGBT people is also a particular interest for me. My own grown children have certainly challenged me in all kinds of unexpected ways.\nAs an out (and visible) transgendered man, my office can feel particularly comfortable for a wide range of trans people. I work to create a protected space where clients can explore their gender without preconceptions or pressure in any direction from me. I also have considerable knowledge of how others have navigated these complex issues–and the medical system — to reach some place of comfort and good health that works for them.\nI am also familiar and comfortable with a range of Queer communities, including Queer communities of Colour, polyamorous or other negotiated non-monogamous relationships, and Leather/BDSM communities.\nI work within a feminist and anti-oppression framework, though I hope I am never didactic. I have training in a wide range of modalities, from Gestalt through Rogerian, from Jungian dreamwork to current mainstream theories. These days I find myself particularly interested in Narrative thinking. Overall it remains my belief (supported by much research) that theoretical background matters much less than the quality of relationship between therapist and client.	hershel@ca.inter.net	\N	\N	\N	\N	\N	Hershel Russell\nMA, MEd, Clinical Member (since 1994) of Ontario Society of Psychotherapists	\N	\N
427	rho	hiv-aids-legal-clinic-ontario-halco	HIV & AIDS Legal Clinic Ontario (HALCO)	55 University Avenue\nToronto, M5J 2H7	\N	HALCO provides a variety of services.  We provide free legal services to people in Ontario who are living with HIV/AIDS.  We also provide public legal education activities across Ontario.  In addition, we are involved in a variety of law reform and community development activities.  HALCO produces publications including our HALCO pamphlet, our newsletter, information sheets, and more.\nClient Groups: People living with HIV/AIDS in Ontario\nOur services:\nLegal Services\nPublic Legal Education activities (including our free workshops)\nLaw Reform\nPublic legal information materials (including our newsletter and website)\nTrans* Legal Needs Assessment (Ontario)	talklaw@halco.org	\N	1-888-705-8889 or 416-340-7790 (Toronto)	M5J	\N	\N	\N	\N	https://www.halco.org/
428	rho	hiv-aids-regional-services-kingston	HIV/AIDS Regional Services – Kingston	844a Princess Street\nKingston, K7L 1G5	\N	Celebrating 25 years of Opening Doors and Changing Lives. For 25 years HARS has been providing education and support to individuals and organizations in Kingston and the surrounding region. Our services include counselling, advocacy, access to free condoms, a Needle Exchange and an extensive resource library & education department.	hars@kingston.net	\N	613-545-3698 or 1-800-565-2209	K7L	\N	\N	\N	\N	https://hars.ca/
429	rho	hiv-aids-resources-and-community-health	HIV/AIDS Resources and Community Health	77 Westmount Road\nGuelph, N1H 5J1	\N	Our goal is to engage, empower and build the capacity of people living with HIV or affected by HIV by offering services that meet people and communities where they are at and responding to their identified needs. ARCH clinical services provides treatment and care to address the many complex health, social and emotional needs for people living with HIV. ARCH clinic also provides Trans Healthcare.\nOther services include:\nAnonymous HIV testing, Hep C testing\nPrEP Clinic\nOutreach Services\nHarm Reduction and Naloxone\nTrans Drop-in (Tuesdays)\nCommunity education and workshops on HIV/AIS, safer sex, harm reduction, trans health\nCounselling and practical support for people living with HIV. ie drives to medical appointments, emergency financial assistance, Vitamins and nutrition programs.	director@archguelph.ca	\N	519-763-2255	N1H	\N	\N	Tom Hammond	\N	https://www.archguelph.ca
430	rho	hiv-and-aids-resource-program-harp-group-health-centre	HIV and AIDS Resource Program (HARP) – Group Health Centre	Sault Ste. Marie	\N	This service is open to the general public. H.A.R.P. does not provide medical care. Staff provide day-to-day education and support for local individuals infected, affected or at risk by HIV/AIDS and related issues. Education and support includes: presentations, workshops, information sessions and conferences on HIV, AIDS, safer sex, and other issues. Outreach services are provided with the help of community partners by developing strategies on harm reduction for safer sex and intravenous drug users.	\N	\N	705-759-5690	\N	\N	\N	\N	\N	https://www.ghc.on.ca/
431	rho	hive-counselling-and-consultancy	Hive Counselling and Consultancy	Toronto , L5L5B8	I can provide secondary assessments for transition-related bottom surgeries		poe@hivecounselling.com	Monday 10am- 8pm EST Tuesday 10am- 8pm EST Wednesday 10am-8pm EST Thursday 10am- 8pm EST	7782003189	L5L	\N	$150	Poe Liberado	\N	https://www.hivecounselling.com/
432	rho	holistic-medical-clinic	Holistic Medical Clinic	2340 Dundas Street West\nToronto, M6P 4A9	\N	Integrated health clinic in West Toronto specializing in RMT, physiotherapy, acupuncture, chiropractic, naturopathy, and psychotherapy. All patients welcome regardless of age, gender identity and expression. We do direct billing whenever possible and work with you on payment plans if needed.	info@holisticmedclinic.ca	\N	(647) 350-6655	M6P	\N	\N	\N	\N	https://holisticmedclinic.ca/
532	rho	leah-keating-at-roncesvalles-psychology-clinic	Leah Keating at Roncesvalles Psychology Clinic	120 Roncesvalles Avenue\nToronto, M6R 2L1	\N	Comprehensive psychological services including therapy/counselling and assessments.	drkeating@roncesvallespsychology.com	\N	416-531-5152	M6R	\N	\N	Leah Keating\nPh.D., C.Psych. (Supervised Practice)	\N	https://roncesvallespsychology.com/
433	rho	hollis-walker-mental-health	Hollis-Walker Mental Health	730 Syndicate Avenue South\nThunder Bay, P7E 1E9	\N	Over a decade of experience: supervised psychological practitioner 2005-2014; registered psychotherapist since 2014. Mental health and psychotherapy for individuals, couples, and groups (adults, adolescents, families); culturally sensitive-towards-competency, evidence-based practice (humanistic, client-centered, cognitive behavioral/CBT, CBT-mindfulness, acceptance-commitment, narrative, emotion-focused, motivational interviewing, process-experiential). Provision of specialized services for identified populations including LGBTQQ2-S (individual psychotherapy, medical and community advocacy, educational and support groups), male survivors of sexual abuse (individual therapy and referrals to community services), Aboriginal, Indigenous, and First Nations peoples (Non-Insured Health Benefits, NIHB & Indian Residential Schools Resolution Health Support Program, IRS HRSP); Ontario motor vehicle accident claims (MVA), and some Employee assistance (EAP) plans. Also serving complex mental health cases (e.g., dual diagnosis, personality disorders, post-traumatic and complex post-traumatic stress disorders, severe major depression, Fetal alcohol spectrum disorders FASD and NARD, gender dysphoria, bi-polar disorder).	holliswalkermentalhealthclinic@gmail.com	\N	807-622-3445	P7E	\N	\N	Laurie Hollis-Walker\nM.A., RP	\N	\N
434	rho	hope-blooms-psychotherapy	Hope Blooms Psychotherapy	2834 Simcoe County Road 124\nDuntroon, L0M 1H0	\N	Individual, Couples and Family Therapy	ahern@hopebloomspsychotherapy.com	Monday-Thursday 12-7pm	5193621016	L0M	\N	150 per individual session\nSliding scale range - $/Hour Minimum: 101.70 Maximum: 230	Amanda Hern\nRegistered Psychotherapist	\N	https://hopebloomspsychotherapy.ca/
435	rho	hope-counselling	Hope Counselling	PO Box 22013, RPO Elmwood Square\nSt Thomas, Ontario\nSt Thomes, N5R6A1	I can provide secondary assessments for transition-related bottom surgeries	I provide telephone and virtual (video call) counselling sessions to individuals who are 14 years and older, who reside in either British Columbia or Ontario. Clients can choose between standard 50 min sessions, and extended 80 min sessions. I welcome clients of all sexual orientations and gender identities, as well as all religions, cultural backgrounds, and past experiences.\nI am trained in a range of different types of therapies, which I draw on to work with each client as an individual, to best support you to reach your goals. Please contact me by phone or email, or visit my website to learn more about me and/or schedule a session.\n	jessica@hope-counselling.ca	Monday -10am - 3pm Tuesday, Wednesday, Thursday - noon - 9pm	778-697-4202	N5R	\N	$90 for 50m session, or $125 for 80min session	Jessica Hope\nMSW	\N	http://hope-counselling.ca
436	rho	hope-for-families-counselling-centre	Hope for Families Counselling Centre	93 Bridgeport Road East\nWaterloo, N2J 2K2	\N	We are passionate about working with you to address your concerns in the way that fits best for you. Strategies need to be relevant to your life situation. We will work together to develop those strategies to move toward the future you want. We have several therapists available who are familiar with trans and LGBTQ+ needs in therapy so we can find a good match for you. We look forward to working with you and have sessions available by phone or video for clients across Ontario.\nWe are also able to access psychiatric assessments remotely with our clients when needed through our partnership with the Psychotherapy Matters Virtual Clinic usually within 2-4 weeks. The psychiatrists are paid by OHIP so there are no additional fees for this.\nWarmly,\nHolly Mathers, Kaytlin Hennigar, Lexi Muniak & Samanta Srijani\nTherapists at Hope for Families Counselling Centre	holly@hopeforfamilies.net	By appointment during weekdays, evenings & weekends.	519-513-9216	N2J	\N	$125+HST/hour	\N	\N	https://www.hopeforfamilies.net
437	rho	houselink-community-programs-toronto	Houselink Community Programs – Toronto	805 Bloor Street West\nToronto, M6G 1L8	\N	Houselink works from a “recovery framework” that emphasizes optimal wellness for all Houselink members.  Houselink’s programs – our social recreation program,  our employment program, the food program and member outreach activities – are all designed to break down isolation and give members control over their own lives.	\N	\N	416-539-0690	M6G	\N	\N	\N	\N	https://www.houselink.on.ca/
438	rho	human-rights-legal-support-centre	Human Rights Legal Support Centre	180 Dundas Street West\nToronto, M5G 1C7	\N	The Human Rights Legal Support Centre provides free legal assistance to people in communities across Ontario who have experienced discrimination contrary to Ontario’s Human Rights Code.	\N	\N	1-866-625-5179	M5G	\N	\N	\N	\N	https://www.hrlsc.on.ca
439	rho	huronia-nurse-practitioner-led-clinic	Huronia Nurse Practitioner-Led Clinic:	3331 4 Line North\nShanty Bay, L0L 2L0	\N	What we offer:\nThe Huronia Nurse Practitioner-Led Clinic provides primary health care services and preventive care to people of all ages. Whether you need to have a complete physical or need to visit us with a minor illness or to manage a chronic or complex illness, the clinic is here for you or your family.\nOur Staff:\nWe are staffed by four Primary Health Care Nurse Practitioners. Our interprofessional team includes nurses, a social worker, a dietitian, a pharmacist, and consulting physicians (visiting the clinic weekly).  We have an administrative support team that includes an Administrative Lead and Administrative Support staff.  Our team works together to meet your health care needs and goals.\nWhat is a Nurse Practitioner?\nNurse Practitioners are nurses that have additional education and licencing to provide primary health care to individuals and families.  They can do complete physical examinations, order diagnostic tests like ultrasounds, X-rays or mammograms, order bloodwork to screen for illness or disease, diagnose illness and disease and prescribe medications necessary for you.\nWhen care is beyond the Nurse Practitioner’s scope to manage, a physician is consulted.  If necessary, you will be seen by both the Nurse Practitioner and the visiting physician.	\N	\N	705-835-7545	L0L	\N	\N	\N	\N	https://www.huronianplc.ca/
440	rho	ian-armstrong-family-physician	Ian Armstrong, Family physician	14 College Street\nToronto, M5G 1K2	\N	Family doctor with a focus in LGBTQ+ individuals and people living with HIV. I provide comprehensive primary care, HIV care, and trans* care (including hormone therapy, surgical assessment, and support around legal aspects of transition).	\N	\N	416-465-3252	M5G	\N	\N	Ian Armstrong\nMD CCFP	\N	https://www.mlmedical.com
441	rho	impower-counselling-services	iMPOWER Counselling Services	186 Albert Street\nLondon, N6A 1M1	\N	A clinical social worker who has been practicing for 23 years in the area of health, disability and trauma. I am a certified EMDR counsellor but in addition to EMDR, I utilize a variety of therapeutic models.	corey@impowercounselling.com	\N	519.868.2499	N6A	\N	\N	Corey Janke\nM.Ed., BSW, RSW	\N	https://www.impowercounselling.com
461	rho	jenny-s-cheng-psychotherapy	Jenny S. Cheng Psychotherapy	421 Bloor Street East\nToronto, M4X 1X6	\N	I assist individual clients over age 16 on navigating the impact of immigration in their lives. This includes identity, sexuality, spirituality, and relationships.	jennyscheng@hushmail.com	Appointments are available the following times: Saturdays 10am-5pm, Wednesdays 5:30pm-8:30pm.	647-974-2083	M4X	\N	$150\nSliding scale range - $/Hour Minimum: 115 Maximum: 150	Jenny Cheng\nRegistered Psychotherapist (Qualifying)	\N	https://www.jennyscheng.ca
443	rho	indulgence-studio-ltd	Indulgence Studio Ltd	1-279 Weber st North\nWaterloo, N2J 3H8	\N	Above And Beyond Your Expectations.\nEstablished in 2006 by Certified Medical Aesthetician Jennifer Thibault, Indulgence Studio Ltd. has been continuously recognized for providing a welcoming, safe, and clean environment for the delivery of aesthetic treatments including Laser Hair Removal and Electrolysis.\nWhether you’re keeping up with your monthly beauty routine, wanting hair removal for the first time, or looking for an inclusive and safe environment, Indulgence Studio always strives to succeed far above and beyond your expectations.\nEveryone is welcome!\nMeet Jennifer Thibault, Certified Medical Aesthetician.\nPreferred Pronouns: she and her\nJennifer – a certified medical aesthetician, graduated from Gina’s College of Aesthetics, and employs over 18 years of experience in the aesthetics industry. Jennifer specializes in hair removal, laser, electrolysis, threading and waxing. Her goal is to support wellness through professional care, and services her clients in a comfortable and inviting space.\nYour Safe And Inclusive Space.\nIndulgence Studio provides hair removal services with no discrimination. Everyone is welcome, regardless of identity or presentation – Indulgence Studio will always go above and beyond your expectations. We even offer wellnesses classes to let you rest and build community in a calm and comfortable environment.\nAs a result of Jennifer’s reputation as a caring and qualified professional, Indulgence Studio has become the service provider of choice for many members of the LGBTQ community – particularly those in the trans community. Indulgence Studio is pleased to address their unique needs, often having clients travel from hundreds of kilometres away for an appointment.\nVisit Us Online To Learn More: www.indulgencestudio.ca	info@indulgencestudio.ca	Please book in for appointments	5194048941	N2J	\N	\N	Jennifer Thibault	\N	https://indulgencestudio.ca
444	rho	information-london	Information London	London	\N	Community services directory website for residents of London and Middlesex County * links to local publications * online versions of the Help Yourself Through Hard Times guide to basic needs services in London and Middlesex, and monthly calendar of meal programs in London * community and social services events calendar * specific service listings for children and families, Immigrants, Newcomers and Ethnocultural Communities, Indigenous Communities, LGBTQ+ communities, people with disabilities, seniors, women and youth	informationlondon@thehealthline.ca	\N	\N	\N	\N	\N	\N	\N	https://www.informationlondon.ca
445	rho	inner-arts-healing-collective	Inner Arts Healing Collective	257 Danforth Avenue\nToronto, M4K 1N2	\N	I use a relational approach to therapy. I will help you to ground yourself and become aware of your habits and beliefs which are holding you back from experiencing joy in your life. We will work with what is present in the here and now. The Gestalt approach is very different from other therapies. I will help you get out of your head and into your body. As a supervised Gestalt Therapist I provide client-led therapy and you will set the pace.\nAs a trans person myself, I have been involved with the LGBTQ2S community for over 20 years.	jamesbrowntherapy@gmail.com	\N	(647) 697-1638	M4K	\N	\N	James Brown\nPsychotherapist (under supervision)	\N	https://www.psychologytoday.com/ca/therapists/james-brown-toronto-on/419427
446	rho	inner-flux-counselling-services	Inner Flux Counselling Services	1350 Wharncliffe Road South\nLondon, N6L 1K3	\N	Inner Flux Counselling Services is a private practice representing a safe, accepting, and affirming space for our LGBTQ+ community.\nPhe Wong (she/her) is owner and sole therapist at Inner Flux. She identifies as a queer POC,  who will also be an advocate alongside you. She strives to ensure you’re seen and heard as your true self.\nYour journey with Phe may include exploration and formation of: sexual identity, gender identity, and/or ethnic/racial identity. Phe is here to help when it comes to concerns around: transition, minority stress, “coming out”, confidence & self-esteem, trauma, shame, anxiety, depression, workplace, and relationships.\nOnline and distance counselling is provided through: Video, Phone, Email, and Instant Messaging, for ages 14+ residing anywhere in Ontario. In-person appointments are held in London, Ontario.\n​Here, you can just be you.	innerflux@therapyemail.com	Monday: Closed Tuesday: 11:00 AM- 2:00 PM Wednesday: 1:00 PM- 9:00 PM Thursday: 1:00 PM- 9:00 PM Friday: 11:00 PM- 7:00 PM Saturday: 11:00- 2:00 PM Sunday: Closed	519-673-4070	N6L	\N	$90-$120 + HST	Phe Wong\nMACP, Registered Psychotherapist (Qualifying	\N	https://www.innerfluxcounselling.com/
447	rho	innerlinks-psychotherapy-and-counselling-services	InnerLinks Psychotherapy and Counselling Services	2351 Royal Windsor Drive\nMississauga, L5J 4S7	\N	Coping with discrimination and oppression, coming out to one’s family, and sorting out a sense of self in the face of social expectations and pressures can lead to higher levels of depression, anxiety, substance use, and other mental health concerns. Innerlinks Psychotherapy and Counselling Services aim to meet the full potential of each individual, couple and family we serve.	info@innerlinks.ca	\N	2898128138	L5J	\N	\N	Ronak Jamali\nM.A., R.P.	\N	https://www.innerlinks.ca
448	rho	insideout-psychological-services	InsideOut Psychological Services	10 Saint Mary Street\nToronto	\N	Provide psychological assessment and treatment services for LGBTQI individuals and couples with a focus on trauma treatment.	kshilson@insideoutpsych.ca	\N	647-404-5568	\N	\N	\N	Kimberley Shilson\nC. Psychological Associate	\N	https://www.insideoutpsych.ca
449	rho	inspiration-transguy	Inspiration Transguy	79 Dover Road\nWelland, L3B 2V1	\N	I offer trainings and public speaking on LGBTQ+ issues with emphasise on the Transgender Community. Since coming out in 2009 as a Transsexual Man, I’ve been doing and offering public speaking/trainings. I’ve spoken locally here in the Niagara Region and as far as Woodstock Ontario and everywhere in between.	\N	\N	289-668-1487	L3B	\N	\N	Michael Sherman\nOwner	\N	https://michaellee88.wixsite.com/sherman
450	rho	integrate-healthcare-collective	Integrate Healthcare Collective	102 Lewis Street\nOttawa, K2P 0S7	\N	Kelsey is a registered physical therapist in downtown Ottawa. She works with a variety of populations to address orthopaedic and pelvic health concerns in a way that emphasizes patient centred, evidence based, hands-on care.	info@integrateottawa.ca	\N	613-230-7891	K2P	\N	\N	Kelsey Drew\nMScPT (Physiotherapist - Pelvic Floor Rehabilitation and Orthopaedic Services)	\N	https://www.integrateottawa.ca/kelsey-drew-bsc-pt
462	rho	jerry-ritt-psychology	Jerry Ritt Psychology	190 Somerset Street West\nOttawa, K2P 0J4	\N	I provide open, welcoming psychotherapy to individuals working through stress, depression, anxiety, and relationship challenges. I work using time-limited or open-ended models tailored to individual need.	Jerry@Hersh.com	\N	6132339669	K2P	\N	\N	JERRY RITT\nMA OACCPP	\N	\N
487	rho	kathy-vance-psychotherapist	Kathy Vance, Psychotherapist	741 Broadview Avenue\nToronto, M4K 3Y3	\N	Mind – Body – Heart – Spirit. I provide a holistic approach to counseling and therapy.\nProfessional, experienced counseling is all about identifying the problem and finding life skill solutions.\nIn a comforting and safe manner, I can help you deal with chronic pain, rehabilitation, personal conflict, psychosocial unbalance, marital challenges, sexuality issues and workplace stress.	kathyvance.dmt@gmail.com	\N	416.465.4121	M4K	\N	\N	Kathy Vance\nCertified Member of OACCPP, Psychotherapy Associate to Dr. Dan Dalton, Clinical Psychologist	\N	https://www.kathyvance.com
451	rho	ivana-kolakovic-registered-psychotherapist	Ivana Kolakovic, Registered Psychotherapist	Toronto, M4K 1N2	\N	I am a Registered Psychotherapist. My approach to therapy is somatic and relational – this simply means that I invite my clients to become curious about their emotions. As these emotions emerge in our contact together, I will gently encourage you to bring them to your awareness and find where you store them within your body. In this way, I will support you to reclaim your innate ways of being in your body by unlearning the harmful beliefs that we adopted while navigating numerous systems of oppression.\nI strive to create a warm and safe space for my clients to explore and uncover themselves. My practice is trans, queer, fat and sex worker affirming and I welcome those who want to explore their sexuality, gender identity, and alternative relationship styles.\nI am also enrolled in the Advanced Somatic Experiencing training for trauma resolution, and I support folks recovering from interpersonal violence, childhood abuse and psychosocal trauma (including war and immigration). Additionally, my work at the Distress Centre provides me with extensive experience in crisis management and suicide prevention.	ivana@ivanatherapy.com	Fridays and Sundays	692603000	M4K	\N	Sliding scale range - $/Hour Minimum: 125 Maximum: 150	Ivana Kolakovic\nMA, Registered Psychotherapist	\N	https://ivanapsychotherapy.com/
452	rho	james-brown-therapy	James Brown Therapy	257 Danforth Avenue\nToronto, M5H 1N2	\N	Gestalt therapy is relational. We will work with what is present in the here and now. Client-led therapy. You will set the pace.\nI offer a free 30 minute consultation.	jamesbrowntherapy@gmail.com	M-F 11am-8pm	647-697-1638	M5H	true	Sliding scale range - $/Hour Minimum: 65 Maximum: 120	James  Brown\nRP (Q)	\N	https://www.psychologytoday.com/ca/therapists/james-brown-toronto-on/419427
453	rho	jamieson-eakin-therapist-intern	Jamieson Eakin, therapist intern	A3 - 20 Floral Parkway\nConcord , L4K 4R1	\N	Jamieson has been working for more than 15 years with diverse and creative community-building projects such as songwriting workshops that draw on emotional experiences for healing and community building through song and dance. His therapy draws on inner strengths and creative expression to manage complex thoughts and emotions. Jamieson has lived experience as part of the 2SLGBTQ+ community and has worked extensively in culturally diverse groups writing, collaborating and performing in theatre and music.\nJamieson’s therapy focuses on the power of thought and intention, psychoeducation, metaphor and ritual to build healthy habits and a balanced life. His approach supports meaning-making, the importance of self-efficacy, and perceived control of experiences in the healing process from both cognitive and social-constructivist perspectives.\nPlease contact me for a free 15-minute consultation and for more information.\nI will be accepting clients for online and in-office appointments. As a practicum student, I will be seeing clients under the supervision of Judy Lui, Registered Psychotherapist.	jamiesone.ysc@gmail.com	Taking Appointments and Consultations for virtual counselling most Sundays through Wednesdays 10 a.m. - 8 p.m. In-person availability on Wednesdays	416-473-3333 ext 9	L4K	\N	Up to $75\nSliding scale range - $/Hour Minimum: 40 Maximum: 75	Jamieson Eakin, therapist intern\nTherapist Intern Registered Psychotherapist (Qualifying)	\N	https://www.yourstorycounselling.com/jamieson-eakin
454	rho	jan-tkachuk-m-a-rp-registered-psychotherapist-clinical-supervisor-and-consultant	Jan Tkachuk, M.A., RP,  Registered Psychotherapist, Clinical Supervisor and Consultant	1404 Balsam Avenue\nPeterborough, K9J 7E3	\N	I provide psychotherapy for individuals, couples, families and groups.  I also provide clinical supervision and consultation for individuals and organizations. My main office is in Peterborough, Ontario. *I also provide virtual services through video and phone for those who prefer or require them.	jan.tkachuk@gmail.com	By appointment only. Hours vary. Please inquire.	705-927-6753	K9J	\N	135 plus HST\nSliding scale range - $/Hour Minimum: 120 Maximum: 135	Jan Tkachuk\nM.A., RP	\N	https://jTtherapy.ca
455	rho	jason-booy-m-d	Jason Booy, M.D.	145 Station Street\nBelleville, K8N 2S9	\N	Family Health Team	doctorbooy@gmail.com	\N	613-771-1910	K8N	\N	\N	Jason Booy\nMD, Resident Physician	\N	\N
456	rho	jay-jonah	Jay Jonah	Toronto, M4C 1K3	\N	Trans-identified therapist offering 2SILGBTQ positive/supportive counselling, in the east end.	jayjonah.therapy@gmail.com	\N	647-517-4012	M4C	\N	\N	Jay Jonah\nMSW, RSW	\N	\N
457	rho	jayne-brown-therapy	Jayne Brown Therapy	344 Dupont Street\nToronto, M5R 1V9	\N	I am a Registered Psychotherapist (RP) and a member of the Canadian Association for Psychodynamic Therapy (CAPT).\nMy approach to psychotherapy is client centered. I meet you where you are right now and provide a safe, non-judgmental supportive space to speak openly about whatever brings you to therapy.\nWe work together to gain greater understanding of the things that are holding you back from living your life the way you want. We work to uncover any negative patterns that are keeping you stuck. As we do so, we focus on your needs, strengths and goals. With increased self awareness comes empowerment.\nI integrate mindfulness-based approaches as well as CBT when you feel it might be helpful to what we are working on.\nI work from an LGBTQ+ positive anti-oppression stance.	jayneloubrown@gmail.com	\N	\N	M5R	\N	\N	Jayne  Brown\nRegistered Psychotherapist	\N	https://jaynebrown.ca
458	rho	jean-tweed-centre-support-for-women-substance-use-and-problem-gambling	Jean Tweed Centre – Support for Women – Substance Use and Problem Gambling	215 Evans Avenue\nToronto, M8Z 1J5	\N	At the Jean Tweed Centre (JTC), we are committed to assisting women who face issues related to substance use and/or problem gambling. We provide a range of programs and services to help women as they begin to make positive lifestyle changes, and offer support to their families with a focus on their young children. We offer an on-site licensed child development centre as well as specialized children’s and parenting programs.	info@jeantweed.com	\N	416-255-7359	M8Z	\N	\N	\N	\N	https://www.jeantweed.com
459	rho	jen-rosa-dupuis-msc-rp	Jen Rosa-Dupuis, MSc., RP	183 Norfolk Street\nGuelph, N1H 4K1	\N	Psychotherapy for individuals, couples, and families.	jen@jenrosadupuis.com	\N	519-835-8918	N1H	\N	\N	Jen  Rosa-Dupuis\nMSc., RP	\N	https://www.jenrosadupuis.com
460	rho	jena-ledson-psychotherapy	Jena Ledson Psychotherapy	120 Carlton Street\nToronto, M5A 4K2	\N	I am trained in both psychodynamic and cognitive behavioral therapy, and work with individuals on a range of issues including anxiety, depression, relationships, addiction and fertility/infertility.\nA successful therapy is marked by emotional growth, more satisfying relationships, and a greater ability to cope with life’s inevitable challenges.\nMy practice consists of individual adults and adolescents over the age of 16. I have experience with clients from all walks of life, with a variety of religious and ethnic backgrounds, sexual orientations and political views.	therapy@jenaledson.com	\N	416-912-5480	M5A	\N	\N	Jena Ledson\nCTP Dipl	\N	https://www.jenaledson.com
484	rho	kathleen-metcalfe-psy-d-c-psych	Kathleen Metcalfe, Psy.D., C.Psych	331 Cooper St, Ste 205, Ottawa, ON K2P 0G5	\N	Individual Psychotherapy	kpmetcalfepsych@gmail.com	\N	6138798368	K2P	\N	\N	\N	\N	https://kpmetcalfe.com/
463	rho	jessica-israelstam-registered-psychotherapist	Jessica Israelstam, Registered Psychotherapist	120 Carlton St.\nToronto, M5A 4K2	\N	To suffer is human – but to grow and heal is also human. In life, you might experience stress, anxiety, self-criticism, anger, difficult transitions or relationships, sleep disturbance, chronic pain/health issues, and other challenges. Sometimes, you might feel so stuck or overwhelmed that your usual coping tools are not quite enough. It can be helpful to seek support from a professional who empowers you to overcome life’s challenges by helping you tap into your inner resources and develop new ones. I am a therapist with years of experience offering such support.	jessica.mindful@gmail.com	Monday to Friday 10 AM to 5:30 PM	6476948939	M5A	\N	$160/hour	Jessica Israelstam\nMEd, RP	\N	https://www.psychologytoday.com/ca/therapists/jessica-israelstam-toronto-on/412569
464	rho	jessica-zhang	Jessica Zhang	Scarborough, M1V2T7	\N	My name is Jessica and I am a Registered Psychotherapist (Qualifying). As a 1st generation Canadian with a Chinese/Jamaican Heritage I understand how all the intersections of our lives shape us as a person. My passion is identity and culture-focused therapy, helping my clients navigate difficult interpersonal dynamics and personal growth within a relationship, family, and cultural dynamics.\nMy approach is warm and very casual, I value connection and being ourselves when we work together. I am open and non-judgemental, basing my sessions on exactly what my client needs at any moment. Sessions are solution-focused, resilience/strength-focused and individualized to fit with my clients, their lifestyle and resources. I explore from a multicultural, psychodynamic approach,  encouraging curiosity as to how our past relationship patterns shape how we behave or think today.\nService is provided via online and phone only.	jessica.zhang1290@gmail.com	Monday to Thursday: 10:00 a.m. - 6:00 p.m. Friday: 9:00 a.m. - 1:00 p.m.	6472971290	M1V	\N	$135.60 (tax included)	Jessica Zhang\nRegistered Psychotherapist (Qualifying)	\N	https://www.jessicazhangcounselling.com/
465	rho	jessie-bawden	Jessie Bawden	\N	\N	Nurse Practitioner at Women’s College Hospital in Toronto Ontario.\nLactation consultant service privately to launch (Sept 2019)	\N	\N	\N	\N	\N	\N	\N	\N	\N
466	rho	jewish-family-services	Jewish Family Services	2255 Carling Avenue\nOttawa, K2B 1A6	\N	Many of us experience some form of emotional difficulty, stress, relationship issue, or conflict. Choosing a therapist who is right for you and has the expertise in the areas of concern to you and your family is crucial.\nOur trained and experienced counsellors at The Counselling Group (TCG) provide confidential counselling to children, adolescents, and adults. We offer individual, couple, family, and group counselling tailored to support you in identifying and reaching your achievable goals.\nOur counsellors are caring and empathetic, each one selected for their clinical excellence and dedication. Their work with clients from all orientations, ethnicities, and cultural backgrounds, reflects The Counselling Group’s respect for difference and diversity.\nOur counsellors utilize a variety of theoretical approaches in their work. They have a holistic, client-centred approach to counselling. All TCG counsellors are registered members of their professional associations and have Masters Degrees in counselling, social work, clinical psychology, or other related disciplines.\nEvery counsellor at TCG is committed to ongoing learning. This is demonstrated by their interest in new research and ongoing professional development, as well as their commitment to teaching and training graduate students and other professionals.\nAll services offered by counsellors at The Counselling Group are provided with strict respect for confidentiality. The privacy of clients is held in strict confidence, complying with privacy and other applicable legislation.	mnerses@jfsottawa.com	\N	(613)722-2225 ext.410	K2B	\N	\N	\N	\N	https://www.jfsottawa.com/TheCounsellingGroup/site/aboutus.html
467	rho	jlb-massage-therapy	JLB Massage Therapy	700 King Street\nLondon, N5W 0A6	\N	At JLB Massage Therapy we provide deep tissue massages, sports massages, prenatal massages and even hot stone therapy. We take the time to listen to our clients. This is what sets us apart from our competition. If you are interested in another type of massage, do not hesitant to ask us where to find a place, as we partner up with some massage wellness centers to ensure our clients receive the correct treatment. We are located in London, Ontario and open from Monday to Friday from 9am to 5pm. Schedule with one of our expert massage therapists today!	jess@jlbmassage.com	\N	2264001818	N5W	\N	\N	Jessica Brown	\N	https://www.jlbmassage.com
468	rho	joanne-darrell-herbert-counsellor	Joanne Darrell Herbert Counsellor	39 Alvin Avenue\nToronto, M4T 2A7	\N	Joanne is a psychotherapist with a master’s degree in Counselling Psychology from The University of British Columbia. She is registered with the Canadian Counselling and Psychotherapy Association. Joanne has been working with teens, parents, teachers and administrators for over twelve years. In her private practice, Joanne especially enjoys helping couples to build stronger relationships and supporting families as they navigate inevitable growing pains.	joanne@joannedarrellherbert.com	\N	6474547446	M4T	\N	\N	Joanne Darrell Herbert\nM.Ed., CCC	\N	https://www.joannedarrellherbert.com
469	rho	joe-chan-optometrist	Joe Chan Optometrist	101 Queensway West\nMississauga, L5B 2P7	\N	Comprehensive eye health and vision assessments; contact lens fittings; spectacle dispensary; laser vision correction comanagement; diabetic assessments	allegro@interlog.com	\N	905-848-2020	L5B	\N	\N	Joe Chan\nDoctor of Optometry	\N	https://www.queenswayoptometric.com
470	rho	john-larsson-counselling-services	John Larsson Counselling Services	2255B Queen St East\nUnit 501\nToronto, ON ,  M4E 1G3	\N		jlarsson.ca@gmail.com	I do phone or video counselling only. Hours are negotiable.	289-277-6554	M4E	\N	Sliding scale range - $/Hour Minimum: 120 Maximum: 150	John Larsson\nRSW	\N	https://www.johnlarsson.ca
471	rho	jonathan-huber-md	Jonathan Huber, MD	\N	\N	Gynecologist offering gender-affirming hormone therapy initiation and follow-up for trans and gender-diverse patients.	\N	\N	\N	\N	\N	\N	\N	\N	\N
472	rho	josh-goodbaum-therapy-for-adolescents-and-young-adults	Josh Goodbaum – Therapy for Adolescents and Young Adults	191 Eglinton Avenue East\nToronto, M4P 1K1	\N	Therapy for adolescents and young adults who are dealing with stress, depression, low self-esteem, anxiety, family conflict, self-injury and relationship issues. I enjoy working with (and learning from) diverse clientele, and I have experience and training in supporting lesbian, gay, bisexual, transgender and queer (LGBTQ) youth. I work from an affirming, anti-oppressive and inclusive perspective.	joshgoodbaum@gmail.com	\N	416-795-4850	M4P	\N	\N	Josh Goodbaum\nMSW, RSW	\N	https://www.joshgoodbaum.com
485	rho	kathleen-pratt-msw-rsw-certified-yoga-instructor	Kathleen Pratt, MSW, RSW, Certified Yoga Instructor	4 Wilfred Crescent East\nKingston, K7K 7G9	\N		kathleen@kathleenpratt.ca	Daytime, evening or weekend classes by appointment	613-777-5207	K7K	\N	\N	Kathleen Pratt\nBA, BSW, MSW, RSW, Yoga Teacher Training (200 hour)	\N	https://www.kathleenpratt.ca/
508	rho	kingston-health-sciences-centre	Kingston Health Sciences Centre	166 Brock Street\nKingston, K7L 3E2	\N	We provide free assessment and counselling services for LGBTQ kids, youth and their families in the South Eastern Ontario region. Referral from physician or other service provider needed.	karen.gillis@kingstonhsc.ca	\N	613-544-3400 ext. 3582	K7L	\N	\N	Karen Gillis\nMA, MSW, RSW	\N	\N
473	rho	julia-garro-registered-massage-therapist	Julia Garro Registered Massage Therapist	135 Victoria Avenue\nBelleville, K8N 2B1	\N	I’m a registered massage therapist with a range of clinical experience, including working with folks who have had breast/chest surgeries, abdominal surgeries/chronic pelvic pain and people living with MS. I’m a queer cissexual woman working to provide therapeutic massage in a way that fully respects the sexual & gender identities of those that I work with.\nAs a registered massage therapist I have a great deal of knowledge about the human body and how it works. But you are the expert on your own body, and I honour that. Together we will learn how massage therapy can work best for you.	juliagarrormt@gmail.com	\N	(613) 554-8888	K8N	\N	\N	Julia Garro\nBSc, RMT	\N	http://sc-clinic.com/clinic/belleville/
474	rho	julia-macarthur-counselling	Julia MacArthur Counselling	68 Algoma Street North\nSuite 102\nThunder Bay, P7A4Z3	\N	Counselling and psychotherapy in-person and virtual with expertise in working with 2SLGBTQ+ people, providing affirming care. Working with youth and adults, individuals, couples, and caregivers. Provision of evidence-informed treatment for mental health issues, trauma, relationships, and working with identities. Approved provider with NIHB.	julia@juliamacarthur.com	Monday to Friday 8:30-4:30	(807) 709-6377	P7A	\N	Also provides sessions covered by NIHB.	Julia MacArthur, MSW, RSW	\N	https://www.juliamacarthur.com
475	rho	kaitlyn-hillier-counselling-and-psychotherapy-services	Kaitlyn Hillier Counselling and Psychotherapy Services	29 Wellington Street North\nWoodstock, N4S 6P4	\N	Counselling and Psychotherapy Services	khillier1985@live.com	Monday to Friday - 12pm-8pm	2269806203	N4S	\N	125-140	Kaitlyn Hillier\nMCP, CCC, RP	\N	https://www.psychologytoday.com/ca/therapists/kaitlyn-hillier-woodstock-on/294664
476	rho	kama-lee-jackson-psychotherapy	Kama Lee Jackson Psychotherapy	Toronto, M4E 3K6	\N	I provide psychotherapy services to teens and adults of all genders and sexualities to help untangle the messy feelings and thoughts that might be weighing you down, getting in the way, and holding you back from being your best you. Together we’ll identify what you want and how to get you there.	hello@kamaleejackson.com	Please see website or contact by e-mail.	n/a	M4E	\N	\N	gender-affirming and trauma-informed psychotherapy\nMACP, BaHSc (Midwifery), BaJ	\N	https://www.kamaleejackson.com/
477	rho	kanata-med-team-clinic	Kanata Med Team Clinic	99 Kakulu Road\nOttawa, K2L 3C8	\N	Med-Team Clinic is a well established walk-in and family practice clinic in Kanata South.	\N	\N	\N	K2L	\N	\N	Dr. Austin Zygmunt\nMD, CCFP	\N	https://www.facebook.com/MedTeamClinic/
478	rho	kanata-south-professional-services	Kanata South Professional Services	120 Terence Matthews Crescent\nOttawa, K2M 2B2	\N	Psychology practice: assessment and treatment for children, adolescents, and adults	owen.helmkay@rogers.com	\N	613-435-9330	K2M	\N	\N	Owen Helmkay\nPhD., C.Psych.	\N	https://www.kanatasouthpros.com
479	rho	kanata-south-professional-services-2	Kanata South Professional Services	120 Terence Matthews Crescent	\N	See website for further information.	owen.helmkay@rogers.com	\N	613 435 9330	\N	\N	\N	Owen Helmkay\nPhD., C.Psych.	\N	https://www.kanatasouthpros.com
480	rho	kane-chamberlain-registered-psychotherapist	Kane Chamberlain Registered Psychotherapist	907 Catskill Drive\nOshawa, L1J 8J9	\N	Kane is Bear Clan of Algonquin/French descent from the Antoine First Nation, descendants of the historic Matawasi`bi ani`cena`bi (Mouth-of-the-River People). His Native name is Kiwedin-nimbi (Northern Thunder). He identifies as Two-Spirited. Traditionally, Two-Spirited people were seen to have special gifts and thus were healers, counsellors, and leaders of ceremony. Kane’s Native Elders honored him with an Eagle Feather in 1998 for leadership and one in 1990 for promoting healing.By providing a warm and trusting space for individuals to explore and express their problems, Kane facilitates emotional acceptance, self- knowledge, and growth. The process provides an opportunity for individuals to work towards meaningful and lasting change, fostering hope for the future\nKane is covered by NIHB for those with Indigenous Status and various health plans (please confirm with your health benefit provider that they cover “registered psychotherapists.”	office.chamberlain@yahoo.ca	\N	905-979-7911	L1J	\N	\N	Kane (Liz) Chamberlain\nMACP, RP004027	\N	https://www.chamberlainandassociates.ca
481	rho	karen-kugelmass-counselling	Karen kugelmass counselling	701 Sheppard Avenue W\nToronto, M3h2s7	\N	Counselling / Therapy	karen.kugelmass@gmail.com	Flexible	416-898-9939	\N	\N	Sliding scale range - $/Hour Minimum: 80 Maximum: 120	Karen	\N	http://www.karenkugelmass.com
482	rho	karma-ivf	KARMA IVF	435 The Boardwalk, Suite 508\nMedical Centre 2\nWaterloo, N2T 0C2	\N	KARMA is Kitchener / Waterloo’s first full-service fertility clinic.\nWith over 20 years of experience in fertility, Dr. Judith Campanaro and her team have helped thousands of people in the Waterloo Region become parents.\nWe offer all services on-site, including semen analysis, sperm cryopreservation, egg (oocyte) preservation, IVF, reciprocal IVF, egg donation, sperm donation, and other fertility and reproductive services.\nSome services are funded through the Ontario Fertility Program (accessible to all genders, orientations, family types, etc.) and some services are self-pay.	info@karmaobgyn.com	Monday to Friday: 7 a.m. to 3 p.m. Weekends and Holidays: 7:30 a.m. to 10 a.m.	5195700090	N2T	\N	Varies depending on treatment needed.	Dr Judith Campanaro\nM.D., F.R.C.S.	\N	https://www.karmaobgyn.com
483	rho	kate-welsh-disability-affirming-counselor	Kate Welsh – Disability Affirming Counselor	Toronto, M6H 2Z2	\N	As a disabled person who has worked in the mental health and the social service sector for over ten years, I know that there is a lack of mental health support for sick/disabled folks and the general care that does exist is not disability competent. Ableism is a profound barrier to accessing the life we want as disabled and sick folks, ableism runs through all parts of our lives – medical ableism from doctors, lack of support for our hopes and dreams from family because “you’re too disabled to do that,” physical barriers to our classrooms or workplaces and internalized ableism that comes from ourselves when we start believing what society is telling us. Internalized ableism can make us feel not worthy of love, support, work, school, relationships, pets, friends and a purpose in life.\nI offer mental health support to people with disabilities and chronic illnesses. As we all know our wellbeing is a combination of all parts of our lives including our mental health. Often mental health takes a backseat when managing chronic illness or disability, but it needs attention too.\nI work with a healing justice and trauma informed approach. I acknowledge how various oppressions and identities intersect and can affect our wellbeing. I see my role as a counselor as an ally in supporting you in your own work. I am here to witness your growth, to help you notice your own behaviors and patterns and to hold space for you to feel and process. I want you to be able to connect to your own values and dreams, to be empowered to know what is you and what society is “expecting” of you.\nIn addition to supporting disabled and/or chronically ill folks I work with parents, siblings and caretakers.  As an adult, I understand the amount of stress that having a sick child can put on parents, as well as siblings. I offer a listening and empathic place where you can get support for your unique needs as well. Disability doesn’t just affect the individual, it can affect folks around us too.\nAll of the counseling is done over video chat. I offer a free 20 minute “meet and greet” to see if we would be a good fit. Sessions are sliding scale $50-75. I work outside of the medical model and therefore do not qualify for insurance reimbursements.	info@katewelsh.ca	See schedule online - Evening and weekend times available	n/a	M6H	\N	Sliding scale range - $/Hour Minimum: 50 Maximum: 75	Kate Welsh\nM.Ed - Social Justice Education	\N	https://www.katewelsh.ca/counseling
488	rho	katie-dunnigan-registered-psychotherapist	Katie Dunnigan – Registered Psychotherapist	Cambridge	\N	I guide people through a healing process that helps to explore who they are on the deepest level. Instead of battling your problems with coping strategies, positive thinking, or willpower, we will focus on nurturing your true self by quieting the mind, strengthening intuition, and opening awareness. Through this type of inner work, people can experience peace of mind, joy, creativity, inner strength, sense of purpose, and connection to self. Other benefits include the ability to relax deeply, to process emotions, to learn from life experiences, and to move through the world in a way that works for you.\nI work with people who experience a wide range of symptoms, including eating disorders, anxiety, depression, addictions, and stress. As a queer person, I understand the need to feel safe and comfortable as you explore all parts of yourself. Feel free to contact me by phone, text, or email to ask questions or book an appointment. I offer free 15-minute phone consults to discuss your concerns and share more about how I work.	katiedunnigantherapy@gmail.com	\N	416-543-5115	\N	\N	\N	Katie Dunnigan\nRegistered Psychotherapist, Master of Arts (Counselling Psychology)	\N	https://www.katiedunnigan.com
489	rho	kawartha-sexual-assult-centre	Kawartha Sexual Assult Centre	411 Water Street\nPeterborough, K9H 3L9	\N	Kawartha Sexual Assault Centre is a not-for-profit organization that is dedicated to supporting those affected by sexual violence as well as raising public awareness around the need to better address conditions, laws and attitudes that contribute to ongoing cycles of violence. Our catchment area includes the city of Peterborough, the counties of Peterborough, Northumberland, Haliburton and the City of Kawartha Lakes\nThrough qualified trauma specialists, men and women survivors of past and recent sexual assault receive professional, well-developed and responsive, healing support. Throughout the trauma recovery cycle, clients are provided with wrap-around services including individual and group counselling, advocacy, accompaniment, referrals, and support to their partners, families and friends.	\N	\N	(705) 741- 0260	K9H	\N	\N	\N	\N	https://www.kawarthasexualassaultcentre.com/
490	rho	kelly-kirkham-psychotherapy	Kelly Kirkham Psychotherapy	\N	\N	Kelly Kirkham is a non-binary Registered Psychotherapist and a Psycho-Spiritual Therapist in private practice in Uptown Waterloo, Ontario. Kelly is a member of the College of Registered Psychotherapists of Ontario (#007789), as well as an associate member of the Canadian Association for Spiritual Care, specializing in mental health. Kelly also brings to this practice, education and training as a child and youth worker, 30 years of teaching, supervision and research in elementary education, 16 years of experience in therapeutically supporting those who have lived through family violence, as well as experience in palliative care.\nKelly engages in a trauma- and violence-informed, strength-based, integrative, collaborative, and client-centred practice. They bring the wholeness of themself and their fully attentive presence into the therapeutic space and moment with others in order to invite the development of a trusting, therapeutic relationship in which connection and understanding can take root. This is a space in which all are welcome, and one in which the fullness of a person, mind, body and spirit, is supported through exploration, growth and healing. Kelly uses therapeutic techniques drawn from a wide range of models and tailors their approach to meet the expressed needs and worldview of each individual client.\nKelly sits with individuals, with couples, and with families at their office in Uptown Waterloo.	kellykirkham@gmail.com	\N	519-721-5974	\N	\N	\N	Kelly Kirkham\nMA, RP	\N	https://kellykirkham.net
491	rho	kelsey-dugas	Kelsey Dugas	602 Wellington Street East\nSault Ste. Marie, P6A 2M5	\N	Counselling services	Kdugas.sw@gmail.com	\N	7059411173	P6A	\N	\N	Kelsey Dugas\nMSW., RSW.	\N	https://www.kelseydugas.com
492	rho	kelsey-dugas-2	Kelsey Dugas	\N	\N	Counselling services	Kdugas.sw@gmail.com	\N	7059411173	\N	\N	\N	Kelsey Dugas\nMSW., RSW.	\N	https://www.kelseydugas.com
493	rho	kemptville-youth-centre	Kemptville Youth Centre	5 Oxford Street West\nKemptville, K0G 1J0	\N	The Kemptville Youth Centre is a non-profit organization with a mission to engage youth in making positive life choices in a socially accepting environment to reach their full potential as responsible productive citizens.\nNot only do we provide a safe and fun place for our Youth to hang out, but as a member of the community, we look for other ways to give back as well. We:\nOffer prom dresses and suits for graduating students.\nAssist parents of teens by offering support and referrals.\nPoint to helpful resources.\nRent our facility for community events.\nPromote and support businesses that partner with us.	ambercaul.fox@gmail.com	\N	613-258-5212	K0G	\N	\N	Amber Fox	\N	\N
494	rho	kennedy-mclean-counselling-and-psychotherapy-services	Kennedy McLean Counselling And Psychotherapy Services	Toronto, M9C 5K6	\N	Individual Counselling\nSubstance Abuse Counselling\nCouples/Relationship Therapy\nFamily Therapy	info@kennedymclean.com	Mon-Fri: 9 a.m. to 8 p.m. Weekends: 10 a.m. to3 p.m.	4167025419	M9C	\N	\N	\N	\N	https://www.kennedymclean.com
495	rho	kennedy-medical-centre	Kennedy Medical Centre	4A - 2 Kennedy Road South\nBrampton, L6W 3E1	\N	Trans Health\nWomen’s and Children’s Health	kmcbrampton@gmail.com	M-F 9-3 schedule varies weekly as provider works in hospital settings as well	9054594385	L6W	\N	\N	Lopita Banerjee\nMSc MD FCFP	\N	https://www.kmcbrampton.com/
496	rho	kensington-midwives	Kensington Midwives	340 College Street\nToronto, L0J 1C0	\N	We provide primary care during pregnancy as well as care for parents and babies for six weeks after the birth. We try to foster an equitable, anti-oppressive environment that is welcoming, safe, accessible and inclusive to all of our clients and midwives.	kmw@kensingtonmidwives.ca	\N	416 928 9777	L0J	\N	\N	\N	\N	https://www.kensingtonmidwives.ca
497	rho	kensington-midwives-2	Kensington Midwives	\N	\N	We provide primary care during pregnancy as well as care for parents and babies for six weeks after the birth. We try to foster an equitable, anti-oppressive environment that is welcoming, safe, accessible and inclusive to all of our clients and midwives.	kmw@kensingtonmidwives.ca	\N	416 928 9777	\N	\N	\N	\N	\N	https://www.kensingtonmidwives.ca
498	rho	kent-to-m-d	Kent To, M.D.	Toronto	\N	General family practice\nHIV/AIDS health care\nMen’s health\nSexual health	tok@smh.ca	\N	416-867-7428	\N	\N	\N	Kent To\nMD	\N	https://www.stmichaelshospital.com
509	rho	kintsu-counselling-services	Kintsu Counselling Services	120 Clarence Street\nKingston, K7L 1X4	\N	I provide psychotherapy specializing in trauma. I also have the pleasure of supporting those who experience anxiety, depression, and low self-worth. I acknowledge and celebrate the strengths and fragility of the human spirit. I provide a trauma-informed and anti-oppressive practice. In addition, I spend time strengthening the therapeutic relationship as I believe it is the most effective tool for change. I have experience supporting individuals with a variety of genders, sexualities, and cultural backgrounds. I am committed to providing services that respect the dignity and value of all people.	dawn@kintsucounselling.com	Mon, Tues, Thurs, Fri 9-5 Some evening and weekend appointments are available each month for those who are unable to meet during weekday hours.	1-844-237-3267 Ext. 1	K7L	\N	\N	Dawn Godfrey\nRegistered Psychotherapist, M.A	\N	https://www.kintsucounselling.com/
499	rho	kerry-lin-mcguire-msw-rsw-psychotherapist	Kerry-Lin McGuire, MSW, RSW, Psychotherapist	Ottawa, K1A 0A1	\N	I am a queer therapist who is personable, approachable, and flexible. I will work with you to establish your goals for therapy, and help to process the issues that come up for you. My approach is seated in a place of kindness and empathy, and I see myself as your advocate. I sometimes use humour during our sessions to reduce stress, and provide relatable examples so that you can integrate therapeutic skills into your life.\nI use evidence-based therapeutic approaches like Cognitive Behavioral Therapy (CBT), Acceptance and Commitment Therapy (ACT), and Mindfulness. My approach is holistic, in that I consider all aspects of your life in order to bring fresh perspective on the challenges you are facing.\nI have varied life experience which enables me to relate to different kinds of people and their life stages and meet them where they are.\nI specialize in individuals who are experiencing anxiety, low mood, low self-esteem, work stress, life transitions, interpersonal difficulty, and trauma. I welcome folks from the LGBTQIA+ community, racialized folks, and anyone that sees themselves as other.\nI am currently offering therapy online, either through video or by telephone, based on your preference. I am available to all Ontario residents. Don’t hesitate to give me a call, or email if you have any questions. You can also create an account here and self-book:\nhttps://oab.owlpractice.ca/klm\nBe well!\n*I can provide secondary assessments for transition-related bottom surgeries as of May 2022*	klmcguiretherapy@gmail.com	Mondays 9am-4pm Thursdays 9am-4pm Fridays 9am-4pm *exceptions can be made if necessary	(613) 704-4738	K1A	\N	150	Therapy\nMSW, RSW	\N	https://www.psychologytoday.com/profile/941434
500	rho	kersty-franklin-psychotherapy-practice	Kersty Franklin Psychotherapy Practice	\N	\N	Clinical counseling and Psychotherapy	\N	\N	\N	\N	\N	\N	\N	\N	\N
501	rho	kevin-joubert-acupuncture	Kevin Joubert Acupuncture	Toronto	\N	Traditional Chinese Medicine acupuncture that integrates sound understanding of energetic systems, western medical knowledge and intuitional healing. I use a variety of modalities that complement acupuncture, including fire cupping, guasha, tuina massage, food energetics and moxibustion. Every client is treated with respect and every treatment is rooted in compassion.	info@kevinjoubert.com	\N	6478011785	\N	\N	\N	Kevin Joubert\nRegistered Acupuncturist with the College of Chinese Medicine Practitioners and Acupuncturist of Ontario	\N	https://www.kevinjoubert.com
502	rho	keyes-to-health	Keyes to Health	750 Oklahoma Drive\nPickering, L1W 3G9	\N	Chiropractic, Acupuncture, RMT, Custom Orthotics, compression wear.	keyestohealth@bellnet.ca	\N	9054201248	L1W	\N	\N	Dr. Warren Keyes\nDoctor of Chiropractic	\N	https://www.keyestohealth.com
503	rho	khalili-zambri-and-associates-naturopathic-healthcare	Khalili Zambri and Associates Naturopathic Healthcare	1333 Sheppard Avenue East\nToronto, M2J 1V1	\N	Naturopathic Medicine, Classical Homeopathy, Clinical Nutrition, Botanical Medicine	contact@khalilizambri.com	\N	4167122796	M2J	\N	\N	Kimberlee Blyden-Taylor\nND	\N	https://www.khalilizambri.com
504	rho	kim-goode-rmt	Kim Goode RMT	489 College St Suite 206\nToronto, M6G 1A5	\N	Smooth Transitionz is a program catered to providing pre- and post-surgical care for individuals who are undergoing/pursuing gender affirming surgery. Individuals who experience gender incongruence (GI) typically fall through cracks in the medical system when attempting to regain quality of life after surgery. Including massage therapy into the circle of care during this rehabilitation period decreases inflammation and swelling, decreases pain, increases range of motion, and improves scar mobility and aesthetics. Many individuals are living with the joy of finally having the gender affirming body they desire, however, are suffering with the unnecessary restrictions that exist with post-surgical trauma.\nSmooth Transitionz aims to bridge the gap from hospital to home and reduce/eliminate the discomforts and restrictions that are unique to this community. The high-quality and trauma informed services offered extend to all states of chest-specific concerns including: binding, top-surgery and breast augmentation. Compassionate pricing options available at Toronto Community Massage & Wellness!\nhttps://kindredtherapy.janeapp.com/locations/toronto-community-massage-and-wellness/book	kimgoodermt@gmail.com	Sunday 11 a.m. - 6 p.m. Monday 2 p.m. - 9 p.m.	9054093660	M6G	\N	Sliding scale range - $/Hour Minimum: 56.50 Maximum: 135	Registered Massage Therapy\nRMT BA	\N	https://kindredtherapy.janeapp.com/locations/toronto-community-massage-and-wellness/book
505	rho	kind-therapy-ottawa	Kind Therapy Ottawa	210 Centrum Boulevard\nOttawa, K1E 3V7	\N	I have a special interest in supporting members of the LGBTQQIP2SA community and their family members. My goal is to help you live a life that is worth celebrating! So wether you are struggling to come out, questioning your sexual, romantic, or gender identity, transitioning, depress, lonely, isolated, anxious, stress, struggling with relationship (s), starting a new family or having infertility problem, among others I am here for you. And if you are seeking therapy for reasons not directly related to your sexuality or your gender, it’s still important to talk to someone who understands your relationships and your identity!\nI have significant personal and professional experience with LGBTQQIP2SA community in all its diversity. Before opening my own private practice, I worked at Ottawa University where LGBTQQIP2SA folks made up a sizeable portion of my clients. I also generated and ran Ottawa University rainbow support group. I continue to educate myself about the diverse needs of the LGBTQQIP2SA communities. I recognize and affirm that there is no single experience or identity that defines these communities, my goal is to learn about YOU and help you understand your unique situation.	kindtherapyottawa@gmail.com	\N	613-209-4052	K1E	\N	\N	Emely Alcina\nRegister Psychotherapist	\N	https://www.kindtherapyottawa.com
506	rho	kingston-community-health-centres	Kingston Community Health Centres	263 Weller Avenue\nKingston, K7K 2V4	\N	We are the new Trans Health in Kingston, ON. Our clinic can see anyone from the South Eastern Local Integrated Health Network. The clinic consists of Heather Geddes, nurse practitioner and Kaili Gabriel, social work. We are affiliated with the Gender Clinic at Kingston Health Sciences Centre.\nServices Provided:\nHormone Therapy\nSurgical referrals\nCounseling\nProvide in-service presentations and education to primary care providers.\nCurrently you need a referral from a doctor; however, we are currently working on how to make our service as accessible as possible.	transhealth@kchc.ca	\N	(613) 542-2949	K7K	\N	\N	Kaili Gabriel\nMSW, RSW	\N	https://www.kchc.ca/home/
507	rho	kingston-family-health-team	Kingston Family Health Team	797 Princess Street\nKingston, K7L 1G1	\N	I am a full-time family physician in Kingston, with the Kingston Family Health Team. My practice is mid-town Kingston (797 Princess Street) and I have an LGBTQ-friendly practice with experience working with transgendered patients. I have training in completing referrals & forms pertaining to accessing gender-affirming surgical procedures as well.	\N	\N	613-650-5471	K7L	\N	\N	Deanna Russell\nMD, CCFP(EM)	\N	https://kFHN.ca
531	rho	leah-keating-at-dr-carmen-weiss-associates	Leah Keating at Dr. Carmen Weiss & Associates	5195 Harvester Road\nBurlington, L7L 6E9	\N	Comprehensive psychological services including therapy/ counselling and assessments	intake@drcarmenweiss.ca	\N	289-427-5577	L7L	\N	\N	Laura Turnbull\nPh.D., C.Psych. (Supervised Practice)	\N	https://drcarmenweiss.ca/
510	rho	kitchener-downtown-community-health-centre	Kitchener Downtown Community Health Centre	44 Francis Street South\nKitchener, N2G 2A2	\N	Our Primary Care team consists of Physicians, Nurse Practitioners and Registered Nurses.  Clients see the most appropriate provider for the health issues and concerns.\nIn general an appointment with a Physician or Nurse Practitioner is a half an hour in length. Services include  diagnosis, treatment, education, referral and follow-up on health issues. Some of the specific services are complete health check-ups, well-baby checks, and immunizations. These are provided on-site at 44 Francis St. South to rostered clients only. Appointments are required.\nOur Allied Health team includes:\nAppointments are required for our Allied Health Team services.\nOur Community Health Worker/Advocate provides individual advocacy for clients who need support/assistance in dealing with community agencies or who need information about community services and supports\nKDCHC also runs many programs including: managing chronic pain, healthy eating, seniors programming and more.	mail@kdchc.org	\N	Phone (519)745-4404	N2G	\N	\N	\N	\N	https://kdchc.org/
511	rho	kizuki-works-counselling-and-psychotherapy	Kizuki Works Counselling and Psychotherapy	Toronto, M5R3J1	\N	Psychotherapy and counselling services for Asian and other racialized and/or immigrant LGBTQ+ folks.	info@kizukiworks.ca	Weekdays, 11 AM - 7 PM	437-747-6429	M5R	\N	133\nSliding scale range - $/Hour Minimum: 65 Maximum: 133	Dai Kojima\nPhD, RP (Qualifying)	\N	https://kizukiworks.ca
512	rho	kris-pryke-psychologist	Kris Pryke Psychologist	238 King Street South\nWaterloo, N2J 1R4	\N	Therapeutic services for a variety of mental health concerns.\nLGBTQ positive.	kris_pryke@rogers.com	\N	519 496-9555	N2J	\N	\N	Kris Pryke\nPhD	\N	https://drkrispryke.com
513	rho	krista-roesler-psychotherapy	Krista Roesler Psychotherapy	20 Eglinton Avenue East\nToronto, M4P 1A6	\N	I have a Masters degree in psychology and I am extensively trained by the Adler Institute (OISE/UofT) as a life coach. My background allows me to recognize and change harmful thought and behaviour patterns.\nAs my client, I will be right there beside you helping you create a positive and healthy lifestyle. My extensive life coach training and my Masters degree in psychology have taught me to not only to support and listen to you but also provide you with practical solutions and strategies to address these feelings/ let them go and move on.\nAre you tired of just being listened to by counselors and ready for some practical strategies to move on with your life?	info@psychcompany.com	\N	1-888-441-9141	M4P	\N	\N	Krista Roesler	\N	https://www.kristaroesler.com
514	rho	kristie-brassard-msw-rsw-online-therapy-in-ontario	Kristie Brassard MSW, RSW – Online Therapy in Ontario	Toronto, Ontario, M5C 2G5	\N	Kristie (she/her) is a queer identified Registered Social Worker, therapist & guide who offers a virtual space for you to share your concerns, and to work on developing and reaching your goals. Greeting you with authenticity, compassion, non-judgment and from time-to-time a little humour, Kristie can support you as you explore your struggles, strengths, and as you process distressing emotions. Using evidence-based therapeutic interventions, Kristie will provide guidance and encouragement as you explore patterns and perspectives, as well as practice healthier communication and coping skills.\nShe often works with clients who are overwhelmed with emotions, struggling to manage stress, feeling disconnected or unsatisfied with various aspects of their lives (i.e. relationships, health, career, social life, self-esteem, etc.) and with clients who are trying to heal from past hurts , as well as engage in personal growth. Kristie does not believe in a “one size fits all” approach and uses various theories, experiences and intuition to serve her clients well. She also works from an anti-oppressive and trauma- informed lens.\nKristie offers virtual therapy sessions for residents of Ontario (aged 17+). All genders, sexual orientations, spiritual and cultural backgrounds are welcome.\nInterventions drawn from:\nCognitive Behavioural Therapy, Dialectical Behavioural Therapy, Acceptance and Commitment Therapy, The Gottman Method, Transpersonal Psychology, Internal Family Systems, and more…\nCommonly addressed issues:\n	hello@kristiebrassard.com	Mondays: 1 p.m. - 8 p.m. Tuesdays: 1 p.m. - 8 p.m. Wednesdays: Closed Thursdays: 10 a.m. - 5 p.m. Fridays: 10 a.m. - 5 p.m.	1-844-612-6505	M5C	true	$135 per session for individuals; $155 per session for couples	Kristie Brassard\nMSW, RSW	\N	https://www.kristiebrassard.com
515	rho	kurtiss-trowbridge-counsellor	Kurtiss Trowbridge- Counsellor	179 Carlton Street\nToronto, M5A 2K3	\N	Providing safe and compassionate counselling to those who identify as LGBTQ. Works from an anti-oppressive, anti-racist, non-discrimination framework.	kurtiss@allofyou.ca	\N	416-558-4681	M5A	\N	\N	Kurtiss  Trowbridge\nMA Counselling Psych	\N	https://therapists.psychologytoday.com/rms/prof_detail.php?profid=273931&sid=1468881032.1558_19061&city=Toronto&state=ON&spec=172&tr=ResultsName
516	rho	kw-counselling-services	KW Counselling Services	480 Charles Street East\nKitchener, N2G 4K5	\N	OK2BME is a set of support services for lesbian, gay, bisexual, transgender, queer/questioning children, youth, and their families in Waterloo Region. Services include: LGBTQ2-positive individual and family counselling, LGBTQ2+ recreational and leadership youth groups, Public education and Training, Consultation and collaboration, and support establishing Gay-Straight Alliances and similar initiatives in local schools.	ok2bme@kwcounselling.com	Monday 8:30am-8pm Tuesday 8:30am-8pm Wednesday 8:30am-8pm Thursday 8:30am-8pm Friday 8:30am-5pm Saturday Closed Sunday Closed	519-884-0000	N2G	\N	\N	\N	\N	https://ok2bme.ca
517	rho	kw-counselling-services-ok2bme	KW Counselling Services – OK2BME	480 Charles Street East\nKitchener, N2G 4K5	\N	OK2BME is a set of free, supportive services for LGBTQ2+ identified children, teens and their families in Waterloo Region. The OK2BME program consists of three unique areas including confidential counselling services, an OK2BME Youth Group for individuals 13-18 as well as public education, consulting and training around LGBTQ2+ issues.\nOK2BME’s services are provided by the staff and supervised placement students at KW Counselling Services. All of the staff at KW Counselling Services have Masters level education and experience working with kids, teens, and families on a variety of topics. The placement students at KW Counselling Services come from Master of Social Work or counselling programs.	ok2bme@kwcounselling.com	Monday 8:30am-8pm Tuesday 8:30am-8pm Wednesday 8:30am-8pm Thursday 8:30am-8pm Friday 8:30am-5pm Saturday Closed Sunday Closed	519-884-0000	N2G	\N	\N	Master Level Therapists	\N	https://ok2bme.ca/
518	rho	kyle-karalash-registered-psychotherapist	Kyle Karalash – Registered Psychotherapist	Sault Ste Marie, P6A 2Z4	\N	Offering affirming and inclusive counselling and therapy support to individuals, couples / partners, families.\nI understand that asking for help and talking to a stranger about your concerns can be difficult and/or overwhelming. My client-centred approach means that I will work alongside you to conquer these feelings and allow you to find comfort and relief in exploring any topic. This may be your journey, but you are not alone in the process.	info@kylekaralash.com	Monday - Friday, flexible hours.	(289) 512-2924	P6A	\N	\N	Kyle Karalash\nM.Sc. Couple & Family Therapy	\N	https://www.kylekaralash.com
519	rho	laine-magidsohn-psychotherapist	Laine Magidsohn Psychotherapist	Toronto	\N	Using a client-centred approach and a feminist, anti-oppression perspective, Lainie uses her own experiences as well as her personal strength, sensitivity, humour and intuition to support you on your journey of growth and healing. She sees both her work as a Nia instructor and as a counsellor, as an opportunity to learn more about our lives, our bodies, our relationships, and our ability to be fully ourselves.\nTo find out more about Lainie’s work as a Psychotherapist or as a Brown Belt Nia Instructor, visit www.feelmovegrow.com You are welcome to a free initial consultation or free first Nia class.	magidsohn@rogers.com	\N	416.533.2147	\N	\N	\N	Gina Julie Lacombe\nM.Ed.	\N	https://www.feelmovegrow.com
520	rho	lakehead-university	Lakehead University	955 Oliver Road\nThunder Bay, P7B 5E1	\N	Provide individual counselling services to university students attending Lakehead University. Issues include mental health, interpersonal, relationship violence, 2SLGBTQI support, stress management, mindfulness training and psychotherapy.	tekergon@lakeheadu.ca	\N	8073438582	P7B	\N	\N	Lainie Magidsohn\nMSW, RSW	\N	https://www.lakeheadu.ca
521	rho	lakeside-wellness-therapy-affiliates	Lakeside Wellness Therapy Affiliates	1755 Queen St. East\nToronto, M4L 3Y4	\N	http://www.modernsocialworker.ca	lakesidewellnesstherapy@gmail.com	Counselling Psychotherapy Mood Care Trauma Care Wellness Counselling	4169518280	M4L	\N	$150.00	Dr. Lisa Romano-Dwyer\nRegistered Social Worker	\N	https://www.modernsocialworker.ca
522	rho	lakeview-family-health-team	Lakeview Family Health Team	170 Main Street\nBrighton, K0K 1H0	\N	Comprehensive primary care for all. LGBTQ patients welcome. Please mention this listing when you call the office.\nThe Lakeview Family Health Team (LFHT) is one of 200 Family Health Teams across Ontario, which opened as part of an Ontario Ministry of Health and Long Term Care initiative aimed at improving access to primary health care professionals in Ontario. The LFHT is composed of an inter-disciplinary team of physicians and other health professionals who work collaboratively to provide patient-centered and comprehensive primary care to residents in the communities of Colborne, Brighton, Quinte West, and the surrounding areas. Our team includes physicians, nurses, nurse practitioners, a physician assistant, a dietitian, a pharmacist, a psychiatrist, and a social worker.	\N	\N	613-475-1555	K0K	\N	\N	Michelle Cohen\nMD, CCFP	\N	https://www.lakeviewfht.ca/
523	rho	lakeview-physicians	Lakeview Physicians	Huntsville	\N	family physician office	kelly.oliver@mahc.ca	\N	(705) 788-3623	\N	\N	\N	Trudy Kergon	\N	\N
524	rho	lambton-public-health	Lambton Public Health	160 Exmouth Street\nSarnia, N7T 7Z6	\N	The Sexual Health Clinic and Harm Reduction Program at Lambton Public Health provide services to people of all ages, genders and sexual orientations.\nServices provided include:\nBirth Control and Contraception\nEmergency Contraception\nFree condoms and barriers\nPregnancy testing and options counseling\nSexually Transmitted Infection (STI) and Blood Borne Infection (BBI) testing and treatment\nHarm Reduction supplies and disposal of used supplies\nReferrals	sexualhealthclinic@county-lambton.on.ca	\N	519 383 8331 #3547	N7T	\N	\N	\N	\N	https://lambtonhealth.on.ca/health-information/sexual-health; https://lambtonhealth.on.ca/health-information/harm-reduction-program
525	rho	langs-community-health-center	LANGS Community Health Center	Cambridge	\N	LGBQTA sensitive, Comprehensive Primary Care, including care for Transgender patients wanting hormone treatment, and/or gender affirming surgery	\N	\N	519-653-1470	\N	\N	\N	MD CCFP FCFP	\N	\N
526	rho	langs-community-health-centre	Langs Community Health Centre	Cambridge	\N	Langs provides primary care to all patients living in the Cambridge and North Dumfries communities. Priority is given to patient who currently do not have access to primary care.	nancyd@langs.org	\N	519-653-1470 x 343	\N	\N	\N	Siobhan Callaghan\nMDs, Nps	\N	https://www.langs.org
527	rho	langs-community-health-service	Langs Community Health Service	\N	\N	Langs (formerly Langs Farm Village Association) was established as a community development project in 1978 by a group of citizens and service providers concerned about vandalism and the lack of accessible services in the community. These individuals believed that the establishment of a community-based organization would play a positive and preventative role in the neighbourhood.\nLangs is a neighbourhood based organization, but has become so much more! Langs has grown to become a dynamic, respected community development organization providing comprehensive health and social support services that are responsive to the changing needs of our region.\nLangs provides: primary health care, early years programs, general counselling services, youth program, community programs and a resource centre	\N	\N	\N	\N	\N	\N	\N	\N	\N
528	rho	latch-lactation	Latch Lactation	\N	\N	Breastfeeding support for women and their families from prenatal to weaning. Experience with induced lactation (adoption/surrogacy) as well as exclusive pumping. Email and telephone support with home visits (Skype for isolated individuals).	michelle@branco.ca	\N	4164070168	\N	\N	\N	\N	\N	https://www.latchlactation.com
529	rho	laura-katherine-hayes-full-spectrum-doula	Laura Katherine Hayes | Full Spectrum Doula	420 Crawford Street\nToronto, M6G 3J6	\N	Laura is a full spectrum doula.\nShe provides physical, emotional, informational, advocacy and partner support for events involving reproductive health. This includes pregnancy, birth, abortion, postpartum, stillbirth, and miscarriage events. She believes that regardless of the choices you make for your body, you deserve to be heard and supported, and always feel ownership of your body. Doulas are professionals, trained to support you and your choices.\nLaura received her training for birth services from DONA International, the oldest doula organization in the world. She also completed training for assisting trauma survivors in birth from the Penny Simkin’s course on “When Survivors Give Birth”, also with DONA .\nWhile running her own private business, Laura is also a doula with the non for profit, BIRTH MARK that specifically works for marginalized communities in Toronto. With BIRTH MARK, she specifically works with abuse survivors, and for providing abortion support for clients. She is a backup doula for Spectrum Doula Collective.and The Doula Collective. She is a labour support volunteer at Jessie’s Centre for Younger Women and is currently in the mentorship program with Toronto Doula Group.\nLaura is also an abortion counselor with Exhale, an after-abortion talk-line that supports callers from all across North America. She is also currently in training to become a trauma counselor at George Brown College, in the Assaulted Women’s & Children’s Counselling/Advocacy program.\nLaura has 10 years of childcare experience, and 5 years working with families as postpartum support, as well as nanny services.\nAs a doula, Laura works from an intersectional feminist approach. Wherever you come from, whatever you believe, how you identify, or who you love, Laura is prepared to help you feel listened to, respected, and empowered during your reproductive health experience.\nLaura is pro-sex work, pro-choice, and works with all genders.\nShe assists individuals and families, of all types, ages, and abilities in Toronto and the GTA.	laurakatherinehayes@gmail.com	\N	6479930057	M6G	\N	\N	Certified Birth Doula (DONA International), abortion counselor (trained working with all genders), currently finishing diploma in intersectional feminist counselling	\N	https://www.laurakatherinehayes.com/
530	rho	laura-turnbull-counselling	Laura Turnbull Counselling	53a Claxton Boulevard\nToronto, M6C 1L9	\N	I provide counselling/therapy and mental health services to adults across Canada over the telephone, as well as in-home counselling services to those living in Toronto, with a specific focus on LGBTQ* individuals and LGBTQ*-affirmative therapy. These services are offered on a sliding scale to ensure affordability and accessibility for those in need.	Lauraturnbullcounselling@gmail.com	\N	6474632765	M6C	\N	\N	Laura Katherine Hayes\nMaster of Counselling, Registered Psychologist, Canadian Certified Counsellor	\N	https://www.lauraturnbullcounselling.com
533	rho	leah-neumann-psychotherapy	Leah Neumann Psychotherapy	\N	\N	Leah’s general counselling and psychotherapy practice addresses the needs of individuals and families who arrive with a variety of life challenges. These may include depression, anxiety, loss and grief, unresolved traumatic stress, sexuality issues, life transitions, parenting struggles, relationship difficulties, and general concerns about life satisfaction.\nLeah’s style is interactive and engaged. She focuses on addressing present life challenges while integrating past experiences. She endeavors to help her clients recognize and heal from unhelpful patterns in order to experience a renewed sense of self and enjoyment of life. She assists clients by empowering them and encouraging them to build on their strengths in order to move to a place of hope and wholeness.\nLeah received her education at the University of Wisconsin-Madison (MSSW), and she holds professional memberships with the Ontario College of Social Workers and Social Service Workers, the Ontario Association of Social Workers, and the National Association of Social Workers in the United States.	\N	\N	\N	\N	\N	\N	\N	\N	\N
534	rho	leeandra-miller-counsellor	Leeandra Miller Counsellor	\N	\N	LeeAndra Miller M.A. has more than 20 years experience as a counsellor specializing in Arts based therapy and Individual psychotherapy for children, youth and adults. She has many years of experience working as a counsellor in LGBTTQ Services, Children’s Mental Health as well as working with people who have experienced trauma. Through working for 10 years as a psychotherapist with queer and trans youth and young adults in the Pride & Prejudice program, she has developed a strong expertise working with people exploring gender identity and sexuality. LeeAndra is particularly skilled in the assessment and treatment of trauma survivors, designing and facilitating dynamic arts based groups, and playroom based therapy. She has a Masters degree in Expressive Arts Therapy from the European Graduate School, EGS. LeeAndra has a private practice where she utilizes both talk therapy and art based approaches to assist clients with their goals. She works within an anti-oppression framework and finds that the use of creativity can be highly effective and even transformational. LeeAndra is a Clinical member of the Ontario Society of Psychotherapists, OSP.	\N	\N	\N	\N	\N	\N	\N	\N	\N
535	rho	leeds-grenville-and-lanark-district-health-unit	Leeds, Grenville and Lanark District Health Unit	458 Laurier Boulevard\nBrockville, K6V 7A3	\N	Sexual Health Clinics in 7 communities across Leeds, Grenville and Lanark. Provides counselling, information and clinic services for sexuality, birth control and pregnancy * confidential, anonymous, and inclusive services * offers low cost birth control, tests free of charge for pregnancy, human immunodeficiency virus (HIV)/acquired immunodeficiency syndrome (AIDS), sexually transmitted infections (STIs) and Pap tests * provides free antibiotic treatment for all STIs.	contact@healthunit.org	\N	1-800-660-5853	K6V	\N	\N	LeeAndra Miller	\N	https://www.areyousafe.ca
536	rho	legacy-health-performance	Legacy Health & Performance	569 Ontario Street\nSt. Catharines, L2N 4N4	\N	Chiropractic, Athletic Therapy and sports medicine services, Registered Massage Therapy, Thai Yoga Massage, Yoga Therapies	legacy.niagara@gmail.com	\N	905-228-9864	L2N	\N	\N	Susan Healey\nChiropractor	\N	https://www.legacyniagara.com
537	rho	legal-services-cambridge	Legal Services Cambridge	\N	\N	Provide the following legal services to the lesbian, gay, bi-sexual, transgendered community and their families: Human Rights (Discrimination/Harrasment), Workers Compensation (WSIB), Employment Standards (termination/severance), Wrongful Dismissal, Motor Vehicle, Personal Injury and Insurance Claims, Personal Offences, Traffic Tickets and Small Claims Court.\nFREE CONSULTATIONS, NO UPFRONT LEGAL FEES, SERVICES AVAILABLE IN 20 LANGUAGES, WALK-INS WELCOME.	\N	\N	\N	\N	\N	\N	\N	\N	\N
538	rho	lenity-care	Lenity Care	70 First Avenue\nToronto, M4M 1W8	\N	Lenity means kindness. We provide inclusive, LGBT+ professional in home health care services for elders in the GTA. Our services include the development of Care Plan, 24 /7 Personal Care ( bathing, skin care, bed transfer, incontinence support, therapeutic massage, yoga, meditation, and hair styling; Companionship (activities such as listening to music, playing cards and accompanying you/your loved one on social outings; Home Care ( home cleaning, food purchase and light meal preparation); Primary Care Giver Support ( navigation of public and private care options in home and facilities. We can also provide personalized Care Plans for primary caregivers, including recommendations for counselling support and resources for self-care if requested. We will also advocate and provide support in relation to access of services outside of the home. As a member of the LGBT+ community and owner of Lenity Care, I am committed to ensuring that our in-home care services embrace and support the needs of the LGBT+ community in terms of care, as well as career opportunities with Lenity Care.	margfoy@lenitycare.com	\N	\N	M4M	\N	\N	MA Psychology; Staff include Personal Support Workers, Occupational Therapists, Registered Nurses, Registered Practical Nurses	\N	https://www.lenitycare.com
539	rho	lequipe-psycho-sociale-pour-enfants-jeunes-et-familles-francophones-de-stormont-dundas-et-glengarry	L’Équipe psycho- sociale pour enfants, jeunes et familles francophones de Stormont, Dundas et Glengarry	610 McConnell Avenue\nCornwall, K6H 4M1	\N	L’Équipe psycho-sociale for children, youth and their families.\nL’Équipe is recognized as a mental health organization under the responsibility of the Ministry of Health and Long-Term Care, providing services to children, youth and their families since August 4th 1980.\nAll of our services are Ministry funded and accessed on a voluntary basis.\nReferrals come from parents, legal caregivers, health care professionals, schools, the Children’s Aid Society, youth over 12 who consent to services or other community or regional organizations.\nOur mission is to provide mental health awareness, education, clinical interventions and therapeutic programs and services aimed at improving the psychological and social well-being of young people and their families\nL’Équipe aims to be recognized as an organization demonstrating excellence in the delivery of French language services for children, youth and their families in Stormont, Dundas and Glengarry\nPROGRAMS AND SERVICES\nTO MAKE A REFERRAL\nTEL: 613-938-7112\nFAX: 613-938-8163\nEMAIL: alandry@equipepsychosociale.ca	glacombe@equipepsychosociale.ca	\N	TO MAKE A REFERRAL TEL: 613-938-7112 FAX: 613-938-8163	K6H	613-938-7112Directions	\N	Marg Foy\nClinidal Director/Registered Psychotherapist	\N	https://www.equipepsychosociale.ca
540	rho	lgbtq-counselling	LGBTQ Counselling	Toronto, M4K 1R3	\N	LGBTQ Counselling is a therapeutic practice dedicated to the care of, and treatment for, members of queer (LGBTQIA+) communities by a queer identified counsellor. I also welcome clients who do not identify on the LGBTQ spectrum.\nWhether you are struggling to come out, questioning your gender identity, are in transition, require referral letters/assessments for GAS, living with or affected by HIV/AIDS, stress, anxiety, depression, addiction, abuse(s) or experience challenges in your relationship(s) (poly+) then I am here to help.\nLGBTQ Counselling is a place where human rights are respected and where lesbian, gay, bisexual, trans, two spirit and queer people, and their friends and allies, are all welcomed and supported.	jeffrey@lgbtqcounselling.com	\N	4168261866	M4K	\N	\N	Jeffrey Reffo\nMSW	\N	https://www.lgbtqcounselling.com
541	rho	lgbtq-parenting-network	LGBTQ Parenting Network	\N	\N	The LGBTQ Parenting Network promotes the rights and well-being of lesbian, gay, bisexual, trans, and queer parents, prospective parents and their families through education, advocacy, research, social networking and community organizing.	\N	\N	\N	\N	\N	\N	\N	\N	\N
542	rho	lice-services-canada	Lice Services Canada	337 Churchill Avenue North\nOttawa, K1Z 5B8	\N	We have different pricing options for in clinic lice treatment, head checks & mobile service. All services are by appointment only. Call 613-777-2939 today.	LiceServicesCanada@techwyseintl.com	\N	6137772932	K1Z	\N	\N	Anne Doswell	\N	https://www.liceservicescanada.com
543	rho	life-in-full-recreation-therapy	Life in Full Recreation Therapy	Greater Toronto Area, M5V4A5	\N	I’m Kim, a private practice Recreation Therapist in the Greater Toronto Area, passionate about improving quality of life for individuals through meaningful leisure! I am dedicated to providing a welcoming, inclusive environment for all clients of all races, genders, religions, ages, orientations, and identities.\nI help individuals with various barriers to leisure make the most of their lives – physically, mentally, emotionally and socially. I support my clients’ recreational and functional goals through purposeful, enjoyable, results-oriented leisure activities. The overall goals are to improve quality of life and enhance the sense of purpose in their lives by helping them do the things that bring them joy, despite any limitations. I meet clients in the community, their homes, and in various living facilities, and am approved by Passport Program funding.\nRecreation Therapy sessions may focus on goal areas like: community integration, mood, mobility, memory, social effectiveness, etc., and programming can include: adapted sports, cognitive games, reminiscence, community outings, creative arts & more! Everything is centred on the individual’s needs, strengths, and preferences.\nFor more information or to schedule a consultation for yourself or your loved one, visit www.lifeinfull.ca, or reach me directly by email at lifeinfullca@gmail.com. I look forward to hearing from you!	lifeinfullca@gmail.com	Mondays-Fridays, 9:00 am - 5:00 pm	Available upon request	M5V	\N	Free initial consultation, session fees as follows: $75 for 1 hour, $100 for 1.5 hours, $125 for 2 hours. Fees reimbursable through Passport funding.	Kim\nBA	\N	https://www.lifeinfull.ca
544	rho	lifewalk-counselling-reiki-and-hypnosis	Lifewalk Counselling, Reiki and Hypnosis	\N	\N	Lifewalk Counselling, Coaching, Reiki and Hypnosis helps children, teens and adults with physical or emotional pain to feel better. We support individuals who are spiritually or emotionally stressed and want to create changes in their lives.\nWe offer individual sessions as well as workshops and Reiki Classes.\nDonna Harris has more than 30 years experience counselling and coaching. In addition to being trained in ‘traditional’ therapies such as: Cognitive Behavioural Therapy, Reality Therapy-Choice Theory, Solution Focused Therapy, Trauma Assessment and Psychodynamic Bodywork, she is also a Reiki Master (Usui Shiki Ryoho) and a practitioner of Polarity and Cranio Sacral Therapy.\nFrancesca Warriner has been practicing Reiki since 1993 and was initiated as a Reiki Master in 1997. Being a Reiki Master for her is a life commitment to personal growth and healing. Within the sessions, you may experience other therapeutic modalities such as Shamanism, Sounding, Intuitive Counselling and Hypnotherapy\nLifewalk offers Reiki classes to Adults, Teens and Children in the standards of The Reiki Alliance.	\N	\N	\N	\N	\N	\N	\N	\N	\N
545	rho	linda-thai-at-your-story-counselling	Linda Thai at Your Story Counselling	20 FLORAL PARKWAY\nUNIT A3\nCONCORD, L4K4R1	\N	My main objective is to support oppressed and stigmatized populations to seek safety and support through talk therapy, and with supportive and safe and effective therapeutic modalities. I would like the opportunity to work with LGBTQ2+ populations who want to seek justice and or happiness within their lives. For those who have been discriminated against and or oppressed, my goal is to enhance inclusivity and to inspire clients to share their own unique lived experiences, without judgement and bias. Finally, with my down to earth and authentic approach, I want to give my clients the opportunity to share and feel supported in a safe and accepting environment, which can enhance their quality of life.\n	lindat@yourstorycounselling.com	9am-9pm.	6479795009	L4K	\N	130\nSliding scale range - $/Hour Minimum: 90 Maximum: 130	Linda Thai\nMACP., RP(Q)	\N	https://www.yourstorycounselling.com
546	rho	lindsay-elin-psychotherapy-and-counselling	Lindsay Elin Psychotherapy and Counselling	\N	\N	I am a Registered Social Worker (RSW) who provides psychotherapy and counselling services to adults, youth and families in Toronto.\nAreas of specialization include: working with individuals and families around issues related to sexual orientation and gender identity, working with parents of LGBTQ+ youth and young adults (including parents who are struggling to understand/accept their child’s gender identity), supporting couples to navigate the challenges of gender identity/transition on their relationship, working around issues of depression, anxiety and healing from abuse, strengthening parent-child relationships, working with youth who are struggling with depression, suicidal feelings and self-harming behaviours, working around issues of sexuality and sexual health. I have a particular interest in supporting queer and trans people as they work to bring children into their lives, navigate queer/trans conception realities, fertility clinics, surrogacy options and/or adoption processes, and adjust to their lives as new parents.\nI am trained in multiple therapeutic modalities – the approach we take will be responsive to your unique needs and goals. I am particularly influenced by attachment-informed therapies, trauma-focused therapies, mindfulness-based therapy, emotion-focused therapy (EFT) and somatic/Sensorimotor Psychotherapy (completed Level 1). Since 2013 I have been pursuing certification in Attachment-Focused Family Therapy (Drexel University, Philadelphia, PA), which is an evidence-based approach for working with depressed youth and their families, and which has been researched with LGBTQ+ youth/young adults, and their families. I work from an anti-oppressive, harm reduction framework.\nI would be honoured to support you and/or your family through life’s challenges and transitions. Please do not hesitate to contact me for a free telephone consultation to discuss how I can be of support to you.	\N	\N	\N	\N	\N	\N	\N	\N	\N
547	rho	lindsay-hancock-m-d	Lindsay Hancock, M.D.	\N	\N	I work as a full-scope family physician providing services to First Nations people living in the Sioux Lookout area, mostly from remote, fly-in communities. I have a particular interest in addictions and mental health issues.	\N	\N	\N	\N	\N	\N	\N	\N	\N
548	rho	lisa-bell-family-physician-at-south-riverdale-community-health-centre	Lisa Bell, family physician at South Riverdale Community Health Centre	955 Queen Street East\nToronto, M4M 3P3	\N	I am a family physician working at South Riverdale Community Health Centre who is comfortable initiating and prescribing hormone therapy.	\N	\N	416-461-2493	M4M	\N	\N	Lisa Bell\nMD, CCFP	\N	https://www.srchc.ca
549	rho	lisa-pelletier-sex-therapist	Lisa Pelletier, Sex Therapist	Collingwood, L9Y 2T7	\N	I am open to providing services to LGBTQ people as well I am familiar with Kink dynamics and Polyamory/Open Relationships.	lisa@heartflame.ca	\N	705-445-9856	L9Y	\N	\N	Lisa Pelletier\nMSc Registered Psychotherapist, Registered Couple and Family Therapist, Certified Sex Therapist	\N	https://www.heartflame.ca
550	rho	lisa-shouldice-ma-rp-ccc	Lisa Shouldice MA, RP, CCC	Toronto, M6G 1L5	\N	Toronto Psychotherapist\nSpecializations:\nTrauma, specifically from a past history of sexual, physical and emotional/psychological abuse\nDepression/Anxiety\nPersonality Disorders and related mental health struggles\nLife transitions\nSexual Identity, Orientation & Gender Identity challenges\nGrief/Bereavement\nDisordered Eating\n	lshouldice@rogers.com	Contact me.	416-953-6880	M6G	\N	140-160	Lisa Shouldice\nRegistered Psychotherapist CRPO 001752	\N	https://www.lisashouldice.com
552	rho	little-sabios-day-care	Little Sabios – Day Care	Toronto	\N	I am opening a Bilingual (English-Spanish) daycare in Toronto with curriculum as a preschool, where I will teach dancing, acting, Spanish-English, crafts, baking, pre math, pre reading – writing (English and Spanish), gardening and more.\nThe daycare will be professionally equipped with everything that’s needed for five children to develop in a creative and free learning environment. There will be different rooms 1. Library-creativity art room, 2. Gym-playroom and 3. sleeping room. Each room will be setup specialized for children to be safe, fun and nicely decorated . Only new learning materials and toys will be use in the daycare and they are branded such as: Melissa & Doug, Learning Resources, B (battat), SKIP*HOP, Fisher-Price, vetch and others\nThe daycare will maintain a high standard of hygiene and cleanliness.\nI am qualified with university bachelor of Early Childhood Education, 15 years experience as pre-school teacher and have my own curriculum with effective methodology in teaching children. I have excellent references as childcare professional in Calgary and Toronto, and I am a certified childcare first aid. I have a vulnerable police clearance.\nI don’t have children , but I love teaching children and seeing them happy, free and enjoying every single learning moment in a safe, healthy, creative, and fun atmosphere.\nThe weekly rate is $350\nFull time from 7:30am to 6:00pm\nChildren between 6 months to 5 years old\nBreakfast, 2 snacks and lunch\nI will have an assistant for special trips and special activities in the daycare.\nI am opening in September 2015	monica-1313@hotmail.com	\N	\N	\N	\N	\N	Monica Restrepo\nEarly Childhood Teacher	\N	\N
553	rho	living-homeopathy	Living Homeopathy	Toronto, M6G 1P1	\N	I work with individuals from the whole spectrum of life’s stages and assist by prescribing remedies to match where people are stuck in lifes transitions or with conditions from mental/emotional to physical health matters. These can be of an acute nature or chronic illnesses that range from inflammatory conditions that are hereditary in nature or that are from traumas/injuries that are held in the body. See my website and come in for a complimentary info session to learn how Homeopathy is used world wide and has many benefits of which the foundational shift that can occur for individuals allows for the vitality of a person to come back and help restore a person to health – from infants to elders of our communities.	info@livinghomeopathy.com	\N	(647) 292-4899	M6G	\N	\N	Laura Coramai\nHomeopath, Registered with College of Homeopaths of Ontario, RSHom (NA)	\N	https://www.livinghomeopathy.com
554	rho	lmc-counselling	LMC Counselling	684 Saint Clair Avenue West\nToronto, M6C 1B1	\N	Private practice Therapist\nCBT, Trauma informed, LGBTQ community, Couples, Anti oppressive lens, family of origin, family conflict and grief.	ellis_mair@hotmail.com	\N	4165707146	M6C	\N	\N	Mair Ellis\nRegistered Social Worker	\N	\N
555	rho	lmc-health-care	LMC Health Care	Barrie, L4N 7L3	\N	Counsel and facilitate transition needs for individuals with gender dysphoria.	lmcbarrie@lmc.ca	\N	705-737-0830	L4N	\N	\N	Huan  Yu\nEndocrinologist	\N	\N
556	rho	lmc-healthcare	LMC Healthcare	140 Oxford St E\nSuite 400\nLondon, N6A5R9	\N	Dr. Brennan is committed to providing high quality, compassionate healthcare to her patients. She follows patients with a range of endocrine conditions, and has particular interest in diabetes, obesity, thyroid, and transgender care.\nDr. Ranjit Singarayer has clinical interests in all areas of endocrinology, with a specific focus on thyroid cancer, thyroid nodules, and transgender medicine. He is looking forward to returning to London to serve his home community.	lmclondon@LMC.CA	Monday - Friday 9 am to 5 pm	226-680-0802	N6A	\N	\N	RPh, BSc, PharmD, CDE	\N	https://www.lmc.ca/locations/lmc-london/
557	rho	lmc-pharmacy-london	LMC Pharmacy – London	140 Oxford St E\nSuite 400\nLondon, N6A5R9	\N	Community Pharmacy within LMC Healthcare.\nSafe space and familiar with navigating drug plan coverage for various hormone therapy regimens. Training available for self-administration of injectable therapy with referral and appointment.	lmclondon@LMC.CA	Monday to Friday - 9 am to 5 pm	2267814545	N6A	\N	\N	Elena Salgado\nBSc PharmD CDE	\N	https://www.lmc.ca/locations/lmc-london/
558	rho	london-intercommunity-health-centre	London InterCommunity Health Centre	659 Dundas Street\nLondon, N5W 2Z1	\N	The London InterCommunity Health Centre has been a part of London’s Old East community for more than 20 years. We provide health and social services in a welcoming setting to those who experience barriers to care. These barriers may include poverty, homelessness, language or culture, and complex and/or chronic health conditions including mental health and addictions.\nOur two East London locations offer care by a team which includes family doctors, nurse practitioners, nurses, social workers, dietitians and community health workers.  The Health Centre offers many programs that address the factors in our living and working lives that impact our health, well-being and ability to reach our potential. These factors include income, education, employment, housing, food, recreation and social supports.\nOur vision is to build opportunities for healthy and inclusive communities.	\N	\N	519-660-0874	N5W	\N	\N	\N	\N	https://lihc.on.ca/
559	rho	london-intercommunity-health-centre-2	London InterCommunity Health Centre	\N	\N	The London InterCommunity Health Centre is dedicated to creating and maintaining an environment that is accessible and safe for members of the transgender community. We are committed to training our staff in the areas of Gender Expression, Gender Identity and Sexual Orientation to ensure that everyone coming through our doors feels heard and respected by our team. Policies of inclusion ensure that programs are aligned with\nour goal of trans accessibility.	info@lihc.on.ca	\N	519-660-0874	\N	\N	\N	\N	\N	https://lihc.on.ca/children-youth-and-families/
560	rho	london-psychologist	London Psychologist	260 Ferndale Avenue\nLondon, N6C 5K6	\N	I primarily provide individual psychological assessment and intervention, though have served as a consultant psychologist to several community agencies. I also engage in graduate level teaching (classroom and practical). I have a strong interest in traditionally underserviced populations, work with medically ill adults, as well as in the broad area of trauma/resilience.	fotchet@drotchet.com	\N	519-630-1863	N6C	\N	\N	\N	\N	https://www.drotchet.com
561	rho	lorraine-munro-psychotherapy	Lorraine Munro Psychotherapy	489 College Street\nToronto, M6G 1A5	\N	Supporting you and your relationships. Poly, kink, Trans, LGBTTI2QQ+ friendly. Wheelchair accessible. Individual, relationships of all kinds. Skype, in person or phone sessions.	lorraine@lorrainemunro.com	\N	647 855-4325	M6G	\N	\N	Lorraine Munro\nMSW, RSW	\N	https://www.lorrainemunro.com
562	rho	lotus-psychotherapy-and-counselling	Lotus Psychotherapy and Counselling	2212 lakeshore Blvd W.\netobicoke, M8V0C2	\N		mia@lotus-psychotherapy.ca	monday to friday 9am to 8pm	2892105869	M8V	\N	$150-$200	Mia Omara\nRegistered Psychoherapist	\N	https://lotus-psychotherapy.ca/
619	rho	midwifery-collective-of-ottawa-2	Midwifery Collective of Ottawa	88 Centrepointe Drive\nOttawa, K2G 5K7	\N	Personal, client-centred care for pregnancy, birth and 6 weeks postpartum.	reception@midwiferycollective.com	\N	6137302323	K2G	\N	\N	Mianh Lamson\nRegistered Midwife	\N	https://www.midwiferycollective.com
563	rho	lynda-narducci-health-and-wellness-consultant	Lynda Narducci Health and Wellness Consultant	93 Canada Street\nHamilton, L8P 1P2	\N	I have been blessed with the good fortune of a learning process that started for me, many years ago. The learning process of the importance of a healthy life style. With this knowledge I was able to work my way through 8 years of competitive bodybuilding. Having achieved the provincial ranks and placing a respectable 2nd in my weight class, I then chose to retire to raise my young family. It is with this same knowledge that I continue to maintain a healthy life, encourage my children and through my leadership skills inspire and mentor many others to do the same.\nIf there is an area of your life that you know needs some managing and you are unsure where to start, I can help you personally or direct you to the service/product that can.\nMy interest is to help people manage their lives with no barriers and with confidentiality.	lyndanarducci@hotmail.com	\N	289-237-2515	L8P	\N	\N	Lynda Narducci\nHealth and Wellness Consultant	\N	\N
564	rho	made-to-move	Made To Move	1915 Danforth Ave\nToronto, M4C1J5	\N	We offer Chiropractic appointments and Registered Massage Therapy appointments. Chiropractic visits may include adjustments, mobilizations, soft tissue therapy (ART/IASTM), a personalized rehab exercise plan, (Pilates, FRC, PBT), Medical Acupuncture (with or w/out electrical stim), Cold Laser Therapy, Taping, and Custom Orthotics. Our staff are all members of the LGBT2QI community, as well as all former professional dancers. We offer Direct Billing, and online booking. Not sure if we can help? Book a free meet and greet over the phone or in person to chat with the Doctor. For more information, please visit www.madetomove.ca. We are here to provide support, care, and community to all of our patients.	hello@madetomove.ca	Hours vary depending on location. If you are looking for an appointment outside of what you see available for online booking, please get in touch and we will do our best to find a time that suits your schedule. We do see patients Monday - Saturday and can be available on Sundays. Mobile Massage is also offered, right in your own home!	(905) 767-5500	M4C	3300 Yonge Street, 4th Floor, Toronto, ON M4N 2L6(905) 767-5500Directions\n35 Golden Ave, Suite 108, Toronto, ON M6R 2J4(905) 767-5500Directions	Follow-Up Chiro ($65), Follow-Up Chiro/Acupuncture ($90), First appointment (exam) + First treatment ($125), Massage (RMT) $110/hour + HST	Dr. Stephen Gray\nDC, BMTP, Medical Acupuncture Provider	\N	https://www.madetomove.ca
565	rho	magenta-health-family-medicine-clinic	Magenta Health – Family Medicine Clinic	625 Queen Street East\nToronto, M5A 1T3	\N	Magenta Health is a family medicine clinic in Riverside (with a second location opening in the Beaches later in 2015). We’ve worked hard to create a modern space staffed by amazing staff and caring physicians, using technology that helps us provide accessible, timely, and convenient patient care:\n– book and confirm appointments online – 24/7\n– communicate with your doctor electronically\n– see your own family doctor with minimal wait times\nAll of our family doctors are accepting new patients. Visit the website to register or email contact@magentahealth.ca	contact@magentahealth.ca	\N	\N	M5A	\N	\N	\N	\N	https://www.magentahealth.ca/
566	rho	mahalia-freed-nd	Mahalia Freed, ND	\N	\N	At Dandelion Naturopathic Clinic, Dr. Mahalia Freed works with you to restore, promote, and maintain optimal health using individualized natural therapies. Mahalia addresses the root cause of illness, and supports people through the cycles and milestones in their life, from PMS to pregnancy to menopause, and from stress-related digestive disorders to depression. Please see www.dandelionnaturopathic.ca for more information about treatments and services offered.	\N	\N	\N	\N	\N	\N	\N	\N	\N
567	rho	mahaya-health-services-rmt	Mahaya Health Services – RMT	2 College Street\nToronto, M5G 1K2	\N	I am a cisgendered queer male who works as a Registered Massage Therapist in the Toronto area. I have been fortunate enough to work in the physio & rehab sector for a while, and now work out of a Naturopathic clinic as well. Available for Swedish, Craniosacral, and Sport treatments in the Down Town core – mostly Church & Wellesley Village, College Street, Bay Street, University and the finacial district.\nI am also available to provide mobile massage in the comfort of your own home or hotel around the GTA.\n**Insurance receipts provided**	carlormttoronto@gmail.com	\N	647 435 0152	M5G	\N	\N	Carlo Marcoccia\nDiploma of Massage Therapy	\N	https://www.mahayahealth.com/rmt-toronto/carlo-marcoccia , www.carlormttoronto.com ,
568	rho	mahboubeh-katirai-psychotherapy	Mahboubeh Katirai Psychotherapy	\N	\N	Feminist anti oppression therapy with GLBTQ, trauma survivours, refugee population, dealing with difficulties in relationships, family and identity issues.	\N	\N	\N	\N	\N	\N	\N	\N	\N
569	rho	maitland-valley-family-health-team	Maitland Valley Family Health Team	180 Cambria Road North\nGoderich, N7A 4N8	\N	We are a Family Health Team based out of Goderich, Ontario. Our mission is to optimize the health of our community through collaboration and patient centres care. We have an outstanding team dedicated to providing the utmost in patient care.	info1@mvmc.ca	\N	519 524 6060	N7A	\N	\N	Matt Hoy\nExecutive Director	\N	https://www.mvfht.ca/
570	rho	maltby-centre	Maltby Centre	31 Hyperion Court\nKingston, K7K 7G3	\N	We provide free counselling services for LGBTQ kids, youth and their families in the Kingston, Frontenac, Lennox and Addington area.	jbrittain@maltbycentre.ca	\N	613-546-8535 ext 5522	K7K	\N	\N	Jen  Brittain\nMSW, RSW	\N	https://www.maltbycentre.ca
571	rho	manitoulin-midwifery	Manitoulin Midwifery	2236 Highway 551\nBox 289\nMindemoya, P0P1S0	\N	Manitoulin Midwifery provides complete prenatal, labour, birth and postpartum care for clients and their newborn. Services are funded by OHIP and provided for all of Manitoulin, Birch Island, Espanola, Massey, Webwood, McKerrow  and Nairn Centre.	christinat@amtelecom.net	Office hours Monday-Friday 9am to 5pm. 24 hour emergency care for midwifery clients.	7052100737	P0P	\N	\N	Christina Therrien\nRegistered Midwife	\N	https://www.ontariomidwives.ca
572	rho	many-paths-therapy	Many Paths Therapy	2039 Robertson Road\nNepean, K2H 8R2	\N	I am a Registered Psychotherapist (Qualifying) living and practicing in Ottawa. My goal is to journey with you for a time along your path. Together we can co-create a space where we may reflect upon old paths or look forward to creating new ways of walking in the world. My approach is trauma-informed, culturally safe and grounded in the belief that you are the expert on your journey. My practice is informed by both western and Indigenous approaches. I have an MA in Counselling, Psychotherapy and Spirituality as well as extensive experience as a traditional counsellor in the Indigenous community.​\nAs an two-spirit, non-binary person I both personally and professionally understand the unique challenges often faced by 2SLGBTQIA+ communities and am fully committed to supporting individuals through the coming-out process and/or transitioning. Gender is, after all, its own journey.\n​Let’s explore a path to mental wellness, whatever that might look like for you!	manypathstherapy@gmail.com	Monday - Thursday 1100-1900 h	3435004866	K2H	\N	Sliding scale range - $/Hour Minimum: 75 Maximum: 150	Sharp Dopler\nCD, MA, RP(Q)	\N	https://www.sharpdopler.com/
573	rho	maple-leaf-prep-clinic	Maple Leaf Prep Clinic	14 College Street\nToronto, M5G 1K2	\N	We are a nurse-led and specialist-supported PrEP Clinic conveniently located in the Maple Leaf Medical Arts building at 14 College St, Suite 102 (in the pharmacy).\nOur clinic is accepting new referrals.\nWe provide access to PrEP for HIV-negative cis and trans-identified men and women, including guidance with Trillium Drug Plan applications from our pharmacy staff, and STI treatment and testing for PrEP Clinic patients.\nMaple Leaf PrEP Clinic hours have changed.	prep@mlmedical.com	\N	4169201991	M5G	\N	\N	Maple Leaf Medical Clinic Clinic	\N	\N
574	rho	maray-counselling	Maray Counselling	231120 Trafalgar Road NorthL9W 7B8	\N	We provide counselling to youth, adults and couples within the LGBTQ community. We are experienced working with trans youth and couples.	maray.counselling@gmail.com	\N	519-855-6067	L9W	\N	\N	Marianne Breadner  Ray St-Amour\nMSW, RSW	\N	https://www.maraycounselling.com/
575	rho	marc-colbourne-rsw-msw	Marc Colbourne, RSW MSW	120 Carlton Street\nToronto, M5A 4K2	\N	A general psychotherapy practice providing safe, supportive, and validating counselling. I specialize in such areas as depression/anxiety, sexual health and behaviour concerns, gender and sexual identity, mindfulness, and grief and change.	info@marccolbourne.ca	\N	416 522 0445	M5A	\N	\N	Marc Colbourne\nBSW, MSW, RSW	\N	https://www.marccolbourne.ca
576	rho	marco-posadas-psychotherapy	Marco Posadas Psychotherapy	\N	\N	Ongoing, long-term (open-ended), intensive, psychodynamic psychotherapy and psychoanalysis with individuals (adolescents and adults) in a client-centered, anti-oppressive, anti-racist approach.\nAlso providing: Couple therapy, and brief (time-limited) strength-based, client-centered, psychodynamic informed psychotherapy.\nAreas of interest: Severe childhood trauma, abuse, transition support, HIV-related issues, grief, anxiety, loneliness and isolation.	\N	\N	\N	\N	\N	\N	\N	\N	\N
577	rho	margaret-lawson-m-d-pediatric-endocrinologist	Margaret Lawson, M.D. Pediatric Endocrinologist	401 Smyth Road\nOttawa, K1H 8L1	\N	Puberty Suppressant and Cross-Gender Hormone Therapy for Transgender Youth	lawson@cheo.on.ca	\N	6137372411	K1H	\N	\N	Margaret Lawson\nMD, MSc, FRCP	\N	\N
578	rho	maria-kielly-at-brockville-general-hospital	Maria Kielly at Brockville General Hospital	75 Charles Street\nBrockville, K6V 1S8	\N	Obstetrician gynecologist who specializes in pediatric and adolescent gynecology and also offers trans affirming care.	\N	\N	613-498-0740 ext 3	K6V	\N	\N	Maria  Kielly\nMD	\N	\N
579	rho	marie-robertson-counsellor	Marie Robertson, Counsellor	2126 - 200 Clearview Avenue\nOttawa, K1Z 8M2	\N	Counselling specializations: relationship issues, grief & bereavement, addiction recovery, codependency, anger release therapy, HIV/AIDS/cancer, coming out, internalized homophobia; individual & couple counselling; some sliding scale spots available. Workshops include: grief & bereavement, anger management, healing shame, internalized homophobia, butch/femme, lesbian sexuality, LGBT aging.	marie@talktomarie.com	10:00 a.m. - 6:00 p.m.	613-421-0344	K1Z	\N	$100 one-on-one; $120 couple counselling	Marie Robertson\n(Serving the LGBT Community since 1987)	\N	http://www.talktomarie.com
580	rho	marika-heinrichs-somatic-psychotherapy	Marika Heinrichs Somatic Psychotherapy	Guelph, N1H 2V1	\N	I am a somatic therapist and educator who works at the intersection of social/environmental justice and embodied healing. My approach is sex positive, anti-racist, harm reduction, queer and trans affirming and I bring a depth of understanding of the embodiment of trauma to my work. My practice is shaped to serve the needs of LGBTTQ2S people and their allies. I offer somatic bodywork as well as somatic education through groups and series. I also offer consultation services for other practitioners and organizations.	info@marikaheinrichs.com	Monday + Tuesday 11 a.m. - 6 p.m.	\N	N1H	\N	\N	Marika Heinrichs\nM.Ed, RP	\N	https://www.marikaheinrichs.com
581	rho	marlee-rubel-psychotherapy	Marlee Rubel Psychotherapy	Toronto	\N	Queer-identified registered psychotherapist specializing in trauma, addictions, anxiety, and relationship counselling with the queer community.	marleerubelpsychotherapy@gmail.com	\N	\N	\N	\N	\N	Marlee Rubel\nM.Ed, Registered Psychotherapist	\N	https://www.MarleeRubel.com
582	rho	marlene-russell-associates-counselling	Marlene Russell & Associates Counselling	4 Deer Park Crescent\nToronto, M4V 2C3	\N	Counselling	marlenerussellcanada@gmail.com	\N	(416) 926-0319	M4V	\N	\N	Marlene Russell\nM.ED	\N	\N
583	rho	maryvale-childrens-mental-health-centre	Maryvale Children’s Mental Health Centre	3640 Wells Street\nWindsor, N9C 1T9	\N	Maryvale is a Children’s Mental Health treatment centre in Windsor, Ontario, where adolescents experiencing very serious emotional, psychological and mental distress can receive therapy and assistance from a team of experts.\nWe help young people (aged 13 to 17) and their families who feel highly anxious, depressed, suicidal, worthless and hopeless, or who have lost their willingness to care about others. They may be dealing with debilitating learning disabilities.\nSome students attend Maryvale during the day for school while others come for after school or weekend programs. Others attend for counselling only to sort out some areas of distress they are facing\nMaryvale is primarily funded by the Ontario Ministries of Children and Youth Services and Health and Long Term Care and fundraising. There is no cost for Maryvale services although parents and legal guardians are asked to cover the costs of their child’s personal expenses.\nIt is Maryvale’s passion to promote the recognition and understanding that one’s inner mental and emotional world is of utmost importance and determines more than any other factor the quality of one’s current life and future life.	\N	\N	519.258.0484	N9C	\N	\N	\N	\N	https://www.maryvale.ca/
584	rho	masina-wright-naturopath	Masina Wright Naturopath	360 King Street East\nToronto, M5A 1K9	\N	As a Naturopathic Doctor I provide alternative medical care using acupuncture, herbal medicine, lifestyle counseling, homeopathy, and nutrition. I practice at 360 Health Care with a circle of other complementary care providers including massage, chiropractic and energy medicine. My areas of special interest are fertility and conception, stress management and HIV/HEP C. I am interested in trans wellness as well as basic health care support for all genders and sexualities.	masina@360healthcare.com	\N	416-360-1300	M5A	\N	\N	Masina Wright\nNaturopathic Doctor	\N	https://www.360healthcare.com
585	rho	massage-addict-brantford	MASSAGE ADDICT BRANTFORD	185 King George Road\nBrantford, N3R 7R9	\N	At Massage Addict, we are all about massage. We’re 100% focused on providing the very best massage therapy, because it’s all we do. We provide the highest quality massage treatments delivered by Registered Massage Therapists in a comfortable environment – at a price you can afford.\nOnce you step into any of our clinics across Canada, you’ll know why we’re the largest and fastest growing provider of registered massage therapy in the country. And we’re membership-based, which means you benefit from preferred prices every time you book a treatment.\nMassage Addict is 100% Canadian owned and operated. With over 70 clinics and some 800 Registered Massage Therapists, we help over 50,000 Canadians each month manage pain, stress, anxiety, injury, muscle tension and much more.	brantford@massageaddict.ca	\N	5193045222	N3R	\N	\N	Joanne Patak\nOwner and Operator	\N	https://www.massageaddict.ca/brantford
586	rho	massage-addict-west-brant	Massage Addict West Brant	320 Colborne Street West\nBrantford, N3T 1M1	\N	At Massage Addict, we are all about massage. We’re 100% focused on providing the very best massage therapy, because it’s all we do. We provide the highest quality massage treatments delivered by Registered Massage Therapists in a comfortable environment – at a price you can afford.\nOnce you step into any of our clinics across Canada, you’ll know why we’re the largest and fastest growing provider of registered massage therapy in the country. And we’re membership-based, which means you benefit from preferred prices every time you book a treatment.\nMassage Addict is 100% Canadian owned and operated. With over 70 clinics and some 800 Registered Massage Therapists, we help over 50,000 Canadians each month manage pain, stress, anxiety, injury, muscle tension and much more.	westbrant@massageaddict.ca	\N	5193047522	N3T	\N	\N	Joanne Patak\nOwner	\N	https://www.massageaddict.ca/brantford-westbrant
587	rho	massage-now	Massage Now	100 Belmont Drive\nLondon, N6J 3T4	\N	Registered Massage Therapy services offered in a professional relaxing clinic setting.	info@massagenow.ca	\N	519-204-8860	N6J	\N	\N	Registered Massaged Therapy	\N	https://www.massagenow.ca
588	rho	matthew-serrick-chiropractic	Matthew Serrick Chiropractic	40 Wellesley Street East\nToronto, M4Y 1G2	\N	We focus on a number of different treatment options to eliminate pain, enable you to functional better in your everyday life, optimize health, and improve your range of motion. Common issues we see include:\n– Pain management\n– Sports injury and performace therapy\n– Postural complaints\n– Back pain\n– Foot pain and discomfort\n– Whiplash and neck injury\n– Arthritis\nWe offer individualized and patient-centered treatments, where a lot of time is spent finding the actual cause and not just treating symptoms. Treatments offered include:\n– Adjustments and mobilizations\n– Laser therapy\n– Shockwave therapy\n– Acupuncture\n– Custom Orthotics\n– Myofascial release\n– Custom orthotics\n– Custom rehab programs	dr.serrick@backinbalanceclinic.com	\N	416-660-9932	M4Y	\N	\N	Matthew Serrick\nD.C.	\N	https://www.backinbalanceclinic.com
589	rho	max-ottawa	MAX Ottawa	400 rue, Cooper St\nSuite 9004\nOttawa, K2P 2H8	\N		info@maxottawa.ca	By Appointment: Monday: 9.30 AM - 5.30 PM Tuesday: 9.30 AM - 5.30 PM Wednesday: 9.30 AM - 12.00 PM Thursday: 9.30 AM - 5.30 PM Friday: 9.30 AM - 12.00 PM Walk-in: Wednesday: 12.00 PM - 8:00 PM Friday: 12.00 PM - 8:00 PM	(613) 701-6555	K2P	\N	\N	\N	\N	https://www.maxottawa.ca/
590	rho	maya-hammer	Maya Hammer	Guelph	\N	Providing counselling and psychotherapy to transgender and gender non-binary people and families, able to provide a diagnosis and second letter of referral for surgery. Currently available by telephone, Skype, or FaceTime only.	maya.hammer@gmail.com	\N	519-350-3971	\N	\N	\N	Maya Hammer\nPsychologist	\N	https://www.mayahammer.ca
591	rho	mcdonald-osteopathy-and-wellness	McDonald Osteopathy and Wellness	Cambridge, N1T 1X4	\N	I am an Osteopathic Manual Practitioner, offering treatment for musculoskeletal pain, injuries and overall health issues. I use gentle, soft-tissue manipulation to promote healing, fluid movement and improve quality of motion throughout the body.	dana.rae.mcdonald@gmail.com	Tuesday: 9:00 AM - 12:00 PM, 3:00 PM - 7:30 PM Wednesday: 3:00 PM - 8:00 PM Thursday: 1:00 PM - 6:00 PM Friday: 9:00 AM - 2:00 PM	2267483212	N1T	\N	\N	Dana McDonald\nM.OMsc	\N	https://linktr.ee/mcdonaldosteopathyandwellness
592	rho	mckenzie-counselling	McKenzie Counselling	101 Queensway West\nMississauga, L5B 2P7	\N	I m a gay registered social worker and activist, and I provide one-on-one and couples counselling.\nMy practice is strength-based and solution-focused, all within an anti-oppressive framework. I specialize in coming out, health and wellness, relationship issues, HIV/AIDS, self-esteem, loneliness, learning disabilities, school/career stress and development, as well as strategies for working towards personal goals and aspirations. I can offer support in managing life challenges that you are experiencing.\nI strive to create a safe environment, and welcome the opportunity to work with all members of the LGBTQ+ community. Through my interest and experience in both social and educational settings, I have created a strong and personal knowledge base to help empower and assist you. I know how important it is to create a sense of belonging both personally and within the community.	mckenziecounselling@gmail.com	\N	6478712162	L5B	\N	\N	Cameron McKenzie\nMSW, RSW	\N	\N
593	rho	mckenzie-counselling-msw	McKenzie Counselling – MSW	101 Queensway West\nMississauga, L5B 2P7	\N	I’m a gay registered social worker and activist, and I provide one-on-one, couples, and family counselling.\nMy practice is strength-based and solution-focused, all within an anti-oppressive framework. I specialize in coming out, health and wellness, relationship issues, HIV/AIDS, self-esteem, loneliness, learning disabilities, school/career stress and development, as well as strategies for working towards personal goals and aspirations. I can offer support in managing life challenges that you are experiencing.\nI strive to create a safe environment, and welcome the opportunity to work with all members of the LGBTQ+ community. Through my interest and experience in both social and educational settings, I have created a strong and personal knowledge base to help empower and assist you. I know how important it is to create a sense of belonging both personally and within the community.	mckenziecounselling@gmail.com	\N	\N	L5B	\N	\N	Cameron McKenzie\nMSW, RSW	\N	\N
594	rho	mclean-noble-psychologists	McLean Noble Psychologists	258 Main St. N.\n2nd Floor\nMarkham, L3P1Y7	\N	Psychotherapy and Assessment Services. Virtual and in-person	contact@mcleannoble.com	By Appointment	905-472-6622	L3P	\N	$160-225	\N	\N	https://www.mcleannoble.com
595	rho	mclean-psychology-centre	McLean Psychology Centre	110 Copper Creek Drive\nMarkham	\N	We offer a variety of services including:\nA one-time consultation,\nA few sessions to help you through a situation,\nA more structured, longer term intervention (e.g. for clinical conditions such as depression or anxiety),\nOr a Psychological or Psychoeducational Assessment.	sbuckingham@mcleanpsych.com	\N	1.844.266.6622, ext.41	\N	\N	\N	Shelly Buckingham\nRegistered Psychological Associate	\N	https://www.mcleanpsych.com
596	rho	mediate393	mediate393	393 University Avenue\nToronto, M5G 1E6	\N	Free and subsidized family mediation services for anyone going through separation or divorce. Free family law information and referrals to service providers. Available at all three Toronto family law courts.	info@mediate393.ca	\N	4165935393	M5G	\N	\N	Family mediators; family lawyers; information and referral coordinators	\N	https://www.mediate393.ca
615	rho	middlesex-london-health-unit	Middlesex-London Health Unit	50 King Street\nLondon, N6A 5L7	\N	We offer a sexually transmitted infection Clinic Monday and Wednesday from 5-7pm and Friday 830-10am. Everyone is seen if they arrive before closing time. No health card needed, no appointment, confidential, free STI treatment, free condoms, counselling and testing, pregnancy testing and referral, emergency contraception, free Hepatitis A and B vaccination, and needle exchange. Birth Control clinic is by appointment only. Health card is needed. Clinics offered Monday to Thursday at various times, with 2 evening clinics. Low cost birth control. Will accept prescriptions of brith control from community physicians. Translation services available if needed.	shaya.dhinsa@mlhu.on.ca	\N	519-663-5317	N6A	\N	\N	\N	\N	https://www.healthunit.com
597	rho	medifeet-clinic-orthotics-centre	MediFeet Clinic & Orthotics Centre	1840 Lakeshore Road West\nMississauga, L5J 1J7	\N	MediFeet Clinic & Orthotics Centre is a Foot Clinic located in the heart of Mississauga. It is your one-stop-shop for the very best in Podiatry care. The mission of our Foot Clinic is to enhance your well-being, so you can put your best foot forward.\nAt MediFeet Clinic, we constantly embrace new technology and equipment, ensuring our patients receives the most effective and comprehensive treatment, based on best practices within podiatric medicine.\nAt our Mississauga Foot Clinic, we employ experienced Chiropodists and Podiatrists that treat a variety of foot disorders, ranging from Corns & Calluses to Ingrown toenails & fungal nails. We specialize in orthotics, orthopaedic shoes, and compression stockings, as we firmly believe these products make a significant impact in enhancing the quality of life.\nChiropodists at our Mississauga Foot Clinic are committed to providing the finest podiatry care in a warm and friendly environment.\nKey Services we provide:\nKey Areas we service:	info@medifeetclinic.ca	\N	905-822-3338	L5J	\N	\N	Neha Arora\nHons.B.Sc, D.Ch	\N	https://www.medifeetclinic.ca
598	rho	medsexpert-clinic-pharmacy	medsExpert Clinic + Pharmacy	461 Church Street\nToronto, M4Y 2C5	\N	Specialize in Men’s Sexual Health, Offer Anonymous Testing for HIV and Hep C\nHIV counselling, prevention and treatment	pharmacist@medsexpert.ca	\N	(416) 922-6337	M4Y	\N	\N	Michael Fanous\nPharm D, HIV Pharmacist - owner and operator of LGBTQ+ pharmacy	\N	https://www.medsexpert.ca
599	rho	meg-boulanger	Meg Boulanger	Toronto, Toronto, ON M6K 1G7, Canada	\N	My name is Meg (she/her) and I am a Registered Psychotherapist (Qualifying) with the College of registered Psychotherapists of Ontario (CRPO). I am a queer intersectional feminist with nearly a decade of experience providing mental health support to youth and adults navigating complex issues in the education, health, and legal systems. My goal is to provide a safe, inclusive, trauma-informed environment for you to process, reflect, and grow on your own terms.\nMy main focus is individual treatment for teens and adults experiencing challenges like family conflict, burnout, addiction, and court system involvement. I typically integrate CBT, DBT, and ACT approaches in my practice. During sessions you can expect me to challenge your assumptions, provide psychoeducation, give active feedback, and facilitate reflection. Therapy is a collaborative process, so we’ll work together to determine what works for you.\nVirtual therapy sessions are open to clients anywhere in Ontario. Walk-and-talk therapy sessions are available in Toronto upon request. If financial barriers are preventing you from accessing therapy, sliding scale rates are available.	megbtherapy@gmail.com	Sunday-Thursday Flexible scheduling between 8:00am-9:00pm	1 (647) 697-8454	M6K	\N	Sliding scale range - $/Hour Minimum: 60 Maximum: 130	Meg Boulanger\nMA in Counselling Psychology, Registered Psychotherapist (Qualifying)	\N	https://www.gorendezvous.com/megbtherapy
600	rho	meg-leitold-psychotherapy	Meg Leitold Psychotherapy	692 Euclid Avenue\nToronto, M6G 2T9	\N	I provide trauma-focused integrative psychodynamic therapy services to adult individuals and couples. My services are queer, trans, kink, and sex worker positive and I aim to provide therapy that is rooted in an understanding of how various systems of oppression and marginalization affect our mental health.\nLike most therapists, I have several areas of practice in which I feel distinctly equipped to work. These include recovery from interpersonal trauma and abuse, including childhood sexual abuse, and work with clients who experience symptoms of complex posttraumatic stress and/or borderline personality disorder (BPD).\nI bring extensive experience to my work with LGBTTIQQ (lesbian, gay, bisexual, transgender, transsexual, intersex, queer or questioning) people and exploring issues of sexual orientation and gender identity. My practice also includes work with clients who engage in consensual bondage and discipline, dominance and submission, and sadomasochism (BDSM) practices. As a former sexual health educator and sexual assault counsellor, I have experience in supporting people living with HIV/AIDS; coping with diagnoses of sexually transmitted infections (STIs); nurturing diverse relationship models (including open relationships, polyamory, and non-monogamy); and healing from sexual trauma and interpersonal violence.	meg@megleitold.com	\N	416.901.9020 ext 320	M6G	\N	\N	Meg Leitold\nMEd, BA	\N	https://megleitold.com
601	rho	melanie-tapson-voice-care	Melanie Tapson Voice Care	107 Hamilton St\nToronto, M4M 2C7	\N	Gender Affirming Voice and Communication Training\nIf you are interested in finding or developing your most authentic voice, and keeping your voice healthy and sustainable while you do, I am happy to work with you.  Our work together can help you find a voice and communication style that feel both comfortable and authentic, and that you feel reflect your gender identity and are congruent with your gender expression.  As a registered speech-language pathologist, you may find that our sessions are covered by your supplemental insurance, as well.\nHere is some information about my approach to gender affirming voice and communication training (also sometimes referred to as “transgender voice therapy”):\nMost people want to know if I can help them find a higher or lower pitch. Therapy with me certainly can involve raising or lowering the pitch of your voice (depending on your goals), but it also often involves working on making your voice lighter (often perceived as a more feminine sound) or deeper (often perceived as a more masculine sound), and in all cases, more resonant and less effortful. Working on your voice doesn’t mean you have to conform to culturally-defined societal expectations of gender; these are just some of the aspects of finding a more authentic voice that many clients have expressed they want to work toward. Voice therapy with me also includes working on the other aspects of communication that help get your message across, such as the way you use your body when you communicate, the kinds of words and phrases you choose, and the way you express yourself. As well, we will explore how you would like to express your gender identity through voice and communication, examining together what makes the most authentic voice for you.\nI typically start with an in-depth 1-hour assessment session, where I get the chance to learn more about you and your goals, which helps me design the most effective approach to voice work for each individual person. Therapy sessions are typically between 30 minutes and an hour long, and often go in blocks of a few weeks’ worth of weekly or bi-weekly sessions, followed by a break for you to work on what we have explored and learned together. This is often followed up with another block of sessions to build on what you are learning and practicing. However, the length of individual sessions and how long we work together is always determined by a combination of your goals, how your voice changes from session to session, and how much support you feel you need, and this is a conversation we will always have together. Sessions may involve speaking, listening, writing, thinking, expressing, and reflecting on your work with your new voice, and they always involve practicing what you are learning and evaluating how you are feeling about your voice.\nI am proud of my connection to the LGBTQ2S+ community, and I maintain relationships with a variety of people, care providers, and resources that partner wonderfully with the work you’re doing on your voice. I’m also proud of my efforts to stay on top of the current best practices in voice therapy and in particular, in gender spectrum voice and communication work. I’ve taken a ton of supplemental training in this area, and I often present workshops and mentor SLPs who are new to this area of practice because I firmly believe we need more competent, confident, caring clinicians in this area, and I’m more than happy to help us all get there together.	info@melanietapson.com	Book an appointment during available hours at melanietapson.com/contact Appointments are typically available Tuesday to Thursday, between 10 a.m. and 3 p.m.	416-816-1856	M4M	\N	For session fees, see melanietapson.com/faq	Melanie Tapson\nMSc SLP (C) CCC-SLP Reg CASLPO	\N	https://www.melanietapson.com
602	rho	melissa-farias-asl-english-interpreter	Melissa Farias ASL/English Interpreter	Mississauga	\N	I am an LGBTQQ2S Ally providing interpretation services between American Sign Language and English to Deaf, deafened, hard-of-hearing and hearing (non-Deaf) individuals and groups in the city of Toronto.	messagemelissa@gmail.com	\N	4168238179	\N	\N	\N	Melissa Farias\nBA (Hons), AEIP, AVLIC/OASLI Member	\N	\N
603	rho	melisse-dedobbeleer	Melisse DeDobbeleer	375 St. Clair Street\nChatham-Kent, N7L3K3	\N	A counsellor in private practice with over 15 years of providing advocacy, counselling and support to the LGBTQIA2S+ communities.  Compassionate, warm, experienced and welcoming to ALL members of the community. This is one of the very few LGBTQIA2S+ specific services offered in Southwestern Ontario.	melisse@melissededobbeleer.com	Monday-Friday: 9 a.m. to 5 p.m.	519-358-1590	N7L	true	\N	private practice, Chatham-Kent Family Health Team\nB.Sc., M.S.W., RP	\N	http://ckfht.ca/healthcare-professionals/registered-psychotherapist-melisse-dedobbeleer/
604	rho	men-having-babies	Men Having Babies	\N	\N	Men Having Babies, Inc. is a nonprofit organization that was spun off in July 2012 from a program that ran at the NYC LGBT Center since 2005. It started as a peer support network for biological gay fathers and fathers-to-be, offering monthly workshops and an annual seminar.\nFor gay men who want to become parents through surrogacy, the Men Having Babies educational conferences are a rare opportunity to get under one roof a wealth of information, advice and access a wide range of relevant service providers – and from an unbiased non-profit organization.	\N	\N	\N	\N	\N	\N	\N	\N	\N
616	rho	midtown-medical	Midtown Medical	565 College Street\nToronto, M6G 1B2	\N	Comprehensive Care Family Medicine	theoffice@midtownmedical.ca	\N	416-538-6653	M6G	\N	\N	Shari Chung\nMD, CCFP	\N	https://www.midtownmedical.ca
617	rho	midwifery-clinic-stratford	Midwifery Clinic Stratford	243 Erie Street\nStratford, N5A 2M9	\N	Midwifery care for women and their families in Perth County and surrounding areas	stratfordmidwives@cyg.net	\N	519-271-3490	N5A	\N	\N	\N	\N	\N
618	rho	midwifery-collective-of-ottawa	Midwifery Collective of Ottawa	88 Centrepointe Drive\nOttawa, K2G 5K7	\N	Personal, client-centred care for pregnancy, birth and 6 weeks postpartum.	reception@midwiferycollective.com	\N	6137302323	K2G	\N	\N	Mianh Lamson\nRegistered Midwife	\N	https://www.midwiferycollective.com
605	rho	metis-nation-of-ontario	Metis Nation of Ontario	226 May Street South\nThunder Bay, P7E 1B4	\N	The Métis Nation of Ontario (MNO) offers culturally relevant victim services within all of its Healing and Wellness programs to address, deter and end violence against Métis women and children, and also against the LGBTQ+ community. These services address the mental, physical, emotional and spiritual impacts of victimization.\nThe MNO Victim Services Program is being offered in MNO community offices throughout the province. The MNO has two Victim Services Coordinators dedicated to:\n– Assisting victims of violence\n– Supporting MNO Healing and Wellness community workers with expertise, support and clarification when helping victims of crime\nOur services are “status blind”, meaning that you do not necessarily have to be Metis to utilize our program. We accept everyone, but our services have a Metis focus/lens to them. We are also a province-wide program.	MeganM@metisnation.org	\N	(807) 624-5025 ext. 309	P7E	\N	\N	Megan Muloin	\N	https://www.metisnation.org/programs/health-wellness/mno-victim-services/
606	rho	metropolitan-community-church-of-toronto	Metropolitan Community Church of Toronto	115 Simpson Avenue\nToronto, M4K 1A1	\N	We are a Christian denomination with a special outreach to the LGBT community in Toronto.\nOur Vision is to be Canada’s leading, progressive, diverse community of faith.\nOur Mission is to build bridges with a vibrant spirituality that transforms lives and transforms the world.\nWe offer a special service to LGBT refugee claimants as well as sponsoring LGBT refugees from overseas.\nWe also offer spiritual support workshops for refugees to help them reconnect with their God.\nOur Sunday services are at 9am, 11am and 7pm.	bbrenie@mcctoronto.com	\N	416 406 6228 ext 129	M4K	\N	\N	\N	\N	https://www.mcctoronto.com
607	rho	michael-obrien-massage-therapy	Michael O’Brien Massage Therapy	565 Sherbourne Street\nToronto, M4X 1W7	\N	Registered Massage Therapy\nSpecialities in:\nSwedish/Deep Tissue\nMyofascial Release\nCranial Sacral Therapy\nMuscle Energy\nFinished 3rd year of Study in Manual Osteopathy at the Canadian College of Osteopathy in Toronto.\nFor information on locations where I practice and hours visit www.mikeobrmt.com.	mikeobrmt@gmail.com	\N	6477469708	M4X	\N	\N	Michael O'Brien\nRMT	\N	https://www.mikeobrmt.com
608	rho	michela-trimboli-psychotherapy-and-consulting-services	Michela Trimboli Psychotherapy And Consulting Services	355 Waverley Street\nSecond Floor\nOttawa, K2P 0W4	I can provide secondary assessments for transition-related bottom surgeries		michelatrimboli2019@gmail.com	Monday-Friday 11 a.m. - 7 p.m.	343-000-0000	K2P	\N	$150/hour	Michela Trimboli\nMSW, RSW	\N	https://www.psychologytoday.com/ca/therapists/michela-trimboli-psychotherpay-consulting--ottawa-on/939201
609	rho	michele-rich-psychotherapy	Michele Rich, Psychotherapy	22 Second Street\nCollingwood, L9Y 1E3	\N	Psychotherapy	mrich.healing@gmail.com	\N	705-444-3372	L9Y	\N	\N	Michele  Rich\nRegistered Psychotherapist	\N	https://mrich.ca
610	rho	michelle-baer-child-and-family-therapy	Michelle Baer, Child and Family Therapy	357 Jane Street\nToronto, M6S 3Z3	\N	I offer Individual, Group and Family Therapy for children, youth and their families, ages 3-17 years, in my private office.\nI am a Registered Psychotherapist with the College of Registered Psychotherapists of Ontario, and a Canadian Certified Counsellor with the Canadian Counselling and Psychotherapy Association. I completed my Master of Arts in Creative Arts Therapies (Drama Therapy) and a post-graduate Certificate in Child and Play Therapy.\nIn addition to these formal qualifications, I am a creative, playful and dynamic individual, who is passionate about supporting children, youth and families in sharing their stories, witnessing, validating and guiding them through the process of healing, growth and change. Play Therapy and Creative Arts Therapies offer clients the opportunity to express themselves, to learn appropriate coping skills, and resolve challenges they are facing through a creative and client-centred process.\nMy areas of expertise are Play Therapy and Creative Arts Therapy; LGBTQ children, youth and families; Adoption; Separation and/or Divorce; Grief and Bereavement; Medical Issues; Emotional, Behavioural, and/or Social challenges; Autism, ADD/ADHD, Learning Disabilities and other Developmental concerns; Trauma; Anxiety, Depression, Eating Disorders and other Mental Health concerns.	michelle@michellebaer.ca	\N	647-741-0435	M6S	\N	\N	Michelle Baer\nMA, RP, CCC	\N	https://www.michellebaer.ca
611	rho	michelle-harrison-ma-rp-ccc-counselling-psychotherapy	Michelle Harrison, MA, RP, CCC Counselling & Psychotherapy	1095 1st Avenue West\nOwen Sound, N4K 4K7	\N	I provide psychotherapy, counselling and coaching services for individuals living in Meaford, Owen Sound and the surrounding areas of beautiful Grey-Bruce County. I am an LGBTQ2+ ally and have undergone significant training to provide multiculturally competent services that honour issues of diversity. I place an emphasis on establishing a non-judgmental, collaborative and empowering therapeutic relationship where you feel safe, heard and understood.	mhpsychotherapy@gmail.com	\N	519.800.6416	N4K	\N	\N	Michelle  Harrison\nRegistered Psychotherapist, Canadian Certified Counsellor	\N	https://integratedtherapy.ca
612	rho	michelle-m-melanson-psychotherapy	Michelle M. Melanson Psychotherapy	180 Bloor Street West\nToronto, M5S 1T6	\N	Trauma informed, anti-oppressive therapy aimed at helping people get unstuck and connected to their natural capacities for growth and change.	mmelanson@bell.net	\N	647-878-3350	M5S	\N	\N	Michelle M. Melanson\nMSW, RSW	\N	https://michellemelanson.ca
613	rho	michener-institute-chiropody-clinic	Michener Institute – Chiropody Clinic	222 Saint Patrick Street\nToronto, M5T 1V4	\N	The Michener Chiropody Clinic offers hands-on training to Chiropody students and care to regional clients in a clinical setting under the supervision of faculty who are also certified chiropodists.\nChiropodists are primary healthcare providers who treat people of all ages and activity levels. A referral or previous diagnosis is not required to visit a Chiropodist. We offer general and preventative foot care for a wide range of foot conditions. We treat at all the levels of the foot, from surface skin infections to bone and joint pain. Your first visit will include a full history and foot exam which will allow us to develop a comprehensive management plan to meet your foot care needs. Chiropody services may be covered by your third party insurance, check with your plan administrator for more details.\nFor more information or to book a treatment, contact the clinic at 416-596-3108.	\N	\N	416-596-3108	M5T	\N	\N	\N	\N	https://michener.ca/discover-michener/chiropody-clinic/
614	rho	michiko-caringal-pelvic-health-physiotherapist-at-bloor-park-physiotherapy	Michiko Caringal, Pelvic Health Physiotherapist at Bloor Park Physiotherapy	726 Bloor Street West\nToronto, M6G 1L4	\N	A registered Physiotherapist with specialized training in pelvic health can be successful treating individuals with urinary or fecal incontinence, pelvic organ prolapse, pain before or after intercourse, rectus diastases, pelvic girdle pain, as well as pre and post natal changes. Pelvic health care applies to both women and men.\nA thorough examination often includes both an external and internal assessment. This allows the therapist to properly evaluate all potential factors contributing to the dysfunction, and develop an appropriate plan of care to address your individualize goals effectively.	michiko@preferredrehab.ca	\N	6473684400	M6G	\N	\N	Michiko Caringal\nPelvic Health Physiotherapist	\N	https://bloorparkphysiotherapy.ca/
620	rho	midwifery-collective-of-ottawa-3	Midwifery Collective of Ottawa	88 Centrepointe Drive\nOttawa, K2G 6B1	\N	Emi (Elm) is a queer, non-binary Registered Midwife serving birthing families in the Ottawa area. At their core they value providing safe, inclusive, anti-oppressive, and individualized care to their clients. Registered Midwives are primary care providers fully funded under OHIP and midwifery clients may choose to birth at home, hospital, or birth centre. Emi is committed to honouring every birthing family’s unique and complex needs and the importance of informed choice, regardless of what path their birthing journey takes. Emi also has experience supporting induced lactation and co-nursing.	reception@midwiferycollective.com	\N	613-730-2323	K2G	\N	\N	Emi (Elm) Klemic\nRM, MA	\N	https://www.midwiferycollective.com
621	rho	midwives-collective	Midwives Collective	1203 Bloor Street West\nToronto, M6H 1N4	\N	Our practice provides midwifery care to LGBTQ folks. We provide primary care during your pregnancy, birth, and 6 weeks postpartum. We use an informed choice model. You have the choice of a home or hospital birth. We are a teaching practice, so there is a good chance of student involvement in your care. We also provide prenatal classes to our clients.\nWe encourage you to call our clinic as early in pregnancy as possible as the demand for midwives exceeds the availability.	midwivescollective@bellnet.ca	\N	4169638842	M6H	\N	\N	\N	\N	\N
622	rho	midwives-grey-bruce	Midwives Grey Bruce	265 8th St E\nOwen Sound, N4K 1L2	\N	A group of 12 midwives serving Grey-Bruce Counties. Inclusive care and welcoming space for lgbtqia2s+ clients and their families.	noemail@noemail.com	Mon-Fri 8:30-4:30	519-371-2886	N4K	true	\N	\N	\N	http://midwivesgreybruce.com/
623	rho	midwives-of-brampton-and-halton-hills	Midwives of Brampton and Halton Hills	50 Sunny Meadow Boulevard\nBrampton, L6R 1X5	\N	Providing prenatal care, pregnancy, and postpartum care for 6 weeks postpartum	bramptonclinic@mobhh.ca	\N	9054586997	L6R	\N	\N	Registered Midwives	\N	\N
624	rho	midwives-of-mississauga	Midwives of Mississauga	2227 South Millway\nMississauga, L5L 3R6	\N	Primary caregivers for low risk pregnant people. Providing pregnancy care, care through labour and birth and care after birth to the pregnant patient and their newborn for six weeks after birth.	info@midwivesofmississauga.ca	\N	9055699995	L5L	\N	\N	Remi Ejiwunmi\nRegistered Midwife	\N	https://www.midwivesofmississauga.ca
625	rho	mike-ware-psychotherapy	Mike Ware Psychotherapy	49 Meadowvale Drive\nSt. Thomas, N5P 4P3	\N	My practice as a psychotherapist has covered the past 36 years and has involved private practice,residential treatment, psychiatric hospital and outpatient treatment, community based mental health program and community based private counselling centre. My most intensive work has been centred on individual and group psychotherapy with clients living with severe mental illness, complex posttraumatic stress disorder and the range of emotional and relational difficulties. My model of practice is based on relational psychoanalytic theories and incorporates an appreciation of the mutual influences of the therapy relationship and the impingements of the client’s relational and cultural world. My fees are relatively low at $50.00 per session and I am covered by a number of health benefit plans provided by employers.	mikeware@sympatico.ca	\N	519-6379956	N5P	\N	\N	Mike Ware\nmsw. rsw	\N	\N
626	rho	milestone-health-services	Milestone Health Services	1011 Upper Middle Rd., East\nSuite 1461\nOakville, L6H5Z9	\N	Milestone Health Services proudly provides premium home care services to clients looking for the very best in-home health care solutions. Founded by a nurse, we have been providing exceptional care for over 8 years.  For peace of mind, our services are nursed managed to adhere to best professional practices in the health care industry. Our clients benefit from Companion Care, Personal Support, Nursing Care and other more specialized services such has cognitive stimulation therapy. The process is easy, it all starts by reaching out to our office and taking to a Client Care Representative who will provide you with guidance and a complimentary consultation. We are proud members of the Canadian Gay & Lesbien Chamber of Commerce.	info@milestonehealth.ca	24 hours a day, 7 days a week,	1-833-392-7366	L6H	3001 Hospital Gate, Oakville, ON1-833-392-7366Directions\n301 - 300 Plains Rd West, Burlington, ON1-833-392-7366Directions	Fee for Service, also approved providers for: WSIB, Interm Federal Health Program and Veterans Affair Canada	\N	\N	http://www.milestonehealth.ca/
627	rho	misty-saikaley-asl-english-interpreter	Misty Saikaley ASL-English Interpreter	\N	\N	I am an LGBTQQ2S+ ally ASL-English interpreter providing interpreting services to Deaf, deafened, hard-of-hearing and hearing (non-Deaf) members of the community. I work on a free-lance basis and generally book services one to two weeks in advance.	\N	\N	\N	\N	\N	\N	\N	\N	\N
628	rho	mj-wass-rmt	MJ Wass, RMT	320 Danforth Avenue\nToronto, M4K 1N8	\N	MJ Wass, a Registered Massage Therapist (College of Massage Therapists of Ontario) for 23 years, welcomes adults, children and infants to her practice. In addition to treating soft tissue and joint conditions, she incorporates several modalities –  acupressure, aromatherapy, craniosacral therapy, reflexology, reiki, rhythmic mobilization, qi gong, shiatsu, swedish massage – to facilitate deep relaxation, stillness and relief from anxiety, depression, stress and the effects of trauma.\nMJ Wass is LGBTQ positive and has worked with queer and trans folks.	stillnessrestores@mjwass.com	\N	4162645949	M4K	\N	\N	MJ Wass\nRMT	\N	https://www.mjwass.com
629	rho	mmpr-counselling	MMPR Counselling	491 Church Street\nToronto, M4Y 2C6	\N	We are a medical cannabinoid clinic, offering counselling, education and registration (with Health Canada Licensed Producers) for anyone seeking medical marijuana.\nWe do not sell or distribute any products, but rather our RPN educators will walk anyone through the endocannabinoid system, medical cannabis properties, THC and CBD ratios, selecting medical cannabis strains from a Licensed Producer, dosage tracking, routes of consumption, legalities and they will share many additional resources.\nWe are here to advocate for knowledge and to support everyone to ensure they feel comfortable and confident as they move forward. We understand this is a last resort medical option for many, therefore, it must be handled professionally to ensure desirable outcomes are achieved.	Info@mmprcounselling.com	\N	416-413-9434	M4Y	\N	\N	MMPR Counselling	\N	https://www.mmprcounselling.com
630	rho	mn-counselling-services	MN Counselling Services	149 Second Avenue\nOttawa, K1S 2H6	\N	Confidential, professional services for clients who are seeking individual, relationships, and sex therapy. Multilingual services. Kink and poly friendly. Newcomer LGBT services.	info@megonerses.com	\N	613.266.6203	K1S	\N	\N	Mego Nerses\nMEd, CCC	\N	https://www.megonerses.com
631	rho	mobo-health	MOBO HEALTH	Toronto	\N	Mobile downtown Toronto and North York clinic location. Sensitive, confidential medical alternative care open to patients of all levels of health. Specialized services include myofascial/joint injury & rehabilitation (Active Release / ART), Activator, KT taping, postural complaints and related pain & discomfort, MVA, ESIB, custom orthotics, compression stockings, patient education & rehabilitative exercises.	info@mobohealth.com	\N	6473238199	\N	\N	\N	Samuel Tang\nDC	\N	https://mobohealth.com
632	rho	mobo-health-2	MOBO HEALTH	88 Blue Jays Way\nToronto, M5V 0L7	\N	Mobile downtown Toronto & North York clinic location. Sensitive, confidential care open to patients of all ages and all levels of health. We invite all patients for complimentary consults to see if we our services can benefit you.\nFully licensed chiropractor focused on postural pain & tension relief (ie. FTM binding), myofascial release techniques (Active Release/ART), Activator, KT taping, custom orthotics, compression stockings, MVA, ESIB, lifestyle education and rehabilitative exercises. Extended health insurance approved methods and products.	info@mobohealth.com	\N	6473238199	M5V	\N	\N	SAMUEL TANG\nDC	\N	https://MOBOHEALTH.COM
633	rho	mogai-mentors	MOGAI Mentors	140 King Street East\nHamilton, L8N 1A5	\N	Mentoring program for 2SLGBTQIA+ kids and youth age 8-15, art/recreational/cooking and gardening programs through mentoring, educational workshops, family support, peer counseling.	info.mogaimentors@gmail.com	\N	\N	L8N	\N	\N	Sean Cullen\nSocial service worker	\N	https://www.mogaimentors.org
634	rho	momenta-clinic	Momenta Clinic	5100 Rutherford Rd\nVaughan, L4H2J2	\N		hello@momentaclinic.com	Monday to Friday: 8:00 a.m. to 5:00 p.m.	905-455-7082	L4H	true	$170-210/hour	\N	\N	https://www.momentaclinic.com/
635	rho	monica-adair-psychotherapy	Monica Adair Psychotherapy	Barrie, L4N 3J7	\N	The journey of therapy can seem intimidating at first. It is my intention to create an atmosphere of growth and inner peace. Through collaboration and empowerment, this service exists to benefit all individuals searching for the fullness of life.\nI strongly believe that emotional and mental wellness make up a vital part of achieving and maintaining overall health and living a meaningful life. It is crucial for engaging in healthy and fulfilling relationships with self and others and plays an essential role in physical health and quality of life.\nWhatever your reason for seeking counselling, I invite you to browse through www.monicaadair.com to decide if Monica Adair Counselling Services will be the right fit for you.	monica@monicaadair.com	Wednesday-Saturday: 9 a.m. to 5 p.m.	705-309-0503	L4N	\N	\N	Monica Adair\nM.A. Counselling psychology, CCC, SEP	\N	https://www.monicaadair.com
636	rho	monica-staffen-massage-therapy	Monica Staffen Massage Therapy	\N	\N	I offer Registered Massage Therapy which has many benefits to those seeking pain relief, prevention and maintainence of the body’s soft tissues. Massage therapy is also helpful in stress management as well as many other conditions affecting the human body.\n…I offer DIRECT BILLING to most insurance companies. Call to inquire or book an appointment. 519.860.0087	\N	\N	\N	\N	\N	\N	\N	\N	\N
637	rho	morningstar-family-medicine	Morningstar Family Medicine	1018 Pelham St\nPelham, L0S1E4	I can provide transition related surgery assessments for top or bottom surgeries	Full scope family medicine practice including LGBTQ* friendly environment and care.	none@none.xa	Mon to Thurs 9 am - 4 pm	905-892-5111	L0S	\N	\N	Dr Michael Milo	\N	http://www.morningstarfamilymedicine.ca
638	rho	mosaic-physiotherapy	Mosaic Physiotherapy	50 St. Clair Ave East\n4th Floor\nToronto, M4T 1M9	\N	We are a community physiotherapy clinic located in the heart of midtown Toronto at Yonge and St. Clair Ave East. Our physiotherapy clinic offers: pelvic health physiotherapy, post-cancer rehab, vestibular therapy and concussion rehab. In addition, we provide special services such as acupuncture, dry needling, and massage therapy.\nOur Vision:\nWe chose the name Mosaic because we see people as made up of many different parts or ‘pieces’ which come together to create the unique individual that you are. Dysfunction, illness and aging can affect and change the different parts that make-up who you are. At Mosaic, we consider all the pieces and help put them back together to create a whole again.\nOur Philosophy:\nWe believe everyone should be provided with high quality care and respect. We believe in working together as a team. Our motto is “Putting the Pieces Together”.	hello@mosaicphysio.com	Monday: 12 pm - 8 pm Tuesday: 10 am - 8 pm Wednesday: 12 pm - 8 pm Thursday: 10 am - 8 pm Friday: 12 pm - 8 pm Saturday: 10 am - 4 pm Sunday: Closed	(416) 901-1278	M4T	\N	https://mosaicphysiotherapy.com/price-list/	\N	\N	https://mosaicphysiotherapy.com/
639	rho	moss-psychology	Moss Psychology	Belleville	\N	Psychological assessment and therapy for all ages (children, adolescents, adults). Individual therapy, Couples counselling, Family Therapy.	andrew@mosspsychology.com	\N	613-689-7783	\N	\N	\N	\N	\N	https://www.mosspsychology.com
640	rho	moss-psychology-2	Moss Psychology	154 Cannifton Road North\nBelleville, K0K 1K0	\N	Mental health assessment and therapy.	reception@mosspsychology.com	Monday - Friday: 9 a.m. to 4 p.m.	613-689-7783	K0K	\N	\N	Andrew Moss\nCPsych	\N	https://www.mosspsychology.com
641	rho	move-forward-counselling	Move Forward Counselling	717 Bloor Street West\nToronto, M6G 1L5	\N	Amy Babcock, Registered Clinical Social Worker/Psychotherapist provides confidential, clinically-informed counseling/therapy services in a comfortable office space located at the Toronto Healing Arts Centre (across from Christie subway station) in downtown Toronto. Amy’s work is informed by 18 years of post-MSW experience and extensive work in the LBGTQ2I+ communities. Amy worked for many years with a hospital-based family health team and was part of an initiative to increase capacity for trans care including providing training and developing protocols for trans surgical assessments in primary care. Amy is able to provide assessment and second letter writing for clients seeking gender confirmation surgeries/SRS as well as offer general counseling/psychotherapy around a range issues that may can come up for queer and trans identified people. Evening and weekend appointment are available. www.moveforwardcounselling.ca	a_babcock@hotmail.com	\N	416-893-1973	M6G	\N	\N	Amy Babcock\nMSW, RSW	\N	https://www.moveforwardcounselling.com
642	rho	moving-together-dance-movement-psychotherapy	Moving Together Dance Movement Psychotherapy	1768 Danforth Ave\nToronto, M4C1H8	\N	My name is Jessica Houghton and I offer individual and group Dance Movement Psychotherapy services in Toronto’s east end. I feel drawn to supporting clients in deepening their relationship with themselves, accessing their body, feelings, emotions, and agency, and integrating parts of themselves that may have been lost or disowned due to past circumstances. I believe in the transformative power of dance and creative movement, and have experienced time and again how embodiment can lead to greater ease in identifying, experiencing, and expressing emotions.\nMy goal as a therapist is to create a supportive and sensitive space for my clients to engage deeply in their process and find empowerment through developing their resources and creative and expressive capacity. Through my lived experience as a queer woman navigating the complex world of polyamorous relationships, I hope to offer my clients an empathetic, compassionate, and affirming experience, wherever they are in their journey.	movingtogetherDMP@gmail.com	\N	647-237-9722	M4C	\N	\N	Jessica Houghton\nRegistered Psychotherapist	\N	https://www.moving-together.ca
665	rho	nicholas-fink	Nicholas Fink	Virtual\nToronto, M5A 4S3	\N		nick@mantrapsychotherapy.ca	Variable	(437) 747-5531	M5A	\N	$130	Nicholas Fink\nRegistered Psychotherapist (Qualifying)	\N	https://www.psychologytoday.com/ca/therapists/nicholas-fink-toronto-on/906738?sid=62055b7f5a734&name=nicholas+fink&ref=1
643	rho	music-of-smiles-dental-hygiene-clinic	Music Of Smiles Dental Hygiene Clinic	3 Irwin Avenue\nToronto, M4Y 1Z8	\N	Music Of Smiles’ Dental Hygiene Clinic has been created with people like You in mind.\nIn a world where many avoid the dentist due to high cost or anxiety, we help You regain the trust through a cozy and calm environment, individualized care and affordable services of high quality.\nWe specialize in Teeth Cleaning, Polishing & stain removal, Whitening, Sensitivity, temporary Fillings (no needle/drilling), Sealants and others.\nPut your trust in us and we’ll help You maintain your oral health for many years to come.	MusicOfSmiles@yahoo.com	\N	647.338.1353	M4Y	\N	\N	Music Of Smiles Dental Hygiene Clinic\nRegistered Dental Hygienist	\N	https://www.MusicOfSmiles.ca
644	rho	muskoka-community-health-hub-wahta-site	Muskoka Community Health Hub: Wahta Site	2350 Muskoka District Road 38\nBala, P0C 1A0	\N	Primary Care Services including:	\N	Monday to Thursday: 9 a.m. - 4 p.m. Friday: 9 a.m. - 12 p.m. By appointment only.	705-762-1274	P0C	\N	\N	Dana Strength\nNP-PHC	\N	https://www.wahtamohawks.com/nursing-station/
645	rho	muskoka-health-hub-port-carling-site	Muskoka Health Hub: Port Carling Site	Port Carling, P0B 1J0	\N	\nPrimary Care Services including:\n	\N	\N	705-394-8535	P0B	\N	\N	\N	\N	https://www.muskokacommunity.ca/
646	rho	muskoka-mobile-health-hub	Cottage Country Family Health Team – Mobile Health Hub	1035 Southwood Rd\nSevern Bridge, P0E 1N0	\N	Mobile Health Hub providing primary care services to remote areas within Muskoka – our locations include Port Sydney, Vankoughnet and Severn Bridge, but we serve all of Muskoka – Gravenhurst, Bracebridge and Huntsville.\nMondays & Wednesdays: Severn Bridge Community Hall (1035 Southwood Rd, Severn Bridge)\nTuesdays & Thursdays: Port Sydney Fire Hall (387 South Mary Lake Rd., Port Sydney)	\N	\N	866-545-0811	P0E	387 South Mary Lake RdDirections	\N	Shereen Worrad\nPrimary Care Nurse Practitioner	\N	https://ccfht.ca/
647	rho	my-online-art-therapy	My Online Art Therapy	London	\N	Connect from anywhere in Canada to find emotional healing and wellness through art making at My Online Art Therapy. Creative expression in an art therapy session helps to release trauma, depression, anxieties, stress and more. Online Art Therapy is a form of telehealth that provides psychotherapy online. Confidentiality, especially for LGBTQ+ youth, young adults, and post-secondary students, is an important factor. Online art therapy can provide that safe healing space. My sessions are affordable and I offer free intake sessions to see if art therapy is a good fit.	cb@myonlinearttherapy.com	\N	18333332585	\N	\N	\N	Christel Bodenbender\nPost-Masters Certificate in Art Therapy	\N	https://www.myonlinearttherapy.com
648	rho	mylife-counselling-guelph-mark-nixon-registered-psychotherapist	MyLife Counselling Guelph – Mark Nixon, Registered Psychotherapist	Guelph	\N	I provide individual and couples counselling to adults in Downtown Guelph. I specialize in anxiety, trauma, anger management, grief and loss.	mark@marknixon.ca	\N	226-780-0212	\N	\N	\N	Mark Nixon\nRegistered Psychotherapist	\N	https://counselling-guelph.ca
649	rho	nadia-saad-psychotherapy	Nadia Saad Psychotherapy	216 Schell Avenue\nToronto, M6E 2T1	I can provide secondary assessments for transition-related bottom surgeries	I am a feminist and trauma-informed private practitioner of psychotherapy,  trained in Narrative therapy, Mindfulness meditation and Somatic experiencing, among other modalities. I practice with a very serious commitment to  anti-colonial and anti-oppressive practice.\nI work with individuals, couples, families, and groups, of many different lived experiences and realities.\nI approach each and every individual whom I counsel with an openness and desire to learn about your unique story, desired therapy outcomes, and how specifically to be a good support person to you.\nI am registered as an NIHB & IRS-RHSP therapist, which means that I can provide fully-funded therapy to most Indigenous folks (http://www.hc-sc.gc.ca/fniah-spnia/services/indiresident/irs-pi-eng.php).	nadia.y.saad@gmail.com	Wednesdays, Thursdays and Fridays, 11am - 8pm	6479396265	M6E	\N	$140-160, self select	Nadia Saad\nMSW, RSW	\N	https://nadiasaadpsychotherapy.com
650	rho	nan-keyser-psychotherapy	Nan Keyser Psychotherapy	30 Elsie Lane\nToronto, M6P 3N1	\N	I provide individual and couple therapy and counselling for adults with a non-judgmental, mindful, compassionate, and anti-oppressive approach in the central/west end of Toronto. I welcome clients of all backgrounds, gender and sexual identities and orientations. I accept most insurance plans.	nankeyser@gmail.com	\N	416534-0655	M6P	\N	\N	Nan Keyser\nRegistered Psychotherapist, Masters of Education in Counselling Psychology Ontario Society of Psychotherapists	\N	https://www.torontopsychotherapyandcounselling.com
651	rho	naomi-reesor	Naomi Reesor	57 John St S.\nHamilton , L8N 2B9	\N		naomi@thecompassionproject.ca	Monday 10:00AM - 7:00PM	(905) 512-1233	L8N	\N	120.00	Naomi Reesor\nMA, MEd, Registered Psychotherapist (Qualifying)	\N	https://www.thecompassionproject.ca/
652	rho	naturopathic-fertility-care	Naturopathic Fertility Care	2 Carlton Street\nToronto, M5B 1J3	\N	Alan and Zeynep are licensed naturopathic doctors, who provide care to individuals and couples who are looking to grow their families. Please visit our website for more information.	info@atozwellness.ca	\N	4165911535	M5B	\N	\N	Alan and Zeynep  Vu\nND	\N	https://www.atozwellness.ca
653	rho	negar-sadeghi-psychotherapy	Negar Sadeghi Psychotherapy	32 Massey Street\nToronto, M6J 3W4	\N	I am a registered psychotherapist for over 19 years with extensive training and education in the field of therapy. I have worked in a tertiary hospital in Toronto, Ontario as a therapist, trainer, and ethno-cultural specialist. I have worked with diverse people from all walks of life. I am respectful of all people of gender orientations, religious, spiritual and cultural backgrounds.\nI provide services and therapy for substance addiction, behavior dependencies (gambling, gaming and technology over use), depression, anxiety, identity issues, relationship difficulties, stress, anger, emotional challenges, spiritual dilemmas (meaning and purpose in life), life transitions, divorce, separation, grief and loss.\nI also provide consultation for parents (including adult children), families and partners affected by a loved one’s addiction and mental health issues.\nFor further information, please feel free to check out my website: www.negarsadeghipsychotherapy.ca.\nlooking forward to discussing how I might be of assistance to you.	sadeghinegar2018@gmail.com	\N	647-952-1931	M6J	\N	\N	Negar Sadeghi\nMA-Master in Counselling Psychology	\N	https://www.negarsadeghipsychotherapy.ca
654	rho	new-beginning-counselling	New Beginning Counselling	355 Ridge Road North\nFort Erie, L0S 1N0	\N	Individual and couple counselling available. An approved service provider. Gender and sexuality issues addressed	newbeginning.counselling@gmail.com	\N	289-214-1574	L0S	\N	\N	New  Beginning\nRSW	\N	https://www.anewbeginningcounselling.com
718	rho	parachute-therapy-wellness	Parachute Therapy & Wellness	900 Guelph St\nSuite 408\nKitchener, N2H 5Z6	\N	Psychotherapy for individuals, partners, and families (age 7+). Currently serving KW, Guelph, and surrounding areas; can provide phone or video services to any Ontario resident.	info@parachutetherapyandwellness.com	Mon 9 am-2 pm, Tues 2 pm-7 pm, Weds 9 am-2 pm, Thurs 2 pm-7 pm	(226) 790-4055	N2H	\N	Sliding scale range - $/Hour Minimum: 135 Maximum: 150	Liz\nTimmers	\N	http://www.parachutetherapyandwellness.com
655	rho	new-connections-counselling-services	New Connections Counselling Services	Niagara Falls, L2J 2P1	\N	I provide counselling and psychotherapy to adults living anywhere in Ontario via teletherapy or in-person for those living in the Niagara area. My treatment specialties include depression, anxiety, PTSD, relationship issues, substance use/addictions and grief/loss and HIV/AIDS. For over 20 years, I have provided  mental health services to members of LGBT2SQ communities, including 10 years providing support to people living with HIV/AIDS. I am well-versed with a range of mental health issues affecting members of LGBT2SQ communities, including disclosure, stigma, discrimination, health equity, transition, substance use and positive sexuality.\nAt New Connections (NC), you are at the centre of your recovery. You are the expert on your life. I work with you to mobilize the natural healing force that already resides within your mind-body system. Moreover, I believe that the meaning and importance of your mental health cannot be defined simply by a diagnosis or a set of symptoms. I provide counselling services that foster critical dialogue and facilitate an exploration of your mental health in all its dimensions: cultural, social, physical, sexual, emotional and spiritual. This involves developing the self-knowledge, resources and abilities that foster adaptive ways of relating to yourself and others. Making new connections is essential to increasing your resilience, your capacity to bend and flow: a step-by-step path that leads to creating positive change through self-awareness, self-acceptance and self-determination. I am here to share your journey toward equanimity, balance and peace of mind.\nHow you are uniquely connected (or not) to yourself, others and your communities is fundamentally important to my approach. I employ a range of therapeutic practices and principles to create an approach that facilitates health-restoring connections in your life. I fit the therapy around you rather than trying to fit you into the therapy. I help to identify counselling goals that are relevant and useful to you with respect to moving forward in your life. Through a dialogic, client-centred process, I explore the meanings and impacts of your mental health experiences, including past, present and future challenges. Deepening your understanding of your mental health is an essential first step in creating positive personal change.	newconnectionscounselling@gmail.com	Monday - Friday 9:00 to 5:00	905-933-1550	L2J	\N	$125/session (individual)	Duane Williams	\N	https://www.newconnectionscounselling.com
656	rho	new-moon-counselling	New Moon Counselling	69 Bridgeport Rd E\nWaterloo, N2J2K1	\N	We provide individual, couples, and family therapy for children, youth and adults. Our therapists focus on building a strong relationship with clients to support them through anxiety, depression, relationship concerns, life stressors, LGBTQ2A+ issues, trans issues, self-esteem, grief, and more. Book a free virtual consultation with one of our amazing therapists! Can’t wait to meet you.	ihammoud@newmooncounselling.com	Monday - Thursday 9:30am to 8:30pm Friday 9:30am to 5pm	519-584-4240	N2J	\N	Individual Session $135; Couples/Family Session $160	Ivonne Hammoud\nMSW, RSW	\N	https://www.newmooncounselling.com
657	rho	new-moon-psychotherapy	New Moon Psychotherapy	60 Atlantic Avenue\nSuite 200\nToronto, M6K 1X9	\N	New Moon Psychotherapy is a team of Registered Psychotherapists and Clinical Social Workers whose expertise is in treating post traumatic stress and related difficulties such as anxiety and depression, post traumatic stress disorder (PTSD and Complex PTSD), substance use and addictions, and non-suicidal self-injury and emotion dysregulation. We work extensively with survivors of sexual violence including childhood sexual abuse as well as those who have experienced emotional and physical abuse, bullying, war and near death experiences.\nWe also offer couples and family therapy and welcome couples and families affected by trauma.\nNew Moon Psychotherapy is committed to using results oriented and evidence-based approaches.\nWe love what we do and stay current through ongoing training and consultation.	info@newmoonpsychotherapy.ca	Monday to Friday: 9 a.m. to 8 p.m. Saturday and Sunday by request	6472033023	M6K	\N	Sliding scale range - $/Hour Minimum: 100 Maximum: 190	\N	\N	https://www.newmoonpsychotherapy.ca
658	rho	new-path-psychology	New Path Psychology	300 John Street\nMarkham, L3T 5W4	\N	New Path Psychology offers comprehensive psychological assessments, evidence-based treatments, and school consultations for children, adolescents, and young adults. Visit our website to learn more.	info@newpathpsychology.ca	\N	1 647 946 2609	L3T	\N	\N	Cathy Ierullo\nRegistered Psychologist	\N	https://newpathpsychology.ca
659	rho	new-path-youth-family-services-of-simcoe-county	New Path Youth & Family Services of Simcoe County	165 Ferris Lane\nBarrie, L4M 2Y1	\N	New Path Youth and Family Services of Simcoe County is an accredited children’s mental health centre providing a range of compassionate,innovative and accessible services for children, youth and their families throughout Simcoe County.   New Path is funded through multiple funding sources including the Ministry of Children and Youth Services, the Ministry of Community and Social Services and the Ministry of Attorney General.\nWe provide direct service to children and adults, and develop resources for new programs.  Everyone at New Path works together to create better futures for people and their communities.	info@newpath.ca	\N	705-725-7656	L4M	\N	\N	\N	\N	https://newpath.ca
660	rho	newgate-180-addiction-rehab-centre	Newgate 180 Addiction Rehab Centre	235 Main Street East\nMerrickville, K0G 1N0	\N	Newgate 180 is a renowned rehab centre that believes in inclusiveness. We have a comprehensive approach to addiction treatment, involving the body, mind, and soul. Our clients take part in individual counselling sessions with our certified staff, along with group sessions involving fellow Newgate 180 clients.\nWe also focus on the physical well-being of our clients; while at Newgate 180 you will eat delicious, healthy food prepared specifically for you by our in-house chef. Our nutritionist creates custom meal plans for our clients so they can continue their healthy eating habits\nafter they leave Newgate. We have an impressive exercise facility on-site and develop customized exercise programs for our clients. Our fitness programs also include yoga, reiki, and acupuncture.\nThe Newgate 180 approach to addiction treatment includes a focus on family and close friends because support is a crucial part of the rehabilitation process. While our clients generally stay at our facility for approximately one month, we also have an 11-month ongoing care program aimed at helping our clients and their loved ones continue to progress.	enquiries@newgate180.com	\N	(613) 269-2672	K0G	\N	\N	\N	\N	https://www.newgate180.com
661	rho	nguyen-wellness-health-quest	Nguyen Wellness @ Health Quest	7 Hayden Street\nToronto, M4Y 2P2	\N	Chiropractic and Acupuncture services	dr.tbnguyen.dc@gmail.com	\N	4169236661	M4Y	\N	\N	Barry Nguyen\nChiropractor	\N	https://www.healthquesttoronto.com/therapists/
662	rho	niagara-counselling-services	Niagara Counselling Services	449 Thorold Road\nWelland, ON, L3C 3W7	\N	Individual, couple, family, anxiety, depression, anger, stress, addiction, mental health and wellness.\n\n	niagaracounselling@gmail.com	Monday to Thursday 11 am to 8 pm	9059885748	L3C	\N	\N	Jay Stukel\nRegistered Social Worker RSW	\N	https://niagaracounselling.org
663	rho	niagara-falls-community-health-centre	Niagara Falls Community Health Centre	4481 Queen Street\nNiagara Falls, L2E 2L4	\N	The Niagara Falls Community Health Centre (NFCHC) is non-profit, community governed, multi-service health centre that provides primary health care, health promotion, and community development services all under one roof at no cost. NFCHC responds to the health needs of individual patients and their families, as well as to the health concerns of the community. We are committed to providing accessible services, the empowerment of individuals and communities, service integration, illness prevention and comprehensive client care.	cpoyton@nfchc.ca	\N	9053564222	L2E	\N	\N	\N	\N	https://www.nfchc.ca
664	rho	niagara-health-system	Niagara Health System	1200 Fourth Avenue\nSt. Catharines, L2S 0A9	\N	Gender Dysphoria assessments and referrals	\N	\N	905-378-4647, ext. 46573	L2S	\N	\N	Oleg Savenkov\nMD	\N	\N
666	rho	nick-mula-psychotherapy	Nick Mula Psychotherapy	77 Maitland Place\nToronto, M4Y 2V6	\N	Experienced gay therapist, activist and academic providing individual, couple, family counselling and psychotherapy to the LGBT communities. Strengths-based, anti-oppressive, goal oriented approach to addressing personal issues. Specializing in coming out, loneliness, relationship issues, career stress and development, self-esteem, self-worth, self-confidence, strategies on achieving personal goals and aspirations. Kink/polyamorous-friendly. Confidential, accessible downtown location, sliding scale fees.	nickm@look.ca	\N	416.926.9135	M4Y	\N	\N	Nick Mulé\nPhD, RSW	\N	\N
667	rho	nicola-brown	Nicola Brown	195 College Street\nToronto, M5T 1P9	\N	Individual therapy for a broad range of issues; WPATH transition-related surgical assessments as a “second assessor”.	nicola@nicolabrown.ca	\N	647-501-2045	M5T	\N	\N	Nicola Brown\nPh.D., C.Psych	\N	https://www.nicolabrown.ca
668	rho	nisrine-maktabi-rp-msc-counselling	Nisrine Maktabi RP.Msc. – Counselling	Toronto, M5B 1L3	\N	I provide counselling in English, French and Arabic. I identify as Muslim queer, Lebanese Canadian with Persian origins.\nI work from an integrative approach, grounded in anti oppression, feminist approaches, always relying on recent research. I use Cognitive Behavioral, and Emotion Focused Therapies, including mindfulness and mind body connection. I am also a registered yoga teacher, including a certificate in restorative yoga.\nI am looking to work with all populations, including Muslim, women and LGBTQ. I work with depression, anxiety, grief, relational issues, trauma, sexuality, poly relationships, gender identity/ transitioning.\nI provide services in English, French and Arabic.	nz.maktabi@gmail.com	\N	4162774453	M5B	\N	\N	Nisrine Maktabi\nRegistered Psychotherapist, Masters of Psychology	\N	https://therapists.psychologytoday.com/rms/prof_detail.php?profid=240215&sid=1431565788.307_25064&city=Toronto&spec=341&tr=ResultsName
669	rho	nogojiwanong-friendship-centre	Nogojiwanong Friendship Centre	580 Cameron Street\nPeterborough, K9J 3Z5	\N	Provide one to one supports, peer mentoring, Elder visits, medicine walks, Aboriginal craft workshops, socials, medicine making in the tipi, sweats, drum making, traditional teachings, cooking, movie nights, drop ins, referrals to support services…etc…	cgdc@nogofc.ca	\N	7057750387	K9J	\N	\N	Heidi Whetung	\N	https://www.nogofc.ca
670	rho	north-bay-counselling-services	North Bay Counselling Services	1180 Cassells Street\nNorth Bay, P1B 4B6	\N	I am a Transman and I provide trans positive counselling that follows the guidelines of the World Professional Association of Trans Health. I work in conjunction with doctors who are providing medical care, such as hormones and referrals for gender affirming surgery to trans people. I also provide Cognitive Behaviour Therapy (CBT) for depression and anxiety. I have years of experience working clients who have experienced many forms of trauma. My therapeutic approach is to integrate client centred/ evidence based therapies that includes the Cree Medicine Wheel, The Anishinaabeg Seven Grandfathers, Intersectional/anti-oppressive Feminist Therapy, Mindfulness, Cognitive Behavioural Therapy, Narrative Therapy, Rational Emotive Behavioural Therapy, Acceptance and Compassion Therapy, Trauma Informed Therapy and Motivational Interviewing for Substance Abuse.\nI offer my services in the evening anytime after 5:00. I do not offer sessions on Mondays and weekend sessions can be arranged. I have a fee for service, but I do offer sliding scale fees.	treanor@nbcounsellingservices.com	\N	705-494-5369	P1B	\N	\N	Mack Treanor Greer-Delarosbel\nLaurentian U - Honours Native Human Services Social Worker (H.N.B.S.W.) and Master of Social Work (MSW)	\N	https://www.nbcousellingservices.com
671	rho	north-bay-counselling-services-2	North Bay Counselling Services	North Bay, P1B4B6	\N	North Bay Counselling Services offers best practice evidence-based therapeutic services to address any mental health challenges you might have in these complicated times. Through a lens that recognizes the importance of your cognitive, behavioural, emotional, and spiritual well-being, we offer individual services for addictions, anxiety, panic attacks and depression; trauma counselling, including addressing power and control and violence against women, sexual abuse, and sexual assault. Our therapeutic services also address family conflict, working with couples, grief counselling, and general brief solution-focused therapy for general mental health improvement in everyday living.\nWe also provide specialized therapies such as:\nTrans Positive Informed Consent Model of Counselling for Trans identified,\nnon-binary, gender fluid children, youth, and adults and also for their families.	jtaun@therapysercure.com	8:30am - 8:30pm	7053587989	P1B	\N	\N	\N	\N	https://www.northbaycounselling.com/
672	rho	north-bay-regional-health-centre	North Bay Regional Health Centre	Mental Health Clinic\n120 King Street W\nNorth Bay, P1B 5Z7	\N	Providing healthcare services to North Bay and surrounding communities, district referral services and specialized mental health services.	beth.ward@nbrhc.on.ca	8:30am - 4:00pm	705-494-3050	P1B	\N	\N	Beth Ward\nMSW RSW	\N	https://www.nbrhc.on.ca
673	rho	north-muskoka-nurse-practitioner-led-clinic	North Muskoka Nurse Practitioner-Led Clinic	5 Centre Street North\nHuntsville	\N	The North Muskoka NPLC offers comprehensive primary health care by Nurse Practitioners, RNs, a social worker, a dietician, and a pharmacist. We provide care when people are ill as well as offer a range of health services that help individuals and families maintain or improve their overall health. Programs and services include annual physicals, episodic illness care, immunizations, sexual health, smoking cessation, mental health counselling, injury prevention and monitoring and management of chronic diseases such as diabetes, arthritis, asthma, heart disease and mental health conditions.	info@northmuskokanplc.com	\N	705-224-6752	\N	\N	\N	\N	\N	https://www.northmuskokanplc.com
674	rho	north-simcoe-muskoka-trans-health-services	North Simcoe Muskoka Trans Health Services	119 Memorial Ave\nOrillia, L3V 5X1	I can provide transition related surgery assessments for top or bottom surgeries\nI can provide secondary assessments for transition-related bottom surgeries		info@cfht.ca	Monday-Friday: 8:00am-4:00pm	(705) 329-3649 x. 214	L3V	\N	\N	\N	\N	https://www.cfht.ca/programs-and-services/program-details/~43_62-north-simcoe-muskoka-trans-health-services
675	rho	norwest-chcs-midwifery-program	NorWest CHCs Midwifery Program	Thunder Bay, P7C3J6	\N	Services de sage-femme, soins prénatales et postnatales, soins pour le nouveau-né jusqu’au 6 mois	jhuntly@norwestchc.org	Lundi au Vendredi 8:30 - 4:30 Horaire de L’Est	8076267872	P7C	\N	\N	Jenni Huntly\nRM	\N	https://www.norwestchc.org/locations/thunder-bay/programs/midwifery-programs
676	rho	norwest-community-health-centre	Norwest Community Health Centre	525 Simpson Street\nThunder Bay, P7C 3J6	\N	Nurse practitioner providing trans and gender diverse primary care.	\N	\N	807-622-8235	P7C	\N	\N	Allison Anderson\nMN, NP-PHC, Completion of Trans and Gender Diverse Primary Care and Trasition Related Surgical Planning with RHO	\N	\N
804	rho	robertpetrietherapy-2	RobertPetrieTherapy	120 Perth Avenue\nSUITE 512\nToronto, M6P 4E1	\N	I am a registered psychotherapist with master’s level training in a range of modalities to treat a variety of mental disturbances such as anxiety, depression, SUDs, relationships, existential, etc..	robertpetrie29@gmail.com	\N	5145504415	M6P	\N	\N	Robert Petrie\nRegistered Psychotherapist	\N	https://member.psychologytoday.com/ca/home
677	rho	norwest-community-health-centres	NorWest Community Health Centres	525 Simpson Street\nThunder Bay, P7C 3J6	\N	The health care team at the NorWest Community Health Centres in Thunder Bay and Longlac includes family physicians, nurse practitioners, nurses, footcare nurses and a dietitian. The Thunder Bay team also includes a counsellor and a chiropodist. The Armstrong health care team consists of nurse practitioners.\nOur family physicians and nurse practitioners provide medical care and regular check ups for clients.\nDuring Walk-in Clinics at our Thunder Bay site, patients are seen by a nurse practitioner for issues such as cuts, coughs and colds, fever, earaches, infections, HIV testing, pregnancy tests, sexual health and birth control.\nCounselling services are available at the Thunder Bay Site and through our Telemedicine Services (OTN) Ontario Telemedicine Network at both our Longlac and Armstrong Sites. Areas of focus are on emotional and mental health related to anxiety, depression, trauma and situational issues. Collaborative Care Model with primary care providers and referrals to community services and programs are available.\nDr Ray Balec has received trans primary care training and will initiate hormone therapy.\nContact NorWest CHC for Gender Journeys dates.	\N	\N	807-622-8235	P7C	\N	\N	\N	\N	https://www.norwestchc.org
678	rho	nurture-by-massage-infant-massage	Nurture By Massage – Infant Massage	Kitchener	\N	Certified Infant Massage Teacher, Anita Bocian, teaches the benefits and fundamentals of infant massage to caregivers in this comprehensive 4-session course that includes special techniques to alleviate symptoms associated with colic/gas, teething and congestion. We offer private, in home classes as well as group classes at various locations around Kitchener, Waterloo, Cambridge and surrounding areas.\nFor more information and to register for an upcoming course, visit www.nurturebymassage.com.	info@nurturebymassage.com	\N	519-807-4834	\N	\N	\N	Anita Bocian\nCertified Infant Massage Teacher	\N	https://www.nurturebymassage.com
679	rho	nutra-journey	Nutra-Journey	PO 565 Stn Main\nWASAGA BEACH, L9Z 1C6	\N	Holistic nutritionists support queer and trans men boosting their energy levels, losing excess weight, and increasing their quality of life. All services are completed via ZOOM online at the comfort of your own home.	alain@nutrajourney.ca	Monday, Tues, and Wednesday 6 AM -8:30 PM Thursday 8 AM-10 AM. Sat and Sunday 10 AM - 4 PM	7057308438	L9Z	\N	\N	Alain Carriere	\N	https://nutrajourney.ca/
680	rho	nutrasen-health-wellness	Nutrasen Health & Wellness	479 Ellerslie Avenue\nToronto, M2R 1C3	\N	Nutrasen Health & Wellness is an eminent company that helps the people to lead a healthy and energetic life through natural supplements. The company focus is to aid the people to build up a healthy body and mind in order to lead a happy and balanced life. We supply the best sleeping supplement which is made up of all natural ingredients that can bring you a high level of energy through out your day.\nOur product “Shanti” helps the people to avoid the problems such as stress, anxiety, inflammation, lack of sleep and many more. The ingredients in the product are from the finest farms and sources in India. The Company website offers you tips and articles about how to remain healthy through natural way. Our vision is to make people live healthier and happier. For more information, visit http://nutrasenwellness.com/	support@nutrasenwellness.com	\N	1-800-230-8870	M2R	\N	\N	Kelly Allen	\N	https://nutrasenwellness.com/
681	rho	nuyu-laser-skin-rejuvenation	NUYU Laser & Skin Rejuvenation	215 Herchimer Avenue\nBelleville, K8N 4G9	\N	Hi There,\nMy name is Cheri and i am the owner of NUYU Laser & Skin Rejuvenation located in Belleville, Ontario. My passion is to make people feel confident and comfortable in their skin. I offer a warm and inviting atmosphere for my clients to feel relaxed during their treatments. I am a supporter of the LGBTQ Community and i want to make everyone who visits feel welcome and safe in my establishment. I have experience working with Trans clients needing hair removal done. I hope that if you are considering any of these services that you check us out…I look forward to meeting you :).\nThank you, NUYU Owner Cheri\nNUYU offers the following treatments:\nLaser hair removal,Acne Laser Treatments, IPL Photofacial Skin rejuvenating treatments(sun spots, broken capillaries fine lines/wrinkles & uneven skin tone/texture. Electrolysis (Alternative Hair removal) or Electrocoagulation (Removes skin tags, cherry angiomas, broken capillaries).	cherimichelle.nuyu@gmail.com	Monday- 10am-7pm Wednesday- 10am-7pm Every other Saturday- 9am-2pm	6139681399	K8N	true	\N	Cheri Gerroir\nLaser Technician Diploma, Electrolysis Diploma and Electrocoagulation Diploma	\N	https://www.nuyulaserskin.ca/
682	rho	oakville-family-birth	Oakville Family Birth	Oakville	\N	Oakville Family Birth provides doula services (birth/postpartum) and prenatal classes (group/private) in the Halton, Hamilton and Mississauga areas.\nAs a small business owner and LGBTQ ally I’m committed to supporting all kinds of families and all kinds of births. We’re about less judgement, more love.	hello@oakvillefamilybirth.com	\N	(289) 813-4363	\N	\N	\N	Jaklyn Andrews	\N	https://www.oakvillefamilybirth.com
683	rho	oasah-ontario-aboriginal-hiv-aids-strategy	OASAH – Ontario Aboriginal HIV/AIDS Strategy	7 Hayden Street\nToronto, M4Y 2P2	\N	The Ontario Aboriginal HIV/AIDS Strategy was implemented in 1995 and has consistently evolved since then to respond to the changing epidemic within the Aboriginal population. The Strategy has embraced two fundamental principles since its inception. The first being a recognition that OAHAS is a distinct strategy based on the distinct needs of Aboriginal people.\nWhile issues and factors related to the disease may be similar to the mainstream population, Aboriginal differences must be respected. This principle is embodied in the Two Row Wampum Treaty of the Haudenosaunee people.\nOasah has a variety of services within urban populations including education and training. Oahas staff will work with community members and families to access the basic needs for optimal health, including income, housing, food, employment and positive working conditions as well as providing safer sex and harm reduction supplies within the community.	info@oahas.org	\N	Toll-free 1.800.743.8851	M4Y	\N	\N	\N	\N	https://www.oahas.org/
684	rho	oasis-centre-des-femmes	Oasis Centre des Femmes	Toronto	\N	Nos programmes de soutien s’adressent aux femmes qui vivent ou ont vécu de la violence sous toutes ses formes comme la violence conjugale ou familiale, la violence sexuelle, la violence liée à des conflits armés, le harcèlement…\nIls sont confidentiels, gratuits et offerts dans un environnement chaleureux et sécuritaire.\nÀ travers nos services communautaires, nous offrons un soutien aux femmes afin qu’elles atteignent un épanouissement personnel, social et économique. Nous travaillons également auprès de la communauté pour prévenir la violence et la discrimination, dans le but de créer une société sécuritaire et inclusive.\nOur support services are geared towards women who have experienced violence in any form, such as domestic or family violence, sexual violence, armed conflict, harassment…\nThey are confidential, free, and are offered in a safe and welcoming environment.\nThrough our community services, we offer support to enable women to achieve personal, social and economic well-being. We also work with the community in order to prevent violence and discrimination, with the goal of creating a safe and inclusive society.	\N	\N	416.591.6565	\N	\N	\N	\N	\N	https://www.oasisfemmes.org/
685	rho	ocad-university-health-and-wellness-centre	OCAD University Health and Wellness Centre	100 McCaul Street\nToronto, M5T 2W7	\N	Dr Alexandra Hrabowych provides trans and gender diverse care as a family physician. She is comfortable in initiating and monitoring hormone therapy. She has taken additional training in WPATH criteria and surgical referrals. Our nurse, Sarah Cree, has also completed training in WPATH criteria and is comfortable in performing injections and providing self-injection teaching. Our clinic is a trans positive space and has a number of social workers who are available for counselling and assisting students connecting to resources in the community. Clinic services are limited to active OCAD University students.	hwc@ocadu.ca	\N	4169776000 ext 260	M5T	\N	\N	Alexandra Hrabowych\nMD CCFP	\N	https://www.ocadu.ca/services/health-and-wellness.htm
686	rho	octopus-garden-holistic-health-centre	Octopus Garden Holistic Health Centre	967 College Street\nToronto, M6H 1A6	\N	Octopus Garden Holistic Yoga Centre is a community of health-based practitioners and teachers who work to incorporate the joy of yoga into all areas of our lives. Our centre offers the following programs and services to help you enrich and broaden your practice (and have some fun, too!).\nOG has many yoga classes from beginners to advanced including family and baby yoga, private lessons and drop in classes. OG also has weekly meditation groups and various holistic clinicians including: osteopathy, chiropractor, counselors, nutritionists ect.	info@octopusgardenyoga.com	\N	416 515 8885	M6H	\N	\N	\N	\N	https://octopusgardenyoga.com/
687	rho	ohsutp-ontario-hiv-and-substance-use-training-program	OHSUTP – Ontario HIV and Substance Use Training Program	490 Sherbourne Street\nToronto, M4X 1K9	\N	The Ontario HIV and Substance Use Training Program provides training to substance use, mental health and allied service providers in Ontario in order to increase knowledge of HIV/AIDS and to promote skills development.\nOHSUTP is a service of Fife House and is funded by the AIDS Bureau, Ministry of Health and Long-term Care. A provincial Advisory Committee consisting of representatives from substance use and AIDS service organizations provides input into programming issues.\nWorkshop Topics:\nThe topics consist of a mix of training materials including PowerPoint’s, exercises, videos, group discussion, and case studies; they can be delivered separately, though we encourage booking the full training. The full training is two days which can be scheduled back to back or over a period of weeks or months. We will work with your organization to determine your needs and which modules are most appropriate.\nDepending on staff size, we offer in-house training, or we support you to plan with other allied social services in your area. In nearly every workshop, OHSUTP staff deliver technical information, while “peers”, people living with HIV, are able to compliment this by sharing their experiences an insights.	\N	\N	1 866 591 0347	M4X	\N	\N	\N	\N	https://www.ohsutp.ca/
688	rho	onsite-acupuncture-therapy	Onsite Acupuncture Therapy	Toronto	\N	Affordable acupuncture in your own home!\nWe offer professional, registered, in-home, acupuncture treatments. Our mobile acupuncturists help you achieve a better quality of life while reducing or eliminating pain.\nDiscover a healthier you\nBOOK AN APPOINTMENT TODAY\nAcupuncture is inexpensive and an effective way to treat pain and restore health without expensive drug therapy or surgery. Acupuncture has been shown to effectively treat many disorders. Although it is best known for it’s impressive ability to reduce or eliminate pain, it is a powerful tool providing relief from insomnia, hypertension, anxiety, depression, menopause, sciatica, back pain, frozen shoulder, tendonitis, headaches, PMS, IBS, arthritis and many other conditions: source World Health Organization.\nAcupuncture is a relaxing experience. Most patients leave the table feeling every muscle in their body relaxed. Many chronic diseases are preventable. Prevention also occurs when we change some bad habits. Change is made easier with the help of supportive and well-informed mentors.	hello@onsitetherapy.ca	\N	4165574116	\N	\N	\N	Adam Taylor\nRegistered Acupuncturist	\N	https://www.onsitetherapy.ca
689	rho	ontario-association-of-mental-health-professionals-oamhp	Ontario Association of Mental Health Professionals (OAMHP)	586 Eglinton Avenue East\nSuite 410\nToronto, M4P 1P2	\N		info@oamhp.ca	Hours: Monday 9a.m.–5p.m. Tuesday 9a.m.–5p.m. Wednesday 9a.m.–5p.m. Thursday 9a.m.–5p.m. Friday 9a.m.–5p.m. Saturday Closed Sunday Closed	4162987333	M4P	\N	\N	oamhp	\N	https://oamhp.ca/
690	rho	ontario-hiv-treatment-network-ohtn	Ontario HIV Treatment Network (OHTN)	1300 Yonge Street\nToronto, M4T 1X3	\N	The Ontario HIV Treatment Network (OHTN) is a collaborative network of:\nOur network supports and conducts high quality research to help end the HIV epidemic, and shares the best available evidence with all those who can put that knowledge into action. We are an active, committed partner in Ontario’s HIV/AIDS strategy.	info@ohtn.on.ca	\N	Tel: 416-642-6486	M4T	\N	\N	\N	\N	https://www.ohtn.on.ca/
691	rho	ontario-prevention-clinic-the-prep-clinic	Ontario Prevention Clinic / The PrEP Clinic	401-344 Bloor St W\nToronto, M5S3A7	\N	Ontario’s inclusive sexual health professionals providing in-person and online sexual health services and featuring a PrEP Clinic.\nServices include:\nA health card is not required to receive care at the clinic. We offer booked appointments as well as walk-in hours. Visit our website or call us to learn more.\nWe are located in a safe secure building. There is an elevator in the building re: access.	info@preventionclinic.ca	Monday 12pm-9pm (by appointment, 6pm-9pm walk-in) Wednesday 10am-5pm (by appointment) Thursday 12pm-9pm (by appointment, 6pm-9pm walk-in) Online appointments throughout the week available via our free app "The PrEP Clinic" If capacity is reached during walk-in clinic times, the clinic may close entry earlier in the evening. This has rarely occurred but it is recommended to come at least 30 min before closing.	416-420-1250	M5S	\N	\N	\N	\N	https://www.preventionclinic.ca
692	rho	open-minds	Open Minds	Guelph	\N	Open Minds provides training in Mental Health First Aid (Basic and Youth), trauma-informed practice, resilience for helpers, and more. We are based in Guelph and serve Southern Ontario.	sarah@openmindsmentalhealth.ca	\N	5193621075	\N	\N	\N	Sarah Stewart\nRSW and Certified Mental Health First Aid trainer	\N	https://www.openmindsmentalhealth.ca
693	rho	open-palm-osteo	Open Palm Osteo	961 Queensbridge Drive\nMississauga, L5C 3M8	\N	A whole body approach to physical manipulation to facilitate health and wellness.	rchang@openpalmosteo.com	\N	647-524-3635	L5C	\N	\N	Richard Chang\nOsteopathic Manual Therapist	\N	\N
694	rho	openarms-ob-gyn	OpenArms Ob/Gyn	658 Danforth Avenue\nToronto, M4K 1R2	\N	Reproductive health care.\nTranshealth care\nGynecological care	Openarmsobgyn@gmail.com	\N	416 466 2360	M4K	\N	\N	Helena Frecker\nMD FRCS(C)	\N	https://www.openarmsobgyn.ca
740	rho	pflag-renfrew-county	PFLAG Renfrew County	Pembroke	\N	PFLAG Renfrew County is a chapter of PFLAG Canada. We are LGBTQ community members, parents and allies offering support, education and advocacy for anyone with questions around sexual orientation, gender identity and gender expression. Monthly support meetings take place in Pembroke, but we will travel throughout Renfrew County.	pflagrc@gmail.com	\N	1-800-530-6777 ext. 572	\N	\N	\N	\N	\N	https://www.pflagrenfrewcounty.ca
695	rho	optimal-life-mental-health-strategies	Optimal Life Mental Health Strategies	993 Princess Street\nKingston, K7L 4V1	\N	I provide CBT and SFBT in a holistic approach using mindfulness techniques to address your concerns. My specialty is anxiety and depression. I treat each person in his or her individual context taking into consideration all contributing social, familial, economic factors in your unique situation. I am a dedicated ally to the LGBTQ, particularly trans community and I am determined to get trans rights to the level of current gay rights. I provide referrals for HRT and GRS. I am fluently bilingual in French and English.	info@olmhs.com	\N	6138773667	K7L	\N	\N	Zelda Hippolyte\nMA MSW RSW	\N	https://www.olmhs.com
696	rho	orilla-soldiers-memorial-hospital	Orilla Soldier’s Memorial Hospital	170 Colborne Street West\nOrillia, L3V 2Z3	\N	Located in the heart of Ontario’s lake country, Orillia Soldiers’ Memorial Hospital (OSMH) is a community hospital providing regional programs, as well as surgical and medical services to the residents of Simcoe County and Muskoka.\nFor over a century our healthcare team has been acknowledged and respected for providing exceptional care and service to our patients. OSMH has a history of providing inclusive and affirming care for LGBTQ communities.	info@osmh.on.ca	\N	705-325-2201	L3V	\N	\N	\N	\N	https://www.osmh.on.ca/
697	rho	orillia-midwives	Orillia Midwives	22 Colborne Street West\nOrillia, L3V 2Y3	\N	Midwifery care for pregnancy, birth, and postpartum	Info@orilliamidwives.com	\N	705-326-0000	L3V	\N	\N	Emily Lyons\nRM	\N	https://www.orilliamidwives.com
698	rho	oshawa-commmunity-health-centre	Oshawa Commmunity Health Centre	115 Grassmere Avenue\nOshawa, L1H 3X7	\N	The Oshawa Community Health Centre utilizes a team of supportive and skilled professionals including child and youth workers, doctors, social workers, counsellors, nurse practitioners, and health promoters to deliver services. Our centre is unique for the reason that we are responsive to the health needs as defined by our Oshawa community.\nOur services include family medicine, social work and counselling, and a variety of health promotion and community development groups, many focusing on children, youth and women. All of our services and programs are free	info@ochc.ca	\N	905-723-0036	L1H	\N	\N	\N	\N	https://www.ochc.ca/
699	rho	oshawa-psychological-and-counselling-services	Oshawa Psychological and Counselling Services	117 King Street East\nOshawa, L1H 1B9	\N	I provide LGBTQ-positive psychological services for the treatment of sexual and gender issues, including transitioning, as well as the treatment of psychological difficulties unrelated to gender or sexuality faced by individuals who identify as LGBTQ.	\N	\N	905-721-7723	L1H	\N	\N	Joanne West\nPhD Clinical Psychology	\N	https://www.oshawapsychologist.com/
700	rho	oshawa-psychological-and-counselling-services-2	Oshawa Psychological and Counselling Services	117 King Street East\nOshawa, L1H 1B9	\N	I provide psychological counselling and assessment services to adult and adolescent members of the LGBTQ community and their loved ones.	clinic@oshawapsychologist.com	\N	905 721 7723	L1H	\N	\N	Dr. Joanne West\nPhD Clinical Psychology	\N	https://oshawapsychologist.com
701	rho	ottawa-centre-for-resilience	Ottawa Centre for Resilience	204-2197 Riverside Drive\nOttawa, K1H7X3	I can provide transition related surgery assessments for top or bottom surgeries\nI can provide secondary assessments for transition-related bottom surgeries		info@ocfr.ca	Monday to Friday, 8:30am - 5:00pm	6137140662	K1H	\N	$150-$220	\N	\N	https://www.ocfr.ca
702	rho	ottawa-integrative-health-centre	Ottawa Integrative Health Centre	904 Lady Ellen Place\nOttawa, K1Z 5L5	\N	At the Ottawa Integrative Health Centre, functional, or integrative medicine is practiced by its array of health care specialists.\nWhether you come to us for better energy, better performance, more balance, more wellness, more confidence, more individualized medicine – we are here to enable you on your journey with our Naturopathic Doctors, Certified Laser Therapists, Psychotherapists, Holistic Nutritionists, Physiotherapists, Osteopaths, Massage Therapists, Reflexologists and more.\nOur Vision at the OIHC is to lead in our commitment to exemplary patient care in our community, while providing a collaborative and comprehensive full-care clinic that embraces the growth and continual education of itself, its associates and its patients.	info@oihc.ca	Temporary Hours of Operation Monday to Friday: 10 am to 6 pm Saturdays (one Saturday per month) Sundays and Statutory Holidays Closed	613-798-1000	K1Z	\N	\N	Owen Wiseman\nND	\N	https://www.oihc.ca/
703	rho	ottawa-south-midwives	Ottawa South Midwives	4112 Albion Road\nOttawa, K1T 3W1	\N	Midwife providing inclusive, client centred, full scope service in Ottawa. Delivering at the Civic hospital, Ottawa Birth and Wellness Centre, and at home.	\N	\N	613-822-6646	K1T	\N	\N	Nicole Pichette\nRM	\N	\N
704	rho	our-journey-counselling-psychotherapy-services	Our Journey Counselling & Psychotherapy Services	55 Village Centre Place\nMississauga, L4Z 1V9	\N	I provide counselling and psychotherapy services to individuals struggling with mental health problems and need the support to manage and overcome these problems. My goal is to provide a safe, warm, understanding, and non-judgmental space for all clients to explore their problems and find strategies or solutions to their problems, so they can enjoy what life has to offer. They will not go on the journey alone, I am here to offer encouragement while being on the journey with clients. I am a client-centred focused therapist.\nMy practice is open to individuals, families, male, female, adults, teens, and it is LGBTQ friendly. I have experience working with transgender clients who were waiting for surgery, who were ready to start hormone treatment, and clients who were on hormone treatment.	info@ourjourneycounselling.ca	\N	6474676017	L4Z	\N	\N	Stacy-Ann Braham\nMACP, RP-Q, CCC-Q	\N	https://www.ourjourneycounselling.ca
705	rho	our-landing-place	Our Landing Place	(online)\nTORONTO, M5V 3J6	\N	We are a collective of LGBTQ2IA+ identified counsellors offering sex-positive, affirming and competent online and phone counselling across Canada (Great Turtle Island).\nWe also provide gender and sexuality focused diversity, equity and inclusivity (DEI) consulting and training services to individuals and organizations worldwide.	inquiries@ourlandingplace.com	Monday-Sunday flexible depending on provider	(250) 806 0455	M5V	\N	$175/50 min	\N	\N	https://www.ourlandingplace.com/
706	rho	out-and-proud-childrens-aid-society-toronto	Out and Proud – Children’s Aid Society (Toronto)	30 Isabella Street\nToronto, M4Y 1N1	\N	The Out and Proud Program enables the Children’s Aid Society of Toronto (CAS of Toronto) to ensure that its services are open, inclusive, safe, affirming and positive for lesbian, gay, bisexual, transsexual, transgender, two-spirit, intersex, gender non-conforming, queer and questioning (LGBTQ) children and youth  served by CAS of Toronto, as well as LGBTQ families, employees, volunteers and care providers.\nWe celebrate diverse sexual orientations and gender identities/expressions. We assist CAS of Toronto to provide an environment that is free from homophobia, heterosexism, rigid gender expectations and transphobia.	\N	\N	416.924.4640 ext 2986  or ext 2987	M4Y	\N	\N	\N	\N	https://www.torontocas.ca/?t=out-and-proud
707	rho	out-of-the-box-counselling-collaborations	Out of the Box Counselling & Collaborations	67 Hohner Avenue\nKitchener, N2H2V3	\N	Out of the Box Counselling & Collaborations offers trauma counselling services to neurodiverse two-spirit, queer, and LGBTQIA+ individuals. We aim to disrupt the status quo of how people approach counselling; by offering an affirmative space run by neuroqueers for neuroqueers.\nThe COVID-19 pandemic has directly impacted the demand for mental health services, and have highlighted the intersectional ways that neurodivergent queer/two-spirit people experience challenges and access services. Curating a space that recognizes the uniqueness of each client’s circumstances and challenges the status quo of ableism, colonization, and heteronormativity can help people to more authentically engage in their own healing work while also creating a meaningful space to connect to other two-spirit and neuroqueer individuals.	krystal@outoftheboxcounselling.ca	Tuesday 11-7 Wednesday 11-7 Thursday 10-6 Friday 10-6	2266985646	N2H	\N	Sliding scale range - $/Hour Minimum: 30 Maximum: 120	Krystal Hilchey Muise\nMSW	\N	https://www.outoftheboxcounselling.ca
708	rho	outline-phone-and-online-support	OUTline Phone and Online Support	50 Stone Road East\nGuelph, N1G 2W1	\N	Ask OUTline is an anonymous way of getting answers to your questions about sexual orientation and gender identity. Trained volunteers read your questions and respond with information and resources. The questions and the responses are posted on this blog and sorted by category so that others may benefit from them. This service is anonymous and confidential. OUTline serves the University of Guelph and surrounding community, and is funded entirely by students.	outline@uoguelph.ca	\N	519-836-4550	N1G	\N	\N	\N	\N	https://askoutline.wordpress.com
709	rho	outniagara	OUTniagara	\N	\N	OUTniagara is a community-based organization serving the Niagara Region. Our purpose is to support and unite Niagara’s sexual- and gender-diverse community. We do this by amplifying the voices of our community, acting as a public policy advocate, and helping to build relationships within the community. Our website is a community hub for connection and information with an up-to-date calendar of local 2SLGBTQ+ events, a listing of active social and support groups and 2SLGBTQ+ friendly businesses in the Region.	outniagara@gmail.com	\N	\N	\N	\N	\N	Kate Alexander\nSecretary	\N	https://www.outniagara.ca
710	rho	outreach-health-group-xytex-canada	Outreach Health Group (Xytex Canada)	\N	\N	Exclusive Canadian Importer and Distributor for Xytex Sperm Bank. Fully compliant with Health Canada regulations.	bvines@xytex.com	\N	9059544066	\N	\N	\N	Brenda Vines\nRN,BN	\N	https://www.creatingcanadianfamilies.ca
711	rho	outside-the-box	Outside The Box	85 Carleton Street\nKingston, K7K 4E9	\N	Registered Psychotherapist (CRPO) who can support individuals to work through interpersonal and personal concerns, such as trauma, addiction, anxiety, depression, and many more. I utilize creative approaches, Cognitive Behavioral Therapy, Mindfulness, and Distress tolerance. I foster creative and strength based recovery and discover.	rich_tyo@yahoo.com	\N	6134849771	K7K	\N	\N	Richard Tyo\nRegistered Psychotherapist (CRPO)	\N	https://www.kingstonoutsidethebox.com
712	rho	p3-obstetrical-and-midwifery-care	P3 Obstetrical and Midwifery Care	6758 Kingston Road\nToronto, M1B 1G8	\N	This is an innovative programme of interdisciplinary obstetrical and midwifery care for HIV + people who are pregnant or planning to become pregnant.\nWe are Dr. Mark Yudin and Midwife Jay MacGillivray and we work out of St. Michael’s hospital in Toronto.\nWe believe that + women have the right to become pregnant and to have their care provided with both expertise and respect. Our focus is on normalizing pregnancy, on health promotion and support as well as establishing appropriate standards of care. We believe that + women have expertise about their own bodies and health which should be an integral part of any pregnancy care.	jaymacgillivray@yahoo.ca	\N	416-286-2228	M1B	\N	\N	\N	\N	\N
713	rho	pace-pharmacy	Pace Pharmacy	14 Isabella Street\nToronto, M4Y 1N1	\N	Pace Pharmacy is a small pharmacy providing services to many LGBT individuals and their pharmacy-related needs. Providing prescriptions, specialty compounding, vitamins, supplements, health information, confidential serivce, and a quiet, community pharmacy ambiance.\nOur licenced and specially trained Pharmacist has years of experience working within the LGBT community and their health and medication related needs. Pace has access to information and resources for people living with HIV/AIDS as well as their friends, family members, and caregivers.	info@pacepharmacy.com	\N	416-515-7223	M4Y	\N	\N	\N	\N	https://www.pacepharmacy.com
714	rho	paduka-wellness	Paduka Wellness	226 Frederick Street\nKitchener, N2H 2M8	\N	I am a therapist in private practice.  I work with individuals 18+ yo, with a focus on the LGBT2SQ+ community.\nI am informed in the following population specific needs:\n Polyamorous relationships\n Intersectional identities (BIPOC, Religious Minorities)\n Informed in Contemporary Subcultures: Kink, Gaming, Drag\n Anti-oppression\n Sex worker positive\n Gender Identity (Trans and Non-Binary spectrums)\n Sexual identities\n Immigrant experience\n Neurodivergence and learning disabilities\n STI/STD informed, specifically HIV/AIDS\n College/University experience\nBelow are some of the core areas I can assist clients with:\n Identity exploration and healthy relationship with self\n Managing life transitions and stressors\n Self-worth and self-compassion\n Co-dependency and healthy relationships\n Grief and Loss\n Addiction\n Trauma and Shame Cycles	padukawellness@gmail.com	In-Person and Virtual meetings Tuesdays 9am - 6pm Wednesdays 9am - 6pm Thursdays 9am - 12pm Friday 9am - 1pm	5484836603	N2H	\N	Sliding scale range - $/Hour Minimum: 70.00 Maximum: 120.00	Ben Stimpson\nTransformational Arts College, OAMHP	\N	https://www.padukawellness.com
715	rho	pakenham-medical	Pakenham Medical	707 Charlotte Street\nPeterborough, K9J 2X5	\N	Dr. Pakenham, Obstetrician/Gynecologist, recently joined The Medical Centre and is also a member of the Department of Obstetrics and Gynaecology at PRHC. Dr. Pakenham was born and raised in Peterborough, attending Westmount PS and PCVS before that, then moving to Kingston where Dr. Pakenham completed an honours Bachelor of Science degree in Life Sciences at Queen’s.\nDr. Pakenham graduated from Queen’s medical school and moved to North York where Dr. Pakenham pursued postgraduate training in Obstetrics and Gynaecology at the University of Toronto.\nThroughout Dr. Pakenham’s residency, Dr. Pakenham published research in Caesarean delivery, intrauterine fetal movements and twin pregnancy, and pursued special clinical training in vulvo vaginal health and minimally invasive surgery. Dr. Pakenham is happy to be home in Peterborough.	\N	\N	7058764530	K9J	\N	\N	Susan Pakenham\nMD FRCS (C)	\N	\N
716	rho	palmer-laser-electrolysis	Palmer Laser & Electrolysis	35 Blyth Street\nRichmond Hill, L4E 2Y2	\N	Providing permanent hair removal using laser and Electrolysis.	joycemichellepalmer@gmail.com	\N	(905)773-0350	L4E	\N	\N	Joyce Palmer\nCPR	\N	https://www.palmerlaserandelectrolysis.com
717	rho	paper-birch-counselling	Paper Birch Counselling	Online Only, N2M 1W5	\N	I enjoy working with clients from a variety of backgrounds and who are seeking therapy for a variety of reasons. I have experience and special interest/training in the following areas:	paperbirchcounselling@gmail.com	In consultation	9779813178304	N2M	\N	\N	Kaitlyn Jantzi\nMSW, RSW	\N	https://www.paperbirchcounselling.com
719	rho	paris-child-adolescent-psychological-centre	Paris Child & Adolescent Psychological Centre	9030 Leslie Street\nRichmond Hill, L4B 1G2	\N	Paris Child & Adolescent Psychological Centre provides comprehensive assessment, consultation, and treatment services for children and adolescents from four to nineteen years of age. Our primary focus is to provide personal, friendly service in a professional and caring environment. Services provided include assessment, consultation, individual therapy and group therapy to address issues of learning and school functioning, anxiety, depression, coping, resilience, self-regulation, and behaviour.	karrela@pariscentre.ca	\N	905-709-3334	L4B	\N	\N	Karrela Paris\nM.A.S.P., C. Psych.	\N	https://pariscentre.ca
720	rho	parkdale-community-health-centre	Parkdale Community Health Centre	1229 Queen Street West\nToronto, M6K 1L2	\N	Parkdale Community Health Centre (PCHC) is situated in a vibrant, multicultural, inner-city neighbourhood of Parkdale in downtown west Toronto. We work with the community, in all its diversity, to address its health-related needs through the delivery of primary health care, health promotion, counselling, advocacy, community development and action.\nWe give priority to individuals and groups who traditionally encounter barriers to high quality health care services, including marginalized or vulnerable populations such as newcomers, racialized communities, people who are homeless or living near the street, people with mental health challenges and addictions, people living with visible and invisible disabilities, isolated seniors, LGBTQ communities and people living in poverty.	\N	\N	416.537.2455	M6K	\N	\N	\N	\N	https://www.pchc.on.ca/
721	rho	parkdale-queen-west-community-health-centre-queen-west-site	Parkdale Queen West Community Health Centre, Queen West Site	168 Bathurst Street\nToronto, M5V 2R4	\N	I provide care to trans and gender non conforming people, people who use drugs, people who are homeless or underhoused, people who are HIV or Hep C positive within an anti-oppressive framework.	\N	\N	416-703-8480	M5V	\N	\N	Nanky Rai\nMD MPH	\N	\N
722	rho	partners-in-pregnancy-clinic	Partners in Pregnancy Clinic	170 Simcoe Street, Suite 302\nPeterborough, K9H 2H7	\N	We are dedicated and experienced family physicians who are passionate about providing safe and patient-centred pregnancy and newborn care. You can be referred to us at any time in your pregnancy although we appreciate referrals prior to the 24 week mark. We will also take self-referrals. We attend births at the Peterborough Regional Health Center (PRHC).\nWe provide care based on respect and collaboration, building on your confidence at each visit and supporting you and your community. We work in collaboration with a fantastic team including lactation consultants, social workers, nurses, dietitians and physician assistants.	pregnancy.clinic@peterboroughfht.com	Monday to Thursday 9am to 4:30pm. Friday 9am to noon.	705-741-1191	K9H	\N	\N	\N	\N	https://www.partnersinpregnancy.ca/
723	rho	pasan	PASAN	526 Richmond Street East\nToronto	\N	PASAN is a community-based AIDS Service Organization that strives to provide community development, education and support to prisoners and ex-prisoners in Ontario on HIV/AIDS, hepatitis C virus (HCV) and other harm reduction issues.\nPASAN formed in 1991 as a grassroots response to HIV /AIDS in the Canadian prison system. Today, PASAN is the only community-based organization in Canada exclusively providing HIV/AIDS and HCV prevention education and support services to prisoners, ex-prisoners, youth in custody and their families. PASAN receives the majority of it’s funding from various levels of government health departments.\nPASAN’s services include: support services, community outreach, education and training.\n~ WE ACCEPT COLLECT CALLS FROM PRISONERS IN CANADA ~\nProvincial Inst – Collect: 416-920-9567\nFederal Inst – Toll-Free: 1-866-224-9978	info@pasan.org	\N	Toll Free: 1-866-224-9978	\N	\N	\N	\N	\N	https://www.pasan.org/
724	rho	pat-rayman-psychotherapy	Pat Rayman Psychotherapy	68 Dewson Street\nToronto, M6H 1G8	\N	Psychotherapy provides the opportunity for people to talk openly and confidentially about their concerns and feelings from the past to the present. Therapy can lead people to a greater understanding of feelings, beliefs, actions. From understanding comes the opportunity to learn and practice new skills, make new choices and develop deeper self acceptance.\nMy approach is collaborative and thoughtful. I believe in and respect each person’s unique qualities and resources. We work together to identify patterns that need changing, and develop new healthy ways of moving forward. I facilitate clients meeting both short and long-term needs in a safe and caring atmosphere.\nI have had in-depth training in a range of psychotherapeutic theories and practices. These include trauma treatment, psychodrama, family therapy, narrative and cognitive behavioral therapy, self psychology, psychodynamic and relational therapy.	patrayman@rogers.com	\N	416-588-3662	M6H	\N	\N	Pat Rayman\nM.Ed., OCT,	\N	\N
725	rho	pathways	PathWays	450 Campbell St.\nUnit 8A\nCobourg, K9A 4C4	\N	PathWays is a permanent hair removal and non-surgical facial feminization service available to anyone desiring a tangible difference in the way they present to the world. We recognize that not all aesthetic changes necessitate a surgical approach, and our goal is to help you discover & navigate the right path for YOUR transition. Personalized treatment plans are devised to achieve individualized goals. Your privacy is our priority.\nServices: Permanent Hair Removal (laser & electrolysis), Skin Reparation Treatments, Brow & Lash Treatments.\n​	pathwaysmtf@gmail.com	By appointment only.	9053736728	K9A	\N	Fees are based on time and/or treatment rendered.	Elizabeth Boileau	\N	https://www.pathwaysmtf.com
726	rho	pathways-for-children-youth-and-families	Pathways for Children, Youth and Families	135 Main Street North\nMarkham, L3P 1Y2	\N	Pathways for Children, Youth and Families of York Region Inc. is a registered charity in York Region that has been providing services for over 20 years. Pathways provides a continuum of care to clients that begins with our family resource centres for children and their caregivers, and ends with transitional programs aimed at assisting clients with independent living goals.	reception@pathwaysyorkregion.org	\N	905-471-7877	L3P	\N	\N	\N	\N	https://www.pathwaysyorkregion.org
727	rho	pauline-obrien-rp	Pauline O’Brien, RP	43 Thornton Trail\nHamilton, L9H 6Y2	\N	I provide individual, couples and family counselling and psychotherapy. I provide support in a culturally safe and anti-oppressive environment for a variety of issues including mental health and addiction.	paulineobrienrp@gmail.com	\N	905-536-8830	L9H	\N	\N	Pauline O'Brien\nEd.D., CCC, CCAC, RP	\N	https://www.paulineobrienrp.com
741	rho	pflag-st-catharines	PFLAG St. Catharines	417 Bunting Road\nSt. Catharines, L2M 3Z1	\N	PFLAG is a volunteer organization providing support and information to individuals and families struggling with issues of sexual orientation and gender identity. We provide one on one meetings or telephone support as well as meeting monthly.	don091040@sympatico.ca	\N	905-937-0202	L2M	\N	\N	\N	\N	https://www.pflagcanada.ca/StCatharines.htm
825	rho	seen-vision-care	SEEN Vision Care	2224 Walker Road\nWindsor, N8W 5L7	\N	Comprehensive Eye Exams and Contact Lens Fittings\nWalkerville’s Premiere Professional Eyewear Boutique	seenvisioncare@gmail.com	\N	519-915-2323	N8W	\N	\N	Dr. Mariam Chaudry\nOptometrist	\N	https://www.haveyoubeenseen.com
728	rho	peel-childrens-aid-society	Peel Children’s Aid Society	6860 Century Avenue\nMississauga, L5N 2V8	\N	Peel Children’s Aid Society’s mission is to provide services to protect children and strengthen families and communities through partnership. Our vision is that every child is to be cherished. Our primary focus is to ensure the protection of children from physical, sexual, emotional abuse and neglect within the Region of Peel. Our agency seeks to provide inclusive services and as such welcome volunteers, foster parents and adoptive parents from the LGBTTQQI2 community. We welcome you to contact us for support or as an interest in any of the above noted areas (see website). Peel Children’s Aid Society recognizes the diversity of the community and employs staff with various linguistic and cultural backgrounds. Peel Children’s Aid Society prides itself on being a positive space within the community.	slevac@peelcas.org	\N	905-363-6131	L5N	\N	\N	\N	\N	https://www.peelcas.org
729	rho	peel-childrens-centre	Peel Children’s Centre	Mississauga	\N	Peel Children’s Centre offers many excellent treatment services for children, teenagers, and families who are having serious issues with relationships, feelings, or behaviour.\nWe treat young people under the age of 18 who live in the Region of Peel in Ontario, Canada. The region we serve includes the City of Brampton, the Town of Caledon and the City of Mississauga.\nAt Peel Children’s Centre, we believe in	\N	\N	(905) 451-4655	\N	\N	\N	\N	\N	https://www.peelcc.org/
730	rho	peel-hiv-aids-network	Peel HIV/AIDS Network	160 Traders Boulevard East\nMississauga, L4Z 3K7	\N	PHAN serves the Peel region including Mississauga, Brampton and Caledon.\nOur programs and services at PHAN are based on our mission:\nAIDS is preventable. This is why we collect, distribute, and educate on current information about AIDS and its prevention. Through our community education and outreach programs, we pro-actively communicate with the general public and at-risk populations on HIV prevention, healthy sexuality and harm reduction. Our Health Promotion Team has specialized outreach programs, which are targeted to Men who have sex with Men (MSM), the African Diaspora, and Injection Drug users who are are-risk for HIV infection.\nThe fight against AIDS requires a collective response and broad based community engagement. Our Volunteer program develops and supports a dynamic, well-trained volunteer team which reflects our community and serves the needs of our client base.\nAll our programs collaborate with a broad base of networks, organizations and community members in planning, service delivery and evaluation.\nOur support department provides programs for individuals living with HIV/AIDS and those affected with a range of services including counselling, case management, health promotion, capacity building, and referrals to improve their quality of life.	\N	\N	905-361-0523	L4Z	\N	\N	\N	\N	https://www.phan.ca
731	rho	peninsula-therapeutic-services	Peninsula Therapeutic Services	520 North Service Road\nGrimsby, L3M 4E8	\N	Individual Therapy, Family Therapy, Couple Therapy	samantha@peninsulatherapeuticservices.com	\N	289-921-1747	L3M	\N	\N	Samantha Di Bartolo\nMSW, RSW	\N	https://www.peninsulatherapeuticservices.com/
732	rho	personal-trainer-for-the-spirit	Personal Trainer for the Spirit	489 College Street\nToronto, M6G 1A5	\N	I am a Personal Trainer for the Spirit and I work with people who have already done therapy or are currently in therapy and who’d like to better understand what the body is holding onto, create better choices for themselves and develop a stronger mind, body, Spirit connection. My practice involves energy, body, and spiritual work and I hold a container for people to tap into the natural wisdom that’s available both within and outside to support healing. I work from an anti-oppressive, client centered, queer and trans affirmative, sex positive, and anti-racist approach.	aishatambo11@gmail.com	\N	647-517-4446	M6G	\N	\N	Aisha Tambo\nSomatic Experiencing Professional Training Certificate, Reiki Practitioner	\N	https://somatictherapytoronto.ca
733	rho	personal-training-shiatsu-and-nutrition	Personal training, shiatsu and nutrition	Newmarket, L3Y 3L8	\N	We offer in home personal training, shiatsu therapy and nutritional counselling.	jzkk.liv@hotmail.com	\N	289 231 3560	L3Y	\N	\N	\N	\N	\N
734	rho	peterborough-aids-resource-network-parn	Peterborough AIDS Resource Network – PARN	159 King Street\nPeterborough, K9J 2R8	\N	PARN began when a small group of concerned people got together in 1987 to respond to the growing need for HIV/AIDS services. The result was an incorporated agency which opened its doors August 8, 1990.\nIn the beginning PARN’s services were mainly education and general awareness. Since then, PARN’s work has expanded to address the needs of people living with HIV or AIDS and those directly affected; prevention events; hepatitis C information.\nMany of the programs and services are also provided via outreach to all the communities we serve in Peterborough, City of Kawartha Lakes, Northumberland and Haliburton. All services are confidential.	getinformed@parn.ca	\N	705-749-9110 or Toll-free:  1-800-361-2895	K9J	\N	\N	\N	\N	https://www.parn.ca/
735	rho	peterborough-family-health-team	Peterborough Family Health Team	185 King Street\n5th Floor\nPeterborough, K9J 2R8	\N	Mental health counselling for rostered patients within the Peterborough Family Health Team.	\N	\N	705-740-8020 ext. 323	K9J	\N	\N	Jenny Andrus\nM.Ed., RP, CCC.	\N	https://www.peterboroughfht.com
736	rho	peterborough-public-health-sexual-health-clinic	Peterborough Public Health Sexual Health Clinic	185 King Street\nJackson Square\nPeterborough , K9J 2R8	\N	Sexual Health Clinic Services for residents of Peterborough City and County.	smarino@peterboroughpublichealth.ca	Monday to Friday: 8:30 a.m. to 4:30 p.m.	7057482021	K9J	\N	\N	\N	\N	https://www.peterboroughpublichealth.ca
737	rho	petra-najafee	Petra Najafee	3515 Lake Shore Boulevard West\nToronto, M8W 1N5	\N	Counselling/Psychotherapy	petratherapy@gmail.com	\N	4165264690	M8W	\N	\N	Petra Najafee\nM.Ed, RP	\N	https://petratherapy.ca
738	rho	pflag-canada-goderich	PFLAG Canada Goderich	77722 London Road\nClinton, N0M 1L0	\N	Parents and Friends of Lesbians and Gays.\nBut we also include bisexual, transgender, queer, transsexual, intersex, questioning, etc.!\nAs a chapter of the national PFLAG organization we provide a safe space to come and be yourself!\nweb: pflaggoderich.blogspot.ca/\nFB: www.facebook.com/pflaggoderichon\nPhone us @ the Huron County Health Unit 1.877.837.6143 ext.2257	goderichon@pflagcanada.ca	\N	1.877.837.6143 ext.2257	N0M	\N	\N	Jennifer Zoethout\nChapter Leader	\N	https://www.pflagcanada.ca
739	rho	pflag-canada-niagara-chapter	PFLAG Canada – Niagara Chapter	145 Queenston Street\nSt.Catharines, L2R 2Z9	\N	Pflag Canada is proud to be Canada’s only national organization that offers peer-to-peer support striving to help all Canadians with issues of sexual orientation, gender identity and gender expression. We support, educate and provide resources to anyone with questions or concerns. We promise to offer local, practical, and emotional peer-to-peer family support for individuals and their loved ones challenged by gender/sexual identity.  Support is available one-to-one or in a group setting.  Meetings are open to parents, friends, family members, allies, and members of the 2SLGBTQIA+ community.	niagaraon@pflagcanada.ca	Our Niagara chapter meets on the 2nd Tuesday of each month @ 7:00 pm	888-530-6777 x 600	L2R	\N	\N	\N	\N	http://www.pflagniagara.ca
742	rho	pflag-toronto	PFLAG Toronto	200 Wolverleigh Boulevard\nToronto, M4C 1S2	\N	PFLAG Toronto is a charitable organization that helps LGBTQ individuals and their families during the ‘coming out’ process and the ‘living out’ process, through support and education. A telephone support line provides information. Monthly support meetings offer a support network where peer support is offered through the sharing of our experiences. Both LGBTQ individuals and/or their families or friends are welcome to attend meetings and receive support.	toronto.office@pflag.ca	\N	416-406-6378	M4C	\N	\N	\N	\N	https://www.pflagcanada.ca/chapters/toronto
743	rho	ping-chen-msw-rsw-emdr-ii	Ping Chen, MSW, RSW, EMDR II	Toronto	\N	Provide individual and family counselling through trauma informed and anti-oppressive framework.	pingtherapy@gmail.com	\N	647-795-3732	\N	\N	\N	Ping Chen\nRegistered Social Worker, Psychotherapist	\N	https://www.psychologytoday.com/ca/therapists/ping-chen-msw-rsw-emdr-ii-toronto-on/467941
744	rho	pink-triangle-services-ottawa	Pink Triangle Services Ottawa	331 Cooper Street\nOttawa, K2P 0G5	\N	As a centre for the celebration of sexual orientation and gender diversity, PTS serves a vibrant and diverse community through support, education and advocacy services. We strive in our work to empower all Queer people in greater Ottawa, and to encourage their well-being and prosperity. PTS provides meaningful support services, actively educates in the greater Ottawa area about Queer issues, and advocates for fair and equal rights.\nPTS runs many groups, please check the website for more details.	programs@ptsottawa.org	\N	613-563-4818	K2P	\N	\N	\N	\N	https://kindspace.ca/
745	rho	planned-parenthood-ottawa-ppo	Planned Parenthood Ottawa (PPO)	Unit 404-222 Somerset Street West\nOttawa, K2P 2G3	\N	Planned Parenthood Ottawa is a bit different from other Planned Parenthood’s as we offer only counselling, referral services, and education services. Although we are not a clinic, we are more than happy to help you find one in the area!	ppottawa@ppottawa.ca	Monday to Friday from 10am-5pm. Currently our office is closed due to COVID-19, but clients can call or email us for support.	6132263234	K2P	\N	\N	\N	\N	https://ppottawa.ca/
746	rho	planned-parenthood-toronto-community-health-centre	Planned Parenthood Toronto community health centre	36 Prince Arthur Avenue\nToronto, M5R 1A9	\N	Sexual Health and Primary Health Care for youth 13-29. PPT also offers community programming for young men, new parents, LGBTQ youth and newcomer youth.\nOHIP not required.	ppt@ppt.on.ca	\N	416-961-0113	M5R	\N	\N	\N	\N	https://www.ppt.on.ca/
747	rho	play-therapy-for-children	Play Therapy for Children	Burlington, L7S 2J9	\N	Attachment-focused play therapy.	Playtherapy1@gmail.com	\N	905-580-7529	L7S	\N	\N	Susan Garofolo\nCertified psychotherapist and play therapist	\N	https://www.playtherapyforchildren.com
748	rho	positive-living-niagara	Positive Living Niagara	\N	\N	Positive Living Niagara is a community based, charitable organization, committed to improving the quality of treatment, support and advocacy for all those affected by HIV/AIDS and preventing the spread of the virus through education and awareness. All calls and information are confidential.	hsquires@positivelivingniagara.com	\N	(905) 984-8684	\N	\N	\N	\N	\N	https://www.positivelivingniagara.com
749	rho	positive-living-niagara-2	Positive Living Niagara	120 Queenston Street\nSt. Catharines, L2R 2Z3	\N	We are a community-based organization made up of dedicated and caring staff and volunteers committed to providing support, education and advocacy in a safe and confidential environment to all who are affected by HIV and AIDS.\nIndividuals who are HIV+ may be facing social, health and financial barriers. These individuals can benefit by drawing upon the support and experience available to them through specialized agencies and organized groups in the HIV community. Here at Positive Living Niagara, there are a variety of Support Services for individuals, their family, friends and loved ones.\nPositive Living Niagara also houses Niagara’s needle exchange program, Streetworks where individuals can access harm reduction services, information, naloxone and case management services for people who are using substances. All services are available in more than 170 languages with the support of Language Line.	hsquires@positivelivingniagara.com	\N	905-984-8684	L2R	\N	\N	\N	\N	https://www.positivelivingniagara.com
750	rho	positive-space-consulting	Positive Space Consulting	\N	\N	LGBTQ+ Inclusion consulting and training for individuals and organizations. A certificate of completion is available for clients who complete training.	charlotte@positivespaceconsulting.ca	\N	289-700-8437	\N	\N	\N	Charlotte Shipley	\N	https://www.positivespaceconsulting.ca
751	rho	positive-space-network-halton-region	Positive Space Network, Halton Region	504 Iroquois Shore Road\nOakville, L6H 3K4	\N	PSN offers LGBTQ+ youth drop-in programs in the Halton Region (ages 12-25). These programs allow LGBTQ+ youth to connect with peers and access resources.\nFor more information, contact us!\nemail: psnyouth@rockonline.ca\ncall/text: 289-208-0886\ninstagram: psn.halton	psncoordinator@rockonline.ca	\N	289 208 0886	L6H	\N	\N	Mandy Kiley\nPSN Coordinator	\N	https://www.positivespacenetwork.ca
752	rho	precision-electrolysis-by-cheryl	Precision Electrolysis by Cheryl	5 versailles court\nRichmond Hill, L4c8v4	\N	Affordable electrolysis in a private home setting. Serving the community for over 23 years!	crwhygiene@yahoo.ca	Monday - 1:00 -9:00 Tuesday - 8:00 -9:00 Wednesday - 8:00 - 8:00 Thursday - 8:00 - 8:00 Friday - 8:00 - 5:00 Saturday - 8:00 - 5:00 Sunday - Closed	9057376958	\N	\N	https://www.electrolysisrichmondhill.com/price-list	Cheryl\nregistered electrologist	\N	https://www.electrolysisrichmondhill.com/
753	rho	pregnancy-and-infant-loss-network	Pregnancy and Infant Loss Network	101A Mary Street West\nWhitby, L1N2R4	\N	PAIL Network offers group support in communities all across Ontario. We recognize how important it is for families to feel a connection to others who have experienced a similar loss, and to talk about their loss in a safe space.\nThese groups are facilitated by a PAIL Network group facilitator who has a lived experience of loss and has successfully completed the training required to host a circle of support. Information about the date, time and login details of each group is provided to families after they have completed their PAIL Network request for support form. Families can attend a circle of support for as long as they would like. These groups are typically attended by bereaved parents, and are open to any other adult family members who have been impacted by the loss.	pailnetwork@sunnybrook.ca	Monday-Friday	18883037245	L1N	\N	\N	\N	\N	https://pailnetwork.sunnybrook.ca/
763	rho	psychotherapy-simplevolution-therapy-centre	Psychotherapy – Simplevolution Therapy Centre	503 Danforth Ave\n2nd Floor\nToronto, M4K 1P5	\N	I specialize in trauma, personality disorders, and coping skills for emotional distress, depression and anxiety. I have training in various psychotherapy models, with foundations in trauma-based practices. I believe in sharing both my insights and psycho-education with my clients to support a personal and informed connection in the therapeutic process.\nVisit our services page (https://www.simplevolution.com/ourservices) and team page (https://www.simplevolution.com/our-team) for more information as well.	amira@simplevolution.com	By appointment	647-493-8944	M4K	\N	120-180 Depending on therapist	Amira Lodhi\nMSW, RSW	\N	https://www.simplevolution.com
754	rho	prendergast-counselling	Prendergast Counselling	320 Danforth Avenue\nToronto, M4K 1N8	\N	At times in our lives we experience challenges and difficulties and this is when we seek support. Challenges may include living with shame, depression, anxiety, low-self-esteem, grief and loss. As well there may be situations related to; life transitions, workplace, finances, career, education, family and intimate relationships that are distressing. This is when therapy can help you manage these situations in a self-satisfying and productive manner.\nI am compassionate and caring and will work with you collaboratively to build a professional trusting relationship where we can identify your strengths and abilities with kindness and acceptance. In acknowledging your strengths, together we can discover your potential and develop approaches to work with the challenges you experience.\nWhile working with individuals I will utilize emotion focused therapy, narrative therapy and mindfulness to address your challenges and concerns. The purpose of therapy is to explore your inner world in a safe and caring environment while bringing greater self-awareness to your life.	djpcounselling@gmail.com	\N	416-570-9261	M4K	\N	\N	David  Prendergast\nMSW, RSW	\N	\N
755	rho	pride-central	Pride Central	955 Oliver Road\nThunder Bay, P7B 5E1	\N	We are Lakehead University’s queer resource centre. Our objectives include peer support and referral service, education, resources, advocacy and lobbying, and safe space.\nWe are officially closed during the summer. However, unofficial office hours are posted weekly on our web site’s event calendar, and phone/e-mail correspondence is maintained. We will re-open with regular office hours in September.	pridecentral@lusu.ca	\N	(807) 343-8813	P7B	\N	\N	\N	\N	https://pride.lusu.ca
756	rho	pridewestern	PrideWestern	1151 Richmond Street\nLondon, N6A 3K7	\N	PrideWestern is a University Students’ Council service dedicated to supporting and celebrating gay, lesbian, bisexual, transgender, two-spirited, intersex, asexual, queer, questioning students, and their allies at the University of Western Ontario. Run entirely by students, PrideWestern organizes speakers, support, and events such as coffeehouses on and off-campus, discussion groups, Rainbow Revolution, Pride Ball, and bi-weekly movie nights.\nAs a service of the University Students Council, the majority of PrideWestern ‘s programming is held free of charge! Unlike a club, you do not need to sign up or pay membership fees. Events that are at an additional costs are usually only the large social events, and this will be posted. All programming is open to all, student card or membership is not required. And if you are curious about an event or are hesitant about being a first timer just contact us!	usc.pride@uwo.ca	\N	519 661 2111 x82647	N6A	\N	\N	\N	\N	https://www.pridewestern.ca/
757	rho	prince-edward-county-counselling-and-psychotherapy	Prince Edward County Counselling and Psychotherapy	Prince Edward	\N	Counselling / psychotherapy / social work services	info@peccp.ca	\N	613-476-8550	\N	\N	\N	Adam Terpstra\nRSW, PR, OCT, M.Ed., B.Ed., B.A.	\N	https://www.peccp.ca
758	rho	priority-massage-and-health	Priority Massage and Health	172 Wortley Road\nLondon, N6C 3P7	\N	Alternative health care clinic featuring registered massage therapists, chiropractic care, naturopathic medicine, acupuncture, custom orthotics, craniosacral therapy and ultrasound therapy.	info@prioritymassageandhealth.com	\N	519-642-7469	N6C	\N	\N	\N	\N	https://www.prioritymassageandhealth.com
759	rho	pritwinder-lucky-work-in-progress-mental-health-collective	Pritwinder (Lucky) @ work in progress mental health collective	1304\nDundas Street West\nToronto, M6J1Y1	\N	I am a student therapist offering lower fees as I complete the requirements for my Masters’s program. I am available online and in person from May 2022.\nAs a queer South Asian woman, I hope to provide mental health services to individuals from diverse communities, particularly those from cultures that do not have a keen awareness of mental health, such as my own. I make every effort to incorporate therapeutic techniques carefully drawn from various modalities while maintaining focus on the client’s issues.\nMy personal experiences and my work with people in similar situations influenced my decision to pursue a career in counselling. As an immigrant, I am aware of the complexities and challenges that a new country can present. I am mindful of the impact of acculturation on our beliefs, worldviews, and sense of self across generations.\nI believe that no one is immune to life’s challenges and variabilities. Hopelessness, anxiety, fear, and other negative emotions can become overwhelming, affecting our overall wellness, leaving us exhausted. I help my clients overcome these difficult emotions by providing a non-judgmental, affirming and safe environment that respects boundaries and offers the space they require for their healing process.\n\n	pritwinder@workinprogress.ca	Wednesday: 4pm-8pm Thursday: 11am-8pm Saturday: 4m-8pm	647-417-7294	M6J	\N	Sliding scale range - $/Hour Minimum: 50 Maximum: 100	\N	\N	https://www.workinprogressto.ca/lucky
760	rho	progressive-health-centre	Progressive Health Centre	600 Sherbourne St\nSuite 407\nToronto, M4K 3H3	\N	Acupuncture.\nChinese Medicine.\nShiatsu Therapy. Naturopathic Medicine.	danforthprogressive@rogers.com	Monday - Saturday	647 801-1735	M4K	\N	$100\nSliding scale range - $/Hour Minimum: 50.00 Maximum: 100	William Hossack\nRTCMP, RAc	\N	http://danforthprogressive.holisticpresence.com/
761	rho	psych-company	Psych Company	20 Eglinton Avenue East\nToronto, M4P 1A6	\N	Are you experiencing personal difficulties? If your emotional & mental health, relationships, career and any other area of your life could use a transformation than our psychotherapy services can help you! We offer the support and tools you need to thrive.\nWe are a team of highly educated, accredited and experienced psychotherapists, psychologists, counselors, relationship counselors and life coaching therapists. Our team is equipped and passionate about helping with any emotional and mental health issues as well as personal and professional needs.	info@psychcompany.com	\N	647-691-5210	M4P	\N	\N	\N	\N	https://www.psychcompany.com
762	rho	psychological-services	Psychological Services	Toronto	\N	I am a clinical psychologist in the province of Ontario providing care to all adults struggling with mental health. Working from a Dialectical Behavioural Therapeutic lens; services are delivered to enhance strengths and target perceived weaknesses. The goal is to provide treatment benefits that are sustained over a long period of time.\nThose that are struggling with depression, anxiety and triggers such as difficult transitions, trauma or life events are welcome to call/text or email. Addictive or maladaptive behavioural patterns can be addressed from a behavioural approach as well. LGBTQ+ inclusive.	judiththepsychologist@gmail.com	\N	416-786-4036	\N	\N	\N	Judith Levy-Ajzenkopf\nPh.D., C.Psych	\N	\N
764	rho	psychotherapy-virtual-in-person	Psychotherapy (Virtual & In-Person)	20 Floral Parkway\nUnit A3\nVaughan, L4K 4R1	\N	My approach involves treating every client with respect, compassion, empathy, understanding and acceptance, no matter what their identity is.\n…\nLGBTQ2S+ individuals should not have to ‘defend’ themselves to society, nor educate others on their identities. Awareness is key, but so is acceptance of queer and trans people. However, given systemic discrimination – soul-crushing macroaggressions and microaggressions – are part of everyday life. Stereotyping and violence are all too common in a country we call “safe” like Canada.\n“Isms” can take place in everyday spaces, at work or even in medical settings. When we are not able to express our opinions, reveal our emotions, and share our experiences, our feelings are stored and manifested in the body, leading to chronic pain and other somatic experiences (i.e., jaw clenching, teeth grinding). Repressed emotions may be good for others, but they are detrimental to our well-being. That’s where therapy comes in as a confidential space to paint a true picture of your lived experience. Nothing is too big or too small to bring up in therapy.\nI do not support toxic positivity and strongly believe that Canada has a lot of work to do when it comes to human rights.\n…\nAs an RP (Qualifying) at Your Story Counselling Services, I provide an open space to share your unfiltered thoughts, opinions, and experiences. Let’s challenge the dominant discourse together.\nSliding scale rates are available for both virtual and in-person counselling. The office is located in Vaughan, accessible by public transit.\n…\nUse the website link to schedule a free 15-minute consult.	brittneyr.ysc@gmail.com	Wednesdays, Thursdays 1-8 pm by appointment Saturdays, Sundays 12-4 pm by appointment	289-963-9868 x 4	L4K	\N	Sliding scale range - $/Hour Minimum: 20 Maximum: 75	Brittney Rossi\nRegistered Psychotherapist (Qualifying)	\N	https://yourstory.janeapp.com/#/staff_member/36
765	rho	psychotherapy-with-alex	Psychotherapy with Alex	Guelph, n1g 2w1	\N	I offer individual low-cost counselling services to individuals who are struggling with relationships, anxiety and LGBTQ+ issues. As a student therapist, I value collaborating with my clients and incorporating client-centred, culturally respectful techniques into our work. My goal is to make every client feel seen, heard, and valued as they are, regardless of their sexuality, gender, ethnicity and beliefs.	alex@charlottepidgeon.com	Monday - Wednesday: noon - 6 p.m.	6476258949	\N	\N	Sliding scale range - $/Hour Minimum: 40 Maximum: 80	Alex Zebeljan\nBA, MACP Student	\N	https://www.charlottepidgeon.com/lowcosttherapy
766	rho	pure-wellness	Pure Wellness	1596 Regent Street\nGreater Sudbury, P3E 3Z6	\N	Pure Wellness Group is a naturopathic medicine clinic located in Sudbury, Ontario. Founded on an integrative approach to whole health, patients receive individualized care that goes beyond symptoms to identify and address the root cause of illness.\nOur naturopathic doctors and multi-disciplinary health care practitioners, cutting-edge diagnostic techniques, modern naturopathy treatments and more traditional systems of medicine direct lifestyle changes, clinical nutrition, whole foods, botanical therapies, homeopathic remedies and traditional Chinese medicine to guide you on your path to optimal health and wellness.	reception@purewg.ca	\N	705.586.7873	P3E	\N	\N	\N	\N	https://purewg.ca/
767	rho	queenan-family-medicine-maternity-care	Queenan Family Medicine & Maternity Care	25 Main Street\nPenetanguishene, L9M 1S7	\N	Dr Queenan is a family doctor who provides full-spectrum primary care, that is primary care for all ages, along with non-surgical gynecological care and low-risk obstetrical care; she attends deliveries at Georgian Bay General Hospital.\nShe is particularly interested in supporting normal physiologic birth, informed by both her medical training and her training as a doula, a woman who supports women in labor, delivery, and the postpartum period.\nShe also has professional interest and added training in transgender medicine, and is happy to provide care to gender diverse patients, including providing transition-related care.\nShe also has particular interest and experience in hospice and palliative care, and is honoured to work with patients and families during this time of life.\nDr Queenan’s care is informed by her training in integrative and holistic medicine. That is to say that she aims to approach patients as whole people, not merely the sum of their parts, and is able to integrate a variety of modalities into a patient’s treatment plan as is desired by the patient and clinically indicated; these modalities include herbal medications, nutritional supplements, bodywork including chiropractic care and massage, mind-body modalities including meditation and hypnosis and yoga and tai chi, and spiritual and energy work including acupuncture and reiki. She freely collaborates with integrative providers including naturopaths, chiropractors, massage therapists, etc.	DrEmily@Queenan.ca	\N	8552437772	L9M	\N	\N	Emily Queenan\nMD, ABFM	\N	https://www.queenan.ca
768	rho	queens-family-health-team-qfht-ae-belleville-quinte-site	Queen’s Family Health Team (QFHT) â€“ Belleville-Quinte Site	145 Station Street\nBelleville, K8N 2S9	\N	Trans and gender-diverse primary care.	\N	\N	(613) 771-1910	K8N	\N	\N	Andrew Robertson\nDr.	\N	\N
769	rho	queerly-nutrition	Queerly Nutrition	Toronto, M6P 0B4	\N	Registered Dietitian\nInstagram @queerlynutrition	craig@queerlynutrition.com	10 a.m. - 6 p.m.	XXXXXXXXX	M6P	\N	\N	\N	\N	https://www.queerlynutrition.com
770	rho	rahim-kanji-naturopath	Rahim Kanji Naturopath	94 Cumberland Street\nToronto, M5R 1A3	\N	Naturopathic Doctors use nutrition, botanical medicine, acupuncture, and intravenous (IV) vitamins/minerals to treat disease. Our goal is to treat the cause of disease, rather than suppress symptoms, and we look at disease through a holistic framework.\nI have experience treating the LGBTQ community as well as patients with HIV/AIDs, so I am aware of the specific health risks of these populations. I’m passionate about integrative medicine, and evidence-based natural treatments.	dr.rkanji.nd@gmail.com	\N	416-920-4325	M5R	\N	\N	Rahim Kanji, N.D.\nNaturopathic Doctor	\N	https://www.rahimkanjind.com
771	rho	rahim-thawer-affective-consulting-training-services	Rahim Thawer – Affective Consulting & Training Services	179 Carlton Street\nToronto, M5A 2K3	\N	Individual psychotherapy, private practice.\nClinical Specialties:\nCounselling/Therapy\nGender-Related Issues/Sexual Issues\nGrief/Trauma/Loss\nMental Health/Addictions\nNonClinical Specialties:\nConsulting/Group Facilitation\nStaff Training/Development\nConducting Workshops/Seminars\nSpecialized Training:\nI work from an integrated anti-oppressive, cognitive-behavioural therapy and psychodynamic approach. I can provide short-term or longer term therapy through collaborative goal setting.\nPersonal Statement:\nI offer individual psychotherapy in a central location. I have clinical experience working with addictions, people living with and affected by HIV, broader LGBT communities, adolescents, and newcomers to Canada. Common issues faced by my clients include: sexuality, identity, relationship issues, anxiety, depression, self-esteem, & trauma. My therapeutic approach is an integration of cognitive-behavioural, psychodynamic and anti-oppressive practice. In addition, I provide consulting and training services in areas of anti-oppression and “cultural competency”, social determinants of LGBT health, healthy relationships, intersections of mental health and sexual health, counselling skills, and more. I can also provide mental health case consults for teams. For more information, visit www.affectiveconsult.ca	rahim@affectiveconsult.ca	\N	416-904-9721	M5A	\N	\N	Rahim Thawer\nMSW, RSW	\N	https://www.affectiveconsult.ca
772	rho	rail-city-therapy	Rail City Therapy	28 Princess Ave\nSt Thomas, N5R2J6	\N	Embodied, relational Gestalt Psychotherapy.  I am a NB person, with 34 years of experience in Mental Health. I am a Registered Psychotherapist (qualifying) in Canada, and an internationally trained psychologist,  and neurocriminologist, I specialize in working with folks with various intersectionalites such as ND+on a Gender Journey; ND and substance users; BIPOC folks on the spectrum,  LGBTQ2S+ families affected by Alcoholism and Addictions, etc.  I welcome, and hold a safe space for all members of our LGBTQ2S+ community, and have completed the trainings offered by RHO to support transitions.\nI also provide integration services under a Harm Reduction model to those who explore Plant Medicine options to support their growth, and healing.\nDo not hesitate to write if you have any questions! I look forward to hearing from you.	hope@railcitytherapy.com	Tuesday to Friday: 9.30 AM to 7:30 PM	(833) 455-0834	N5R	true	Sliding scale range - $/Hour Minimum: 110 Maximum: 150	Hope M. Pelufo\nRP(Q), M.Sc.	\N	https://www.railcitytherapy.com
783	rho	reconnect-mental-health-services	Reconnect Mental Health Services	56 Aberfoyle Crescent\nToronto, M8X 2W4	\N	Reconnect Mental Health Services is a community based agency, located in Toronto. We offer intensive case management and support services to individuals 16 years and up with complex mental health needs, including developmental disabilities, substance use and physical health challenges.\nServices are easily accessible and include highly agile clinical supports in the form of case management, assertive community treatment, justice prevention and diversion services, 24/7 short-term residential crisis services, group based services, and employment programs	contact@reconnect.on.ca	\N	(416) 248.2050	M8X	\N	\N	\N	\N	https://reconnect.on.ca/
773	rho	rainbow-alliance-laurier-brantford	Rainbow Alliance – Laurier Brantford	103 Darling Street\nBrantford, N3T 2K6	\N	The Rainbow Alliance exists as a support system that promotes awareness, acceptance, and advocacy for the LGBTQ community and its allies. They are dedicated to creating a positive campus experience for everyone with no assumptions and in which all individuals are encouraged to be themselves without fear of judgement or discrimination. The Rainbow Alliance operates out of the Diversity Lounge, which provides students with a safe place to get student-provided information and support for the LGBTQ community, as well as an assumption-free area for students to do homework, group work, or just hang out between classes.	rainbowalliance@wlu.ca	\N	519-756-8228 x5715	N3T	\N	\N	\N	\N	https://www.lbstudentaffairs.ca/student-life/diversity/committees/lbra.htm
774	rho	rainbow-caregivers-network	Rainbow Caregivers Network	154 Cannifton Road North\nBelleville, K0K 1K0	\N	RAINBOW CAREGIVERS NETWORK\nIs a peer support group for people who care for individuals who identify within the LGBTQ+ community. Whether you are a parent, grandparent, teacher or care provider you are welcome to attend.	jld1307@yahoo.ca	\N	16138494641	K0K	\N	\N	Jackie Dales\nRN	\N	https://www.transforumquinte.ca/rcn
775	rho	rainbow-niagara-lgbtq-services-at-quest-community-health-centre	Rainbow Niagara LGBTQ+ Services at Quest Community Health Centre	145 Queenston Street\nSt. Catharines, L2R 2Z9	\N	Provides primary health care including health promotion, chronic disease management and community development to priority populations including; sexually and gender diverse communities, isolated seniors, persons experiencing mental health, addiction and/or concurrent disorders, persons who are homeless/under-housed, at risk children and youth, migrant agricultural workers, and individuals who frequent the emergency department for their care and/or are opiate dependent.  Services are for persons who are not registered with a primary care practitioner or who are having trouble accessing health care that they need. No health card is required.\nRainbow Niagara LGBTQ+ Services include:\nOur interdisciplinary team focuses on the delivery of culturally competent LGBTQ+ services to individuals across their lifespan.\nIf you are seeking culturally competent primary health care and/or trans specific health care contact our front office coordinators at 905 688-2558 ext: 0 to book an intake appointment.\nFor more information about Rainbow Niagara LGBTQ+ outreach and community programs contact Stephanie Vail, Community Health Worker, at 905 688-2558 ex. 222.	svail@questchc.ca	Monday - Friday: 8:30 a.m. to 4:30 p.m.	905 688-2558 ext: 0	L2R	\N	\N	\N	\N	https://www.questchc.ca
776	rho	rainbow-services-centre-for-addiction-and-mental-health	Rainbow Services – Centre for Addiction and Mental Health	60 White Squirrel Way\nToronto, M6J 1H4	\N	Rainbow Services provides counselling to lesbian, gay, bisexual, transgender, transsexual, two-spirit and intersex people who are concerned about their use of drugs and alcohol. Our services are available to individuals with a variety of goals, including those who want to try to quit, cut down, or who would just like to gain more awareness about their drinking or drug use.	info@camh.ca	\N	Intake: 416-535-8501 press 2	M6J	\N	\N	\N	\N	https://www.camh.ca/
777	rho	raven-parkinson-massage-therapy	Raven Parkinson Massage Therapy	102 Brierdale Drive\nKitchener, N2A 3S8	\N	I am a trans-identified massage therapist working in the tri-cities area providing on-site treatment. I graduated from the Canadian College of Massage & Hydrotherapy in 2011 and have recently become registered. I have many years experience from my time in the student intern clinic and the various community and hospital outreaches I was involved in during my time at CCMH.	ravenrmt@gmail.com	\N	5195040470	N2A	\N	\N	Raven Parkinson\nRMT	\N	\N
778	rho	raymond-fung-m-d-endocrinologist	Raymond Fung M.D. – Endocrinologist	650 Sammon Avenue\nToronto, M4C 5M5	\N	Dr. Raymond Fung is an endocrinologist who will also prescribe hormones to trans folks in consideration with the endocrine system and hormonal imbalances due to issues such as diabetes, thyroid issues etc. He works at Toronto East General Hospital.	\N	\N	(416) 915-5460	M4C	\N	\N	\N	\N	\N
779	rho	rbois-speech-and-language-services-dorthophonie	RBois Speech And Language Services d’orthophonie	Sudbury , P3B3P1	\N	Voice feminization (vocal training)	roxannebois.slp@gmail.com	Hours of operation are flexible	7052077928	P3B	\N	$150 per hour	Roxanne\nBois	\N	https://www.rboisspeechlanguageservicesdorthophonie.com/
780	rho	rean-cross-doula	Rean Cross Doula	206 Willow Avenue\nToronto, M4E 3K5	\N	Lucina provides doula support for labour and the first few weeks postpartum, thought-provoking prenatal classes and placenta services.\nI support pregnant people in creating their own definition of the ideal birth experience. I also support them in creating their own definition of family. Everyone has the right to decide who will support them during childbirth, and who (if anyone) will parent with them. My practice therefore welcomes clients in any relationship structure.\nA Birth Doula works with you and your family during pregnancy and childbirth. I meet with you during your pregnancy to answer questions and help you prepare a birth plan. I offer continuous support during your labour and birth, including comfort techniques and the provision of information to support you in informed decision making.\nA Postpartum Doula works with you for the first few weeks after your baby is born. I help ensure that breastfeeding, where appropriate, is off to a good start, and help you and your family settle into your new life together.\nI also offer community-based prenatal classes.\nMany people choose childbirth education at their birthing hospital or with their midwifery practice. Others prefer to take classes that are not affiliated with the birth setting. This can allow you to access information tailored to your specific needs.	info@lucina.ca	\N	416-737-4086	M4E	\N	\N	Rean Cross\nDoula	\N	https://www.lucina.ca
781	rho	rebecca-lester-counsellor	Rebecca Lester Counsellor	86 Homewood Avenue\nHamilton, L8P 2M4	\N	I am thrilled to offer individual and relationship counselling to all people who identify as LGBTTTQQIAA. I have personal and professional experience supporting people of all ages with working through identity issues so that we can live well with our truest selves. I also understand that for many people in our community issues related to identity are not the most pressing. It is often everyday life that affects us most and we need support around personal growth, relationships, parenting, and school or work life just like everyone else does. I offer counselling services to individuals, couples, families and polyamorous partners. Although I don’t have professional experience working with people who identify as Intersex, Two-Spirited or Asexual I am more than happy to offer my services to you.	counsellor@rebeccalester.ca	\N	289-921-8845	L8P	\N	\N	Rebecca Lester\nMSW, RSW	\N	https://www.rebeccalester.ca
782	rho	reclaim-counselling-and-wellness	Reclaim Counselling and Wellness	110A Hannover Drive\nSt. Catharines, L2W 1A4	\N	Your organic and holistic source for health care. Healing body, mind, and spirit! All service providers at Reclaim Counselling & Wellness Centre are happy to work with the LGBTTTIQ communities. We provide a variety of health services and products. Call or email for details.\nAlthough there is usually someone in the office during normal office hours services are generally by appointment. Some Saturday and extended evening appointments available.	info@reclaimcounselling.com	\N	289-479-5155	L2W	\N	\N	\N	\N	https://www.reclaimcounselling.com
784	rho	red-pearl-homeopathy	Red Pearl Homeopathy	344 Bloor Street West\nToronto, M5S 3A7	\N	I offer holistic treatment to individuals using Homeopathic Medicine and Reiki. Homeopathic medicine is a truly holistic medicine that works on finding one medicine made from a natural substance that is the best match for each person and their symptom picture. By doing so, the body is stimulated to heal itself. Homeopathy is safe and gentle; has no side effects and won’t interact with any prescribed pharamceutical medications.\nReiki is an type of energetic touch therapy that was developed in Japan in the late nineteenth century. It involves a practitioner laying their hands on a person in various hand positions. It is useful for emotional, physical and spiritual health.\nAreas of specialization are: LGBT health care, women’s health, pediatrics and HIV/AIDS.	redpearlhomeopathy@gmail.com	\N	647-688-8290	M5S	\N	\N	Rebecca Gower\nHomeopath DSHM (hons)	\N	https://www.redpearlhomeopathy.com
785	rho	regeneration-station	Regeneration Station	149 roncesvalles ave\nUnit 201\nToronto, M6r 2l3	\N	Registered Massage Therapy providers who identify/ live in solidarity with LGBTQ2S+persons\n	info@regenerationstation.ca	Daily 9am-8pm	4165355210	\N	\N	\N	\N	\N	https://www.regenerationstation.ca/
786	rho	regent-park-community-health-centre	Regent Park Community Health Centre	465 Dundas Street East\nToronto, M5A 2B2	\N	Regent Park CHC is dedicated to improving the health of Regent Park area residents and the community as a whole, by providing high quality, integrated primary health care services, health promotion services and community capacity building. Our priority is to reduce the health inequities experienced by low-income, immigrant & refugee, non-status and marginally-housed & homeless populations.	\N	\N	(416) 364-2261	M5A	\N	\N	\N	\N	https://www.regentparkchc.org
787	rho	regional-hiv-aids-connection-london	Regional HIV/AIDS Connection – London	186 King Street\nLondon, N6A 3N7	\N	Regional HIV/AIDS Connection serves the six counties of Perth, Huron, Lambton, Elgin, Middlesex and Oxford.	info@hivaidsconnection.ca	\N	519-434-1601	N6A	\N	\N	\N	\N	https://www.hivaidsconnection.ca/
788	rho	registered-dietitian-services	Registered Dietitian Services	219 Oxford Street West\nLondon, N6H 1S5	\N	Registered Dietitian Services (RD Services) is a company based in London, dedicated to providing high quality, evidence-based, client-centered nutritional assessments and counselling, as well as group workshops and seminars.	info@rdservices.ca	\N	5196451620	N6H	\N	\N	\N	\N	https://www.rdservices.ca
789	rho	reiki-with-cherokee-macleod	Reiki with Cherokee MacLeod	2005 Danforth Avenue\nToronto, M4C 1J7	\N	Reiki is a healing technique based on the principle that the therapist can channel energy into the patient by means of touch, to activate the natural healing processes of the patient’s body and restore physical and emotional well-being.\nI am available at The Healing Collective on Wednesdays from 5-9 PM by appointment. Home visits can also be arranged.	macleod.cherokee@gmail.com	\N	416-890-6484	M4C	\N	\N	Cherokee MacLeod\nCRA-RP	\N	https://www.healingcollective.ca/collective-members/cherokee-macleod/
790	rho	relationship-matters-therapy	Relationship Matters Therapy Centre	150 Water St South, Suite 204, Cambridge ON\nCambridge , N1R 3E2	\N	I approach therapy from a postmodern, systemic and relational lens – but what does that mean exactly?\nIn my therapeutic work, I recognize how we do not live in isolation. We all live in the context of much larger systems and multiple relationships that inevitably have an impact on how we experience the world.\n​In my conversations with clients, I keep this vital piece at the forefront of my mind as we continue with the therapeutic work.\n​Also, I draw from different therapeutic modalities in order to best fit your needs. As an integrative therapist, my influences come from Collaborative Therapy, Solution Focused Brief Therapy, Narrative Therapy, Gottman Method Couple Therapy, Dialectical Behaviour Therapy and Emotionally Focused Couples Therapy.\n​As an individual who holds different roles and identities, I recognize the difficulties and hardships that can be uncovered when navigating different systems.\nI have both personal, and professional experience in navigating systemic barriers, along with experiences of oppression and marginalization.\nAs a therapist, it is my goal to uphold my values and beliefs in the work that I do with my clients. I believe in being honest and authentic as a person, while also being skilled, knowledgeable, and resourceful as a clinician.\nI strive to maintain an open and honest dialogue with my clients in a way that speaks to who we are and honours our experiences. I do not believe in a robotic or prescriptive way of being. Rather, it is my hope that in every interaction that I have with clients I am able to do so in the most human way possible. In a way that highlights honesty, advocacy, and empathy, while also upholding your dignity and decency as a human being.	admin@relationshipmatterstherapy.com	Monday-Friday 9am-8pm	226-894-4112	N1R	\N	\N	Jason Carrasco\nMSc., RP, RMFT	\N	https://www.relationshipmatterstherapy.com/
791	rho	renascent	Renascent	Toronto	\N	Renascent is committed to providing recovery and hope to individuals, families, organizations, and communities affected by substance addictions. Our evidence-based programs are centred on the person and provide a strong abstinence and Twelve Step approach. We help people achieve lifelong recovery and freedom from drugs and alcohol	info@renascent.ca	\N	866-232-1212	\N	\N	\N	\N	\N	https://renascent.ca/
792	rho	renee-pilgrim-acupuncture	Renee Pilgrim Acupuncture	18 Beverley Street\nToronto, M5T 3L2	\N	The people that seek my services are looking to make changes in their lives.\nFrom dealing with addictions, various life transitions & generally searching for better health and quality of life.\nThe Acupuncture I practice is based on Traditional Chinese Medicine as well as Five Element Principles. Within these modalities I am able to work on a physical, emotional, and psychological level with patients to help them achieve their health goals.\nI have been trained in the NADA protocol for addictions, in pain management therapies & protocols including TUINA massage (Chinese style therapeutic massage for such conditions such as injuries, digestive problems, PMS & migraines) & lifestyle counseling using the fundamentals of Chinese Medicine Practice around food & lifestyles. Over the past 2 years I have been working at PWA as an Acupuncturist providing services through my school to support the people living with HIV & AIDS.\nIn life and in practice I work from a framework of anti-oppression and seek to continue my awareness, knowledge and practice in this path. My work is Queer & Sex Positive.	acupuncture@reneepilgrim.com	\N	416 919 3769	M5T	\N	\N	Renee Pilgrim\nDiploma Of Acupuncture	\N	http://www.reneepilgrim.com/
793	rho	reseau-access-network	Réseau ACCESS Network	111 Elm Street\nGreater Sudbury, P3C 1T3	\N	Réseau ACCESS Network is a non-profit, community-based charitable organization, committed to promoting wellness, harm and risk reduction and education.  Réseau ACCESS Network supports individuals and serves the whole community – in a comprehensive / holistic approach to HIV/AIDS, Hep C and related health issues.	aaninfo@reseauaccessnetwork.com	\N	(705) 688-0500	P3C	\N	\N	\N	\N	https://www.accessaidsnetwork.com/
794	rho	reseau-access-network-2	Réseau ACCESS Network	\N	\N	Réseau ACCESS Network is a non-profit, community-based charitable organization, committed to promoting wellness, harm and risk reduction and education.  Réseau ACCESS Network supports individuals and serves the whole community – in a comprehensive / holistic approach to HIV/AIDS, Hep C and related health issues.	aaninfo@reseauaccessnetwork.com	\N	(705) 688-0500	\N	\N	\N	\N	\N	https://www.accessaidsnetwork.com/
795	rho	restoration-mental-health-agency	Restoration Mental Health Agency	Hamilton, L8N 2B6	\N	Psychotherapy is offered for anxiety, depression, grief, trauma, communication, anger, relationships, boundaries, life transitions, identity, and other life events. Psychotherapy opens the door to allow a safe space to explore your inner thoughts, feelings and actions in a place that does not carry the burden of judgement. An integrative or naturopathic approach to mental health concerns means working to find the right balance for you. It means looking at the whole picture, and root issues that can cause or contribute to mental health concerns. These may include: Healthy Neurotransmitter Support, Hormone Balance, Blood Sugar Regulation, Nutrition Factors, Vitamin & Mineral Status Address Inflammation Lifestyle Habits Thyroid Health.	restorationmentalhealthagency@gmail.com	Tuesdays 11 AM to 7PM Virtual Drop in sessions By Appointment Only (No Walk-ins at this time.)	905-317-2510	L8N	\N	$100.00\nSliding scale range - $/Hour Minimum: 40 Maximum: 80	\N	\N	https://www.restorationmentalhealth.com/
796	rho	rexdale-community-health-centre	Rexdale Community Health Centre	8 Taber Road\nToronto, M9W 3A4	\N	Rexdale CHC serves individuals and families living in the area bounded to the north by Steeles Avenue, to the south by Dixon Road, to the west by Highway 427 and to the East by the Humber River.\nRexdale Community Health Centre delivers integrated, coordinated clinical services through a team of physicians, nurse practitioners, nurses, dietitians, social workers, a physiotherapist and a chiropodist. Our multi-disciplinary team addresses the health needs of individuals and families at all ages and stages of their lives. In collaboration with the City of Toronto’s Public Health department, Rexdale CHC also offers dental services for children, students and seniors.	\N	\N	416-744-0066	M9W	\N	\N	\N	\N	https://www.rexdalechc.com/
797	rho	rick-vassallo-therapy	Rick Vassallo Therapy	45 Forty Second Street\nToronto, M8W 3P4	\N	Support and training in: relaxation therapies, for smoking, weight, anxiety, stress management, life transitions, goal setting, motivation, boundary formation, habit change, habit improvement, relaxation dynamics. Psychotherapy, hypnotherapy, massage, energy therapy.	thehypnosisroom@yahoo.com	\N	416-871-1677	M8W	\N	\N	\N	\N	https://www.rickvassallo.com
798	rho	rick-vassallo-therapy-2	Rick Vassallo Therapy	\N	\N	Support and training in: relaxation therapies, for smoking, weight, anxiety, stress management, life transitions, goal setting, motivation, boundary formation, habit change, habit improvement, relaxation dynamics. Psychotherapy, hypnotherapy, massage, energy therapy.	thehypnosisroom@yahoo.com	\N	416-871-1677	\N	\N	\N	\N	\N	https://www.rickvassallo.com
799	rho	rideau-community-health-services	Rideau Community Health Services	354 Read Street\nMerrickville-Wolford, K0G 1N0	\N	Rideau Community Health Services includes Smith Falls CHC, Merrickville CHC, Rideau Valley Diabetes Services and various telemedicine partners.\nCommunity Health Centres (CHCs) offer a range of primary health care and health promotion programs to the diverse communities in and around Merrickville and Smiths Falls. Services at CHCs in Smiths Falls and Merrickville and indeed across Ontario are organized to make it easy for people facing barriers to get the help they need. Barriers such as transportation, poverty, racism, homophobia, or disabilities can get in the way of people accessing good health care. With this in mind, both the Smiths Falls and Merrickville CHCs offer the services of doctors, nurse practitioners, nurses, social workers, and health promotion workers to registered clients. Some services like walking groups, help with quitting smoking, or community gardens are offered to the general public	info@RideauCHS.ca	\N	(613) 269-3400	K0G	\N	\N	\N	\N	https://www.rideauchs.ca/
800	rho	rideauwood-addiction-and-family-services	Rideauwood Addiction and Family Services	312 Parkdale Avenue\nOttawa, K1Y 4X5	\N	Rideauwood offers evidence based community addiction treatment services targeted for youth (ages 12-25), adults, parents, and families. Services include: assessment, treatment planning, individual counselling, group counselling, referral and follow-up. The programs incorporates a harm reduction and abstinence approach and treatment is based upon individual client needs. Counselling services are provided both day and evening.\nRideauwood prides itself on being a safe space for individuals identifying as LGBT2SQ seeking substance use & addiction services.	admin@rideauwood.org	Our phone is answered between the hours of 8:30 am to 4:30 pm, Monday to Friday.	(613) 724-4881	K1Y	\N	\N	\N	\N	https://www.rideauwood.org/
801	rho	rising-insight-counselling	Rising Insight Counselling	521 Colborne St.\nLondon, N6B 2B7	\N	Kimberly is a Registered Social Worker who works with individuals, couples, and youth on a wide variety of issues with specialization in gender, sexuality, identity, trauma, anxiety, and depression.  She approaches counselling with a narrative philosophy and utilizes an eclectic range of tools and methods to help you regain control of your own story.	kimberly.gautreau@risinginsightcounselling.com	Wedenesday's and Friday's 10-8, Weekends by arrangement. Both in-person and online sessions available	2267814104	N6B	\N	Sliding scale range - $/Hour Minimum: 130 Maximum: 150	Kimberly Gautreau\nMSW, RSW	\N	https://www.risinginsightcounselling.com/
802	rho	rising-insight-counselling-psychotherapy	Rising Insight Counselling & Psychotherapy	521 Colborne Street\nLondon, N6B 2B7	\N	At Rising Insight Counselling and Psychotherapy, we believe that everyone has the ability to become the person that they want to be. As registered mental health professionals, we work with individuals and couples to create a space for the development of insight which allows you to be the person you want to be. We work in partnership with you, the expert on your life, and we walk along with you to help you better your experience.\nWe are committed to providing an experience where you feel valued, safe and respected which we believe is necessary for you to benefit from counselling and psychotherapy. We pride ourselves on our dedication to anti-oppressive practice and being LGBTQIA2S+, neurodivergent, and polyamory inclusive; we work to create a space that is safe and confirming to the intersections of your identity.\nTo give you the best services that we can, we have clinicians trained in a number of modalities including Acceptance and Commitment Therapy (ACT), Cognitive Behaviour Therapy (CBT), Dialectical Behaviour Therapy (CBT), narrative therapy, neurofeedback and Gottman’s Couple’s Counselling. We are committed to empowering our clinicians to develop skills to support a diverse range of concerns and needs. If your concern is outside the scope of our practice, we can support you in finding a clinician who can help you.	admin@risinginsightcounselling.com	Flexible booking availability, including days, evenings and weekends.	226-781-4104	N6B	\N	$130+	\N	\N	https://www.risinginsightcounselling.com
803	rho	robertpetrietherapy	RobertPetrieTherapy	120 Perth Avenue\nSUITE 512\nToronto, M6P 4E1	\N	I am a registered psychotherapist with master’s level training in a range of modalities to treat a variety of mental disturbances such as anxiety, depression, SUDs, relationships, existential, etc..	robertpetrie29@gmail.com	\N	5145504415	M6P	\N	\N	Robert Petrie\nRegistered Psychotherapist	\N	https://member.psychologytoday.com/ca/home
805	rho	robin-magder-rmt	Robin Magder, RMT	Toronto	\N	I am a Registered Massage Therapist who works with the body to explore the root causes of physical pain and discomfort, as well as provide relaxation massages for stress relief.\nI graduated from Kikkawa College in June of 2016 where I became proficient at Swedish massage, myofacial release and deep tissue massage. My practice as a Massage Therapist is grounded in more than five years of experience in the social work field where I became acutely aware of the ways that social factors impact people’s bodies.\nUsing massage therapy, I encourage soft tissues and joints to realign. In this way, the body is given an opportunity to use it’s own restorative wisdom. I work within my client’s comfort level to bring calm and healing to people experiencing a range of issues including chronic pain, sports or other injuries, headaches and migraines, and chronic musculoskeletal conditions. I also understand Massage Therapy to be preventative in its ability to increase well-being through general relaxation treatments and alignment maintenance.\nMy practice is body positive, and queer and trans welcoming. I strive to make massage therapy accessible by fostering supportive and caring relationships with the people I work with.	robinmager.rmt@gmail.com	\N	6478259698	\N	\N	\N	Robin Magder\nRegistered Massage Therapist	\N	\N
806	rho	rocco-gizzarelli	Rocco Gizzarelli	180 James St. South Suite 207\nHamilton , L8P 4V1	\N	Provide counselling services to LGBTQ2+	roccogizzarelli@gmail.com	by appointment	905-512-8419	L8P	\N	$100 per hour	\N	\N	http://gizzarelliandassociates.com
807	rho	rock-reach-out-centre-for-kids	ROCK – Reach Out Centre for Kids	471 Pearl Street\nBurlington, L7R 4M4	\N	ROCK has been providing mental health services since 1974. We began as CATC Children’s Assessment and Treatment Services and merged with HASS Halton Adolescent Support Services in 2002. In 2006 we rebranded to become ROCK Reach Out Centre for Kids. In 2008 we were joined by The Burlington Family Resource Centre in order to provide OEYC and Early Years programming.\nConnecTions – social group for trans/gender independent youth and their families/caregiver runs the 1st Wednesday of the month at the ROCK Oakville offices – 504 Iroquois Shore Road, Unit 12A from 6:00pm – 8:00pm (Next dates: [rescheduled for] July 22, Sept 2, Oct 7, Nov 4, Dec 2)\nMilton LGBTQ  Youth Drop-In runs the first Thursday of the month 5:00-8:00pm Milton Hub 540 Commercial Street (Next dates: June 4th, July 2)\nBurlington LGBTQ+ Youth Drop-In runs the 2nd Tuesday of the month at Mountainside Recreation Centre 2205 Mount Forest Drive from 5:00pm – 8:00pm (Next dates: Jun 9, July 14)\nActon LGBTQ+ Youth Drop-In runs the 3rd Wednesday of the month at Acton Hub McKenzie-Smith Bennett Public School (south side) 69 Acton Blvd from 5:00pm-8:00pm (Next dates: Jun 17, July 15)\nOakville LGBTQ+ Youth Drop-In runs the last Thursday of the month at the Oakville Youth Centre 177 Cross Ave from 5:00-8:00pm (Next date: Jun 25, July 30)\nIf you are in crisis please contact the ROCK 24 hour Crisis Line at 905-878-9785	\N	\N	905-634-2347	L7R	\N	\N	\N	\N	https://rockonline.ca/
808	rho	roots-in-wellness	Roots in Wellness	428 Aberdeen Avenue\nHamilton, L8P 2S2	\N	I provide individual counselling services for the LGBTQ+ community. I have experience working with individuals with trans issues, and have knowledge regarding the process of obtaining HRT and surgery. I offer a warm and safe environment for individuals to work through their own unique and individual process.	jennifer@rootsinwellness.ca	\N	2265039412	L8P	\N	\N	Jennifer Thomson\nRP, MACP	\N	https://www.rootsinwellness.ca
809	rho	rr-counselling-and-consulting	RR Counselling and Consulting	\N	\N	Service Description:\n*Individual, Couple & Family Counselling for Trans, Queer & Heterosexual Adults, Adolescents & Children\n*Assessments for Readiness for Hormone Therapy & Sex-Reassignment Surgery\n*Gender Consultations for Health Care & Social Service Professionals\n*Professional Development Training Workshops on Transgenderism & Gender Non-Conformity in Children\n*Corporate Consulting & Training for Employers of Transitioning Employees\n	\N	\N	\N	\N	\N	\N	\N	\N	\N
810	rho	ruby-rowan-msw-rsw	Ruby Rowan MSW RSW	Virtual therapy for anyone in Ontario\nToronto, M6H 1V5	\N	My approach to therapy is practical, creative, humorous, and interactive. Engaging in therapy is a vulnerable and courageous step, and I aim to foster a comfortable, collaborative process that is respectful of each individual’s pace. When the tools and skills that were previously helpful are no longer working, I support clients to cultivate new coping skills, and identify potential areas for change and/or acceptance.\nI am a seasoned therapist and mental health clinician who draws on theories of intersectionality, feminism, attachment, cognitive behaviour therapy, and trauma therapy. Being an ally is a core value for me, and I work from an anti-oppression perspective. I identify as queer and non-binary, and I have experience providing supportive counselling and psychotherapy to individuals dealing with issues related to gender and sexuality.	rubyrowanpsychotherapy@gmail.com	Offering virtual therapy sessions Mondays, Tuesdays, and Wednesdays.	n/a	M6H	\N	$180/session	Ruby Lisa Rowan\nMSW RSW	\N	https://www.psychologytoday.com/profile/368084
811	rho	ruth-neustifter-rmft-rp	Ruth Neustifter, RMFT, RP	Guelph, N1G 2W1	\N	Therapy for Individuals & Relationships: Trauma Informed, Queer & Trans Affirming, Kink Aware, Non-Monogamy and Monogamy Positive, Disability Inclusive, Dedicated to Anti-Oppressive Practice that Recognizes Intersectionality\nRuthie is an RMFT and RP in Ontario, who has been practicing since 2005. Sessions are available in-person at their office in Guelph, and online across Ontario. Online session are hosted through a Zoom based webcam software, and office sessions can booked in Ruthie’s office (upstairs) or in an accessible room (wide door, navigable hallway and room) on an accessible floor (power door, concrete ramp to building entry, washroom with power door) near designated accessible parking upon request. (They don’t use the accessible rooms when they aren’t requested, as those rooms are shared and others may need them.)\nRuthie primarily practices from Narrative approach and sees individuals, couples, and intimate relationships of all sizes and types. Some clients appreciate knowing that Ruthie is a non-binary trans person (they/them), active in kink communities, pansexual/bisexual, and non-monogamous. Their areas of focus as a therapist, researcher, and educator include sexual well-being and pleasure for diverse bodies and attractions, affirming gender support, and trauma recovery (including: sexual assault survivors, adult survivors of sexual and non-sexual child abuse, medicalized trauma, intimate partner violence, emotional abuse, the impact of surviving/navigating bigotry, and more). They engage in regular continuing education, including receiving anti-oppression training at least annually. Limited sliding scale spots may be available, sessions are reimbursable by some insurance plans, payment is accepted by cash, etransfer, and credit card. This practice cannot provide emergency or crisis services, nor appointments for diagnosis/assessment/legal purposes. Appointments are required, please contact Ruthie by email or review their website to learn more.	ExploringIntimacy@gmail.com	\N	\N	N1G	\N	\N	Ruth Neustifter\nRegistered Marriage and Family Therapist (Canada), Registered Psychotherapist (Ontario), AAMFT Clinical Fellow and Approved Supervisor	\N	https://www.ExploringIntimacy.com
812	rho	s-l-hunter-speechworks	S.L. Hunter SpeechWorks	5195 Harvester Road\nBurlington, L7L 6E9	\N	We provide voice training and communication services to those individuals who have transitioned or who may be in the process of transitioning and are looking to alter their voice to match their identity. We also offer transgender communication groups for youth and adults.	lsaarenvirta@slhunter.ca	\N	905-637-5522	L7L	\N	\N	Linda Saarenvirta\nSLP	\N	https://slhunterspeechworks.com
813	rho	sacred-path-centre	Sacred Path Centre	616 Bronson Road\nBancroft	\N	The Sacred Path Centre provides non-residential workshops for women and LGBT people throughout the year. Workshops provide opportunities for self discovery and reconnection with nature. The Sacred Path Centre is located in a forested valley on the edge of the York River. In 2010 we are offering, Love & Sex (for LGBT women), Renew Your Relationship (For LGBT couples), Being in Our Bodies (for women survivors), Our True Nature, Finding Our Beauty, Turning Resolutions in Reality, Sex For Survivors and The Creative Spirit. Exploring our spirituality, sexuality and creativity renews our relationship to life.	sacredpathcentre@sympatico.ca	\N	(613) 332-2356	\N	\N	\N	Jody and Melissa Raven and Gordon\n25 years of counselling/therapy experience in urban and rural communities, providing workshops to women & LGBT people for past 5 years	\N	https://sacredpathcentre.com
814	rho	sahara-counselling	Sahara Counselling	10970 Bramalea Road\nBrampton, L6R 0C1	\N	Psychotherapy services provided and tailored to the client and their needs, preferences. Services include but not limited to: Cognitive Behavioural Therapy, Brief Solution Focused Therapy, Mindfulness, Narrative Therapy and Art therapy. I see clients with various problems and if I am not able to help then I make the appropriate referral. I am client centered, compassionate, empathetic, LGBTQ+ friendly and believe everyone should have access to mental health and care.	saharacounselling@outlook.com	\N	416-948-7744	L6R	\N	\N	Fenny Goyal\nMD, MACP, Registered Psychotherapist (Qualifying)	\N	https://www.saharacounselling.com
815	rho	sandy-hill-community-health-centre	Sandy Hill Community Health Centre	221 Nelson Street\nOttawa, K1N 1C7	\N	Good health means more than just treating people when they are sick. Problems like poverty, addiction, and family violence can bring on illness – or keep people from getting well. At Sandy Hill Community Health Centre, we treat illness when it arises. We also work hard to create a healthy community, so that people stay well and get the most out of life, and we believe in: integrity | respect | equity | collaboration | empathy\nSandy Hill CHC provides primary healthcare, health promotion, chronic disease management, additions and mental health services and community development.	\N	\N	613-789-8458	K1N	\N	\N	\N	\N	https://www.shchc.ca
816	rho	sandy-jardine-counselling	Sandy Jardine Counselling	927 King Street East\nCambridge, N3H 3P4	\N	Sometimes life throws us curves and doesn’t work out as we planned. When these times strike, we might feel overwhelmed, anxious or depressed. These times don’t have to break us, but may require us to reach out for help. Counselling can move us forward, through and around the barriers that seem insurmountable.\nCounselling is a way of getting healthy and learning skills to deal with life’s obstacles.\nI provide Individual Counselling, Family Counselling, and Workshops, Seminars, Lectures. Please contact me for more information regarding how my services can be tailored to meet your needs.	sandy.jardine@rogers.com	\N	5199983836	N3H	\N	\N	\N	\N	https://www.sandyjardine.ca
817	rho	sarah-cassel-speech-language-pathologist	Sarah Cassel, speech-language pathologist	84 Ferris Road\nToronto, M4B 1G4	\N	Offering voice modification and gender affirming voice therapy and communication, in a safe and supportive environment. Sessions offered virtually, in office, or in-home in East York.	sarah@casselspeechandlanguage.com	Tuesdays: sessions available Monays-Fridays: inquiries welcome	647-629-7068	M4B	\N	\N	Sarah Cassel\nM.Sc.Ed., Reg. CASLPO	\N	https://casselspeechandlanguage.com
818	rho	saretta-herman-msw-rsw	Saretta Herman, MSW RSW	2261 Bloor Street West\nToronto, M6S 1N8	\N	I provide psychotherapy services to adolescents and adults facing a wide variety of issues including anxiety, depression, relationship issues, life changes and transitions, grief and loss, stress and time management, and pre- and post-partum adjustment (for either parent). Please note, unfortunately my office is not wheelchair accessible at this time.	saretta.rsw@protonmail.com	\N	647-828-5831	M6S	\N	\N	Saretta Herman\nMSW, RSW	\N	https://www.psychologytoday.com/ca/therapists/saretta-herman-toronto-on/386228?sid=1547567576.2236_23303&search=saretta+herman&name=saretta+herman&ref=1&tr=ResultsName
819	rho	sarnia-lambton-rebound-support-for-youth	Sarnia-Lambton Rebound Support for Youth	10 Lorne Crescent\nSarnia, N7S 1H8	\N	Sarnia-Lambton Rebound is a non-profit organization that strives to assist youth aged 7-24 to reach their full potential. We offer several group programs as well an individual support program for youth in Lambton County.\nRebound has many services including Spectrum.\nSpectrum is a positive drop-in space open to all Lesbian, Gay, Bisexual, Transgender, Two-Spirited and Questioning (LGBT2SQ) youth ages 14 to 24 in Sarnia and Lambton County that meets Wednesdays bi-weekly from 4 to 5:30 p.m.	kelly@reboundonline.com	\N	519-344-2841	N7S	\N	\N	\N	\N	https://www.reboundonline.com
820	rho	scarborough-centre-for-healthy-communities	Scarborough Centre for Healthy Communities	629 Markham Road\nToronto, M1H 2A4	\N	SCHC is dedicated to meeting the diverse, holistic health needs of the communities of Scarborough by addressing the physical, mental, social, financial and environmental aspects of their health.\nThrough the promotion of healthy lifestyles and the delivery of a comprehensive range of culturally competent health and social services, we cultivate vital and connected communities.\nWe have 11 sites across Scarborough, with services including primary health care, food bank, child & family programs, housing support, seniors programs, and diabetes education.	ask@schcontario.ca	\N	416-642-9445	M1H	\N	\N	\N	\N	https://www.schcontario.ca
821	rho	scarborough-interprofessional-primary-care-team	Scarborough Interprofessional Primary Care Team	1333 Neilson Road\nToronto, M1B 3C2	\N	The Scarborough IPPC is a new program which provides patients with access to a coordinated team of health care professionals. The goal of our team is to strengthen integration of primary care services to improve the patient experience, and to meet the needs of vulnerable patients with complex healthcare requirements. To receive IPPC services, patients may be referred by their family doctor or nurse practitioner.\nNo family doctor? You can receive primary care from our nurse practitioners by calling 416-847-4165.\nThe IPPC Team includes nurse practitioners, registered nurses, social workers, mental health case workers, harm reduction workers, registered dieticians, foot care nurses, chiropodists, physiotherapy and occupational therapy.\nServices\n– Primary care for children & adults\n– Women’s Health\n– LGBT+ Care, HIV Pre-Exposure Prophylaxis (PrEP) & medical transition care\n– Chronic Disease Management\n– Harm Reduction – clean supplies and support for problematic substance use\n– Nutrition\n– Clinical counseling\n– Cognitive Behavioural Therapy for Insomnia (CBT-i)\n– Foot Care\n– Occupational therapy\n– Physiotherapy\n– Community workshops, groups and presentations\nTo be eligible for our services, the patient or referring provider must reside in Scarborough. To access allied health services, please fax a referral form to 416-410-7072.\n	\N	\N	416 847 4165	M1B	\N	\N	\N	\N	https://www.schcontario.ca/ippc.html
822	rho	scott-duggan-psychology	Scott Duggan Psychology	85 Henry Lane Terrace\nToronto, M5A 4B7	\N	I work mainly with gay, lesbian and bisexual individuals, their families and friends on a variety of issues including coming out, safer sex, relationships, anxiety, depression, sexual prejudice, HIV, and a variety of other issues.	dr.duggan@bell.net	\N	4162094036	M5A	\N	\N	Scott Duggan\nPh.D. C.Psych.	\N	https://www.drduggan.ca
823	rho	seaway-valley-community-health-centre	Seaway Valley Community Health Centre	353 Pitt Street\nCornwall, K6J 3R1	\N	Seaway Valley CHC provides primary health care as well as many programs for health living and health promotion.\nWe also provide a safe space for monthly gatherings for LGBTQ, friends and allies the first Thursday of every month, 5-7pm. We also have a Youth and Young Adult monthly gathering the third Thursday of every month, 5-7pm. The meetings are held at Seaway Valley Community Health Centre, 353 Pitt Street, Cornwall ON. Our gatherings are directed by the participants. We offer education, support – peer and professional, and social activities. Participants are also actively involved in organizing community activities and mobilizing within our larger community to make it a safe place.	clappc@seawayvalleychc.ca	\N	613-930-4892  x153	K6J	\N	\N	\N	\N	https://www.seawayvalleychc.ca
824	rho	seaway-valley-community-health-centre-2	Seaway Valley Community Health Centre	\N	\N	LGBTQ All Ages Group – First Thursday of every month, 5:00 – 7:00 p.m. Allies and family members welcome. Support, education and resources provided in a safe environment. Workshops, guest speakers often invited on topics decided by participants. Find us on Facebook! Search LGBTQ Cornwall SDG to join our group. LGBTQ Youth Group (up to 25) Support, education, activities and fun geared to youth within a safe environment.\nThird Thursday of every month, 5:00 – 7:00 p.m. Find us on Facebook! Search LGBTQ Cornwall SDG to join our group.	hemmericks@seawayvalleychc.ca	\N	6139360306	\N	\N	\N	Stephanie Hemmerick\nMPH	\N	https://www.seawayvalleychc.ca
826	rho	selfcareto	SelfCareTO	Toronto, M5S 2J4	\N	SelfCareTO is a virtual wellness clinic offering services to take care of your whole self well. Whether it’s increasing your current skills or a place of support to help you with your physical, mental, emotional and/or spiritual journey.\nSelfCareTO aims to create a modern approach with ensuring inclusivity and equity. We are members and allies of the BIPOC & LGBTQIA+ community. We work from an anti-racist, trauma informed, cultural adapted lens.	chantee@selfcareto.com	Monday 9:00- 5:00pm Tuesday 11:00am - 7:30pm	647-696-5924	M5S	\N	140\nSliding scale range - $/Hour Minimum: 85 Maximum: 140	Jordyn Banks\nRP (Qualifying)	\N	https://www.selfcareto.com
827	rho	serge-keravel-psychotherapy	Serge Keravel Psychotherapy	Ottawa	\N	Individual and couple psychotherapy.	sergekeravel@videotron.ca	\N	613.235.8752	\N	\N	\N	Serge Keravel\nM.Ps. Psychological Associate	\N	\N
828	rho	seventh-generation-midwives-of-toronto	Seventh Generation Midwives of Toronto	525 Dundas Street East\nToronto, M5A 2B6	\N	Midwifery services in downtown Toronto	emilystewartwilson@gmail.com	\N	4165307468	M5A	\N	\N	Emily Stewart-Wilson\nRegistered Midwife	\N	https://www.sgmt.ca
829	rho	sex-therapy-service	Sex Therapy Service	184 Barrie Street\nKingston, K7L 3K1	\N	Provide letters of referral for HRT and surgery for those who are transitioning; therapy for sex and gender diverse individuals who have sexual/relationship concerns	psycclin@queensu.ca	\N	613 533 6021	K7L	\N	\N	Caroline Pukall\nPhD in Clinical Psychology, Registered clinical psychologist	\N	\N
830	rho	sexual-assault-support-centre	Sexual Assault Support Centre	Kitchener	\N	Sexual Assault Support Centre of Waterloo Region (SASC) is a feminist, non-profit organization. We work to end sexual violence against women and children and to support female survivors and their families in Waterloo Region.\nOur services include:\n24 hour Crisis & Support Line: 519.741.8633 providing immediate support, information and emergency accompaniments\nCounselling: Individual & Group; empowerment-based counselling for women 16 and older, as well as short-term counselling for family and friends\nAdvocacy & Accompaniment: accompany you to the hospital, court or police visits, assist with telephone calls, letter writing or meetings as required	info@sascwr.org	\N	519 571 0121	\N	\N	\N	\N	\N	https://www.sascwr.org
831	rho	sexual-health-clinic	Sexual Health Clinic	101 17th Street East\nOwen Sound, N4K 0A5	\N	The overall goal of the Sexual Health Program is to promote healthy sexuality through education, clinics and community support. Education and counselling are provided to increase awareness and knowledge about personal responsibility, healthy relationships, abstinence, safer sex, communication and sexual orientation. The program also provides services related to birth control, unplanned pregnancies, and sexually transmitted diseases, including AIDS and HIV.\nAll sexual health clinics are confidential and contraception is offered at low cost to the client.	publichealth@publichealthgreybruce.on.ca	\N	519-376-9420 x1256	N4K	\N	\N	\N	\N	https://www.publichealthgreybruce.on.ca
832	rho	sexual-health-options-resources-and-education-centre	Sexual Health Options, Resources and Education Centre	235 King Street East\nKitchener, N2G 4N5	\N	SHORE Centre promotes choice through accurate sexual health education and confidential pregnancy options support, including medical abortion with the abortion pill. Our programs and services are pro-choice, sex positive, inclusive and accessible. We provide free condoms, dental dams, lube, pregnancy tests and pre-natal vitamins.	Info@shorecentre.ca	\N	5197439360	N2G	\N	\N	Lyndsey Butcher\nMSW	\N	https://www.shorecentre.ca
833	rho	sexual-violence-support-line-24-hour	Sexual Violence Support Line (24-hour)	75 MacNab Street South\nHamilton, L8P 3C1	\N	No emails please. 24-hour Telephone Support Line for callers age 16 and over who experienced sexual violence at any time in their life and their support persons: support, information, referrals; accompaniment for women and Trans women of all sexual orientations to the hospital and/or police station. Tel. 905-525-4162.	sacha@sacha.ca	\N	905-525-4162	L8P	\N	\N	\N	\N	https://www.sacha.ca
834	rho	shannon-collins-psychotherapy	Shannon Collins Psychotherapy	Kingston	\N	Seeking support from a therapist takes a lot of courage. I provide non-judgemental, individual counselling for people who want support with issues around relationships, family/intimate partner violence, grieving and bereavement, LGBTTIQQ issues, coming out and/or questioning your sexuality and/or gender, coping with stress, and healing from trauma. I work within a feminist, anti-oppressive framework and use an eclectic approach based on what resonates with my clients. My training includes an attachment focus with narrative, cognitive behavioural, mindfulness and trauma therapy.	therapy.collins@gmail.com	\N	6135491451	\N	\N	\N	Shannon Collins\nB.A. Psych, B.Ed, MSW	\N	https://shannoncollins1.wordpress.com
835	rho	sharron-carson-registered-psychotherapist	Sharron Carson Registered Psychotherapist	81 Toronto St\nBarrie , L4N 1V1	\N	Individual and couple counselling for ages 11 and older.\nMental health, addiction, relationships, self esteem, gender identity and transition.\nSignificant experience supporting LGBTQ community.\nAlways confidential and non judgmental.\nSAFE AND INCLUSIVE SPACE.\nVIDEO AND PHONE SESSIONS OFFERED.  AVAILABLE TO THOSE THROUGHOUT ONTARIO\n\n	scarsonrp@gmail.com	Monday to Friday - 6 to 10 p.m. ( daytime hours available if unable to do evenings) Sat and Sunday 10 a.m. to 9 p.m.	705-970-7494	L4N	\N	\N	Sharron Carson RP\nRP (Registered Psychotherapist)	\N	https://www.mendingmindscounselling.com
836	rho	shaun-castor-rmt	Shaun Castor, RMT	Toronto, M4C 1J5	\N	Massage Therapy services provided at dance studios associated with madetomove.ca and in-home (mobile).\nAlso available at Satori Health & Wellness at Eglinton & Avenue.	castorshaun@gmail.com	Tuesday - Saturday 10am-5pm	416-817-2682	M4C	\N	$110/hr. See madetomove.ca for full price list.	Shaun Castor\nRegistered Massage Therapist	\N	https://www.madetomove.ca
837	rho	shawn-meirovici-naturopathic-doctor	Shawn Meirovici Naturopathic Doctor	225 Duncan Mill Road\nToronto, M3B3K9	\N	Naturopathic Doctor in Toronto with a focus in pain management, neurological disease, cancer, pediatrics and cannabis education. Services include: Acupuncture, Cupping, Laser Therapy, Intravenous Therapy, Nutrition, Diet, Food Sensitivity Testing, Hormone Replacement and many more functional tests.\nI have worked closely with members of the 2SLGBTQ community for several years. Natural strategies to optimize mental health, disease prevention, symptom management, and minimizing side effects of medications. I spent a 3-month externship at the Sherbourne health center working exclusively with HIV positive patients working to improve quality of life through the use of complimentary medicines and therapies.	Shawn.naturopath@gmail.com	Mon-Fri 10am-4pm Sat 10am-3pm	416-490-8243	M3B	\N	$50-$200	Dr. Shawn Meirovici N.D.\nN.D.	\N	https://www.doctorshawn.ca/
846	rho	six-degrees-health-acupuncture-and-community-healing	Six Degrees Health – Acupuncture and Community Healing	204 Spadina Avenue\nToronto, M5T 2C2	\N	Community Health with services including:\nAcupuncture and Chinese Medicine\nBody work, massage, shiatsu\nCounselling and couching\nClasses/Workshops include:\nBrown Girls Yoga\nMindfulness Based Stress Reduction\nCaring For The Caregiver: Yoga for Moms of ASD Kids\nKung Fu	info@sixdegreeshealth.ca	\N	416-866-8484	M5T	\N	\N	\N	\N	https://sixdegreeshealth.ca/
838	rho	sheldon-hill-therapy	Sheldon Hill Therapy	521 Colborne Street\nLondon, N6B 2B7	\N	At Rising Insight Counselling and Psychotherapy, we believe that everyone has the ability to become the person that they want to be. As registered mental health professionals, we work with individuals and couples to create a space for the development of insight which allows you to be the person you want to be. We work in partnership with you, the expert on your life, and we walk along with you to help you better your experience.\nWe are committed to providing an experience where you feel valued, safe and respected which we believe is necessary for you to benefit from counselling and psychotherapy. We pride ourselves on our dedication to anti-oppressive practice and being LGBTQIA2S+, neurodivergent, and polyamory inclusive; we work to create a space that is safe and confirming to the intersections of your identity.\nTo give you the best services that we can, we have clinicians trained in a number of modalities including Acceptance and Commitment Therapy (ACT), Cognitive Behaviour Therapy (CBT), Dialectical Behaviour Therapy (CBT), narrative therapy, neurofeedback and Gottman’s Couple’s Counselling. We are committed to empowering our clinicians to develop skills to support a diverse range of concerns and needs. If your concern is outside the scope of our practice, we can support you in finding a clinician who can help you.	sheldon.hill@risinginsightcounselling.com	Contact for appointment booking.	226-702-8473	N6B	\N	$130+	Sheldon Hill\nMA, RP, CCC	\N	https://www.risinginsightcounselling.com
839	rho	sherbourne-health	Sherbourne Health	333 Sherbourne Street\nToronto, M5A 2S5	\N	Sherbourne Health provides a wide range of health and wellness services for LGBT2SQ communities including specialized programs for trans and non-binary people, families and youth.	info@sherbourne.on.ca	\N	416 -324-4100	M5A	\N	\N	\N	\N	https://www.sherbourne.on.ca
840	rho	shore-centre	SHORE Centre	235 King St. E.\nSuite 130\nKitchener, N2G 4N5	\N	SHORE Centre offers a variety of emotional support, outreach, and medical appointments to meet your reproductive health needs.\nServices are typically offered in English, and free interpretation services are available by request.\nMedical Services (covered by OHIP)\n• Medication Abortion (available by telemedicine)\n• Birth Control Consultation (available by telemedicine)\n• This includes the pill, patch, ring, the shot (Depo Provera) intrauterine device (IUD), implant (Nexplanon), and referral for tubal ligation or vasectomy\n• IUD Insertion and Removal (available in-person)\n• Nexplanon (implant) Insertion and Removal (available in-person)\nTo request an appointment please visit: https://clinic.shorecentre.ca/contact-us\nCounselling Services (FREE)\n• Pregnancy Options Support\n• Abortion Options Support\n• Support After an Abortion\n• Adoption Options Support\n• Support After Placing a Child for Adoption\n• Support During Pregnancy\n• Support After Giving Birth\nAll counselling appointments are being offered via telemedicine – phone or video appointments available.\nOutreach Services for Pregnant People\n• Empowering Pregnancy Support Program\nAlso Available by Appointment (FREE)\n• Pregnancy Test Pick Up\n• Prenatal Vitamin Pick Up\n• Condom, Dam and Lube Pick Up\nTo request an appointment please visit: https://shore.inputhealth.com/ebooking\nOur Kitchener office has a gender inclusive, single stall bathroom, and is accessible.	general@shorecentre.ca	Phones are answered Monday - Friday: 9: a.m. - 4 p.m. Services on-site in Kitchener: Monday, Tuesday, Wednesday Services on-site in Guelph: Thursday Virtual Appointments: Monday, Tuesday, Wednesday, Thursday Office closed daily between 12 and 1 p.m. for lunch, and on all weekends and holidays.	519-743-9360	N2G	true	\N	\N	\N	https://clinic.shorecentre.ca
841	rho	shoshana-pollack-psychotherapy	Shoshana Pollack Psychotherapy	Toronto, M6G 1Y4	\N	I have been working in the counseling field for 22 years. My counseling experience includes working with individuals, groups and couples on a variety of issues including childhood trauma, abuse in intimate relationships, eating issues, self-harm, drug and alcohol use, sexual orientation, relationship issues, loss and grief, self-esteem, anger management, and dealing with oppression. I am a registered clinical social worker (MSW, RSW) and a professor of social work (Ph.D).\nI work from an anti-oppression, feminist, and client-centred perspective. This means that:\n-I respect the goals, perspectives and pace that you bring to therapy.\n-I work to understand you and your experiences in the context of your relationships (past and present) and the society in which we live.\n-specific approaches may be drawn from psychodynamic, narrative, cognitive-behavioural, and mindfulness therapies.\nI have a bright, comfortable office in the Bloor and Ossington area and have day and evening appointments available. Many insurance companies cover my services.	shoshana.pollack@rogers.com	\N	416-534-3519	M6G	\N	\N	Shoshana Pollack\nMSW, RSW, PhD	\N	\N
842	rho	shuter-st-pharmacy	Shuter St Pharmacy	290 Shuter St\nToronto, M5A 1W7	\N	Shuter St Pharmacy cares about the well being of each individual who walks through our doors. We have dedicated so much time to ensuring we stock the widest range of medical products, offer the highest quality health services and retain the best staff possible. As a middleman between your doctor’s prescriptions and your own well being, we strive to provide personalized and professional attention, as well as medication management protocols that inspires individuals to seek out the medication and advise they need in order to get and feel better.\nTrust our pharmacy to provide you with the care you deserve.\nWe pride ourselves on establishing meaningful and therapeutic relationships and strive to make you feel welcome and supported.	shuterstpharmacy@gmail.com	Mondays to Fridays 9 am to 5 pm Saturdays 10am to 2 pm Sundays and Holidays closed	16473522252	M5A	\N	\N	Kassandra Dizon\nRegistered Pharmacist	\N	https://www.shuterstpharmacy.ca
843	rho	silm-centre-for-mental-health	Silm Centre for Mental Health	18 Wynford Drive\nToronto, M3C 3S2	\N	We offer psychotherapy and assessment services for adolescents and adults. We ensure that both counselling and assessment services are recovery-oriented, trauma-informed, and culturally safe and competent. Our services are generally covered by extended health benefits and we offer a sliding scale.	admin@silmmentalhealth.com	\N	416-384-1111	M3C	\N	\N	Taslim Alani-Verjee\nPsychologist (C. Psych)	\N	https://silmmentalhealth.com
844	rho	silvana-hernando-psychotherapy	Silvana Hernando Psychotherapy	Toronto, M6G 1L5	\N	CURRENTLY ON LEAVE from seeing clients – Working for Rainbow Health Ontario as Clinical Educator for Trans Health\nSTILL PROVIDING Clinical Supervision and Consultation to providers working with BIPOC QT clients.	silvanabazet@hushmail.com	\N	\N	M6G	\N	\N	Silvana Bazet\nRegistered Psychotherapist	\N	https://torontopsychotherapy.wordpress.com
845	rho	sioux-lookout-regional-physicians-services	Sioux Lookout Regional Physicians Services	Sioux Lookout, P8T 1K2	\N	Rural family doc with special interests in Indigenous Health, Trans Health, and Mental Health & Addictions.	lindsay.hancock@gmail.com	\N	807-737-5166	P8T	\N	\N	Lindsay Hancock\nMD	\N	\N
864	rho	st-jacobs-midwives	St Jacobs Midwives	9 Parkside Dr.\nSt Jacobs, N0B 2N0	\N	Midwifery Care.\nRegistered Midwives (RM’s) provide primary care to clients during pregnancy, labour, and birth.\nWe continue to provide midwifery care during the first six weeks after the baby is born.	birth@stjacobsmidwives.on.ca	M-Th 9-4:30	519-664-2542	N0B	\N	\N	\N	\N	https://www.stjacobsmidwives.on.ca/
847	rho	sly-sarkisova-counselling	Sly Sarkisova Counselling	720 Bathurst Street\nToronto, J4Y 0K7	\N	ABOUT\nProviding counselling and therapy to LGBTTQ2SI communities and beyond. Specializing in trauma informed care, issues of mental health and substance misuse.\nDESCRIPTION\nI am a queer and trans identified counsellor who has been working in the field of mental health and addictions counselling, therapy and support for the past 13 years.\nMy social work practice is clinical in nature, providing therapy to individuals that centers and affirms unique experiences and strengths. I work to help folks feel safe to discuss the issues and barriers they face and establish goals for change.\nMy counselling training and practice is wholly derived from my ability to listen to the individual as the expert of their experience. I believe the most powerful healing and change come from affirmative relationships that acknowledge the power of an individual to tell and understand their own story. I strive to provide a non-judgmental, safe and reflexive space that centers your unique experience, while also identifying the impacts of systemic and individual traumas and stresses on your ability to cope and function. We will co-create a space wherein you feel safe to explore issues of concern to you, identify goals for increasing your ability to cope with distress, function better, and begin to externalize shame and stigma collected in the body and spirit.\nThe approach that I use will be specifically catered to your experience and needs, and may be seen to infuse CBT, Narrative, Solution Focussed and Harm Reduction techniques within a larger model of anti-oppressive, trauma informed, holistic therapy.\nAREAS OF SPECIALIZATION AND INTEREST:\nConcurrent Disorders (co-occurring mental health and addictions issues)\nSubstance Misuse\nSerious and persistent mental health concerns including\nSchizophrenia, Bi-Polar, Major Depression, Social Anxiety &\nAgoraphobia, Complex Post Traumatic Stress Disorder, OCD\nDepression and Anxiety\nTrauma therapy\nIncreasing coping strategies\nManaging anger\nRelationships\nNavigating stigma associated with queer and trans identities\nAccessing trans positive health care\nDiverse gender experiences and presentations\nSex positive, sex work positive, kink positive, poly positive	slysarkisova@gmail.com	\N	0	J4Y	\N	\N	Sly Sarkisova\nMSW, OASW, BA, BSW	\N	https://www.slysarkisovacounselling.com
848	rho	smith-falls-community-health-centre	Smith Falls Community Health Centre	2 Gould Street\nSmiths Falls, K7A 2S5	\N	Our two CHCs offer a wide variety of programs and services designed to meet the needs of the communities we serve. Our programs and services are provided by a variety of health professionals who work together to provide access in response to client and community needs.\nThe Primary Health Care Team consists of:\nWorking together, our team looks at the factors in our clients lives that impact their health and well-being: income, housing, social supports, employment, neighbourhood and access to healthy, affordable foods.	\N	\N	(613) 283-1952	K7A	\N	\N	\N	\N	https://www.rideauchs.ca/
849	rho	snapclarity	Snapclarity	7 Bayview Rd\nOttawa, K1Y 2C5	\N	Snapclarity introduces a solution that provides personalized mental health care. The system today is confusing and full of disconnected parts. Through technology, Snapclarity delivers an all-in-one experience that is frictionless for our members, providers and employers. We provide a mental health checkup for early screening and care management to share with your care team. By offering a virtual model, our intelligent technology connects you to the right therapists, while giving you the ability to get better on your terms. We create an experience for you and your family, so you can focus on your journey to wellness.	info@snapclarity.com	\N	833-444-7627	K1Y	\N	\N	\N	\N	https://www.snapclarity.com
850	rho	social-inc-mohawk-college	Social Inc. – Mohawk College	135 Fennell Avenue West\nHamilton, L9C 7V7	\N	Social Inc. is a place where human rights are respected. We celebrate social inclusion and work toward erasing discrimination. This process includes identifying and confronting oppression. We do this by supporting students and staff with a physical positive space located in G112 and delivering a message of harmony outside of our safe space.\nSocial Inc. is open from Monday to Friday, 8:30am-4:30pm with minor interruptions when events are being held. The room is fully accessible. Registered student and community groups can also book the room during day, evening and weekend hours. We are closed during the month’s of July and August and have modified hours during all reading weeks.\nThe space is staffed with Peer Wellness Workers that are there to support you. The coordinator of Social Inc. is Marco Felvus and can be reached via email: socialinc@mohawkcollege.ca. Please note that services are limited to students enrolled at and of the Mohawk College campuses or satellites as well as staff. Many events are open to community and some services are open to alumni. Please direct questions to Centre Coordinator, Marco Felvus.	marco.felvus@mohawkcollege.ca	\N	905-575-1212 X3812	L9C	\N	\N	\N	\N	https://www.mohawkcollege.ca/studentservices/diversity/location.html
851	rho	soft-soles-advanced-diabetic-foot-care	Soft Soles Advanced Diabetic Foot Care	2410 Old Second Line Road\nDunrobin, K0A1T0	\N	Nursing foot care in the comfort of your home, in the clinic or in facility.\nThe idea of empowering people is foundational to nursing. It’s a thought process and skill set that goes beyond the information available and the science of nursing, to the art of healing.\nMeet a Soft Soles nurse, share some laughter, gain some information, and invest in your health.	footcare@softsoles.ca	7 days a week 9am - 7pm depending on Nurses availability	6136210012	K0A	true	depending on clinic $45.00/50.00 home care $65.00	Michelle De Grandmont\nRPN Nurse Educator Adnvaced foot care nurse	\N	https://www.softsoles.ca
852	rho	somerset-west-community-health-centre	Somerset West Community Health Centre	55 Eccles Street\nOttawa, K1R 6S3	\N	Somerset West Community Health Centre (SWCHC) is a non-profit, community-governed organization that provides primary health care, health promotion and community development services, using interdisciplinary teams of health providers. These teams include physicians, nurse practitioners, dietitians, health promoters, counsellors and others.\nSWCHC is well known for its excellent community health centre model and its professional health services team, but it has also become a leader in offering a wide range of social services, community-building activities and advocacy programs.	info@swchc.on.ca	\N	613-238-8210	K1R	\N	\N	\N	\N	https://www.swchc.on.ca
853	rho	south-east-grey-community-health-centre	South East Grey Community Health Centre	\N	\N	We provide health and wellness services to residents in southeast Grey County. LGBTQ+ Connection runs once per month. See our website for full details on services, groups, and events. www.segchc.ca, or call us at 519-986-2222.	info@segchc.ca	\N	519-986-2222	\N	\N	\N	Crystal Ferguson\nHealth Promoter	\N	https://www.segchc.ca
854	rho	south-east-grey-community-health-centre-dundalk-sites	South East Grey Community Haealth Centre – Dundalk Sites	90 Artemesia Street & 53 Main Street.\nDundalk, N0C 1B0	\N	We provide health and wellness services to residents in southeast Grey County. LGBTQ2S+ Connection runs once per month. See our website for full details on services, groups, and events. www.segchc.ca, or call us at 519-986-2222.	crystal.ferguson@segchc.ca	\N	5199862222	N0C	53 Main Street West, Dundalk, Ontario, Canada5199862222Directions	\N	N0C1H0	\N	https://www.segchc.ca
855	rho	south-riverdale-chc	South Riverdale CHC	955 Queen Street East\nToronto, M4M 3P3	\N	I am a Nurse Practitioner offering Primary Care for Trans client including hormonal treatment, referral for surgery and advocacy.	\N	\N	(416) 461-2493	M4M	\N	\N	Emmet O'reilly\nRN(EC)	\N	\N
884	rho	sumac-creek-health-centre	Sumac Creek Health Centre	73 Regent Park Boulevard\nToronto, M5A 2B7	\N	LGBTQ positive primary health care, trans care including gender affirming treatments and surgical referrals	gordonki@smh.ca	\N	4168643022	M5A	\N	\N	Kim  Gordon\nPrimary Health Care Nurse Practitioner	\N	\N
856	rho	south-riverdale-community-health-centre	South Riverdale Community Health Centre	\N	\N	The MATCH (Midwifery and Toronto Community Health) Program provides complete prenatal, labour, birth and postpartum care with a team of midwives. Midwives are experts in caring for pregnant people and their newborns. The MATCH team can attend your labour and birth at Michael Garron Hospital, The Toronto Birth Centre, or at home. Midwives provide 24 hour on-call services to MATCH clients during pregnancy and for the first 6 weeks postpartum. Home visits are scheduled to provide clinical care for you and your baby in the first week postpartum.\nMATCH Midwives also provide well-gynecological care (Pap tests), STI screening, pregnancy testing (urine or blood tests) and counselling related to pregnancy options at the Health Centre. If you have a valid prescription for transition-related testosterone injections, you can see the midwives for your regular injections or for self-injection teaching.	\N	\N	4164612493	\N	\N	\N	Jenna Robertson Bly\nRM	\N	https://srchc.com/match
857	rho	south-riverdale-community-health-centre-2	South Riverdale Community Health Centre	955 Queen Street East\nToronto, M4M 3P3	\N	Full spectrum pregnancy, birth and postpartum care. Access to planned hospital (Michael Garron), home or birth centre births. Home visits. Well gynecological care (Paps & STI screening). Team-based care with Dr. Lisa Bell managing hormone therapy for trans clients.	match@srchc.com	\N	(416) 461-2493	M4M	\N	\N	RM	\N	https://www.srchc.ca
858	rho	south-riverdale-community-health-centre-3	South Riverdale Community Health Centre	955 Queen Street East\nToronto, M4M 3P3	\N	The MATCH (Midwifery and Toronto Community Health) Program provides complete prenatal, labour, birth and postpartum care with a team midwives. Midwives are experts in caring for pregnant people and their newborns. The MATCH Team can attend your labour and birth at Michael Garron Hospital, The Toronto Birth Centre, or at home. Midwives provide 24h on-call services to MATCH clients during pregnancy and for the first 6 weeks postpartum with home visits to provide clinical care for you and your baby in the first week postpartum. Midwives also provide well-gynecological care (Pap tests), STI screening, pregnancy testing (urine or blood tests) and counselling related to pregnancy options at the Centre. The midwives at MATCH work closely with Dr. Lisa Bell, who provides transition-related hormone therapy for trans clients. If you have a valid prescription for transition-related testosterone injections, you can see the midwives for your regular injections or for self-injection teaching. LGBTQI2S+ clients can access preconception, pregnancy, labour, birth and postpartum care from a multidisciplinary team in a multi-use clinic, which protects your anonymity in the waiting room. We offer appointments at South Riverdale Community Health Centre most days and Thursday mornings at Regent Park Community Health Centre.\nCall our clinic at (416) 461-2493 for more information and booking appointments.	jbly@srchc.com	\N	(416) 461-2493	M4M	\N	\N	Tiffany Fung	\N	https://www.srchc.ca
859	rho	spectrum-doula-collective	Spectrum Doula Collective	Toronto	\N	Spectrum Doula Collective is committed to providing compassionate and professional care to families planning on growing in traditional and non-traditional ways (e.g. adoption, IVF, surrogacy, single parents by choice, and LGBTQ-identified). We cover the entire spectrum of childbearing including fertility, pregnancy loss, birth, termination and postpartum support. Spectrum Doula Collective was created to fill a gap in the current birth community: unprecedented care and support to all families, no matter their structure. Spectrum provides unique, individualized care to the full spectrum of clients. We hope that you join our spectrum!	hello@spectrumdoulacollective.com	\N	\N	\N	\N	\N	MA, CD (BFW), CBE	\N	https://www.spectrumdoulacollective.com
860	rho	spectrum-doula-services	Spectrum Doula Services	Stratford, N5A 7E3	\N	Spectrum Doula Services is proudly queer-owned and makes every effort to create safe and accessible spaces for all. We provide continuous care throughout your reproductive journey, supporting individuals and families through pregnancy, labour & birth, postpartum, loss, adoption, termination, surrogacy and all other related experiences.\n	spectrum.doula@gmail.com	Hours may vary, inquiry responses can be expected within 48 hours.	(519) 703-2774	N5A	\N	Fees vary based on support needed. Contact us for a free consultation!	Katie Nelson\nFull Spectrum Doula	\N	https://www.spectrumdoula.com
861	rho	spectrum-waterloo-regions-rainbow-community-space	SPECTRUM – Waterloo Region’s Rainbow Community Space	283 Duke Street West\nUnit 210\nKitchener, N2H 5C2	\N	The Purposes of SPECTRUM are:	info@ourspectrum.com	\N	\N	N2H	\N	\N	\N	\N	https://ourspectrum.com/
862	rho	spencer-n-psychotherapy	Spencer ‘N’ Psychotherapy	1235 Bay Street\nSuite 521\nToronto, M5R 3K4	\N	You’ve spent years hiding your emotional pain away from yourself, struggling with life’s challenges, and perhaps experiencing a sense of “stuckness” in your life. As someone who has been on my own path to healing, I recognize the courage and strength it takes to reach to someone for help.\nI meet you where you are – another human being in the room. You can expect to find a warm, calm space with empathetic listening. A compassionate space for collaboratively exploring your healing. Psychotherapy offers the chance for pinpointing the emotional pain that we’ve so effectively hidden away from ourselves. Allow me to accompany you with empathy and compassion as you overcome “stuckness” in your life.\nI have experience in assisting with: anger, depression, anxiety, insomnia, relationship issues, school challenges and other life’s struggles. Although there are no guarantees in therapy, clients can expect to develop stronger self-awareness of the underlying hurt, learn to recognize and validate pain as it arises and learn skills for comforting and soothing the self. I want to help you achieve fullness of life, purpose and meaning. I welcome you to check out my website for more information.	info@spencernpsychotherapy.com	\N	(647) 800-1654	M5R	\N	\N	Spencer Nageleisen\nB.Sc., M.A., RP (Qualifying)	\N	https://spencernpsychotherapy.com
863	rho	sprint-senior-care	SPRINT Senior Care	140 Merton Street\nToronto, M4S 1A1	\N	We have develop an innovative peer support program for LGBT caregivers, matching volunteers with lived experience with caregivers who may face barriers accessing services due to their sexual orientation. Volunteers will undergo extensive training and will build capacity around leadership and community engagement, while program participants will be supported and empowered in their caregiving roles in a safe, welcoming environment that meets their individual needs. SPRINT Senior Care will facilitate a combination of formal and informal peer support, incorporating opportunities for education and resource sharing; as well as enabling organic relationship building between the volunteers and participants who can connect in a way that works best for them (in-person, phone, video and/or online chat). In order to achieve project sustainability, a toolkit will be created and shared with other senior-serving organizations seeking to deliver a similar program. This project will take place in Toronto and is facilitated in English. If you are interested please contact The Community Program Lead at 416-481-0669 Ext. 295, Priynka.patil@sprintseniorcare.org	Priynka.patil@sprintseniorcare.org	\N	416-481-0669 x295	M4S	\N	\N	Priynka Patil	\N	\N
865	rho	st-michaels-family-health-team	St. Michael’s Family Health Team	61 Queen Street East\nToronto, M5C 2T2	\N	As a patient in our academic Family Health Team, you will receive excellent care that reflects the values and mission of St. Michael’s Hospital. Your care will be delivered by our skilled interprofessional team and will be centered on your needs. The Department of Family and Community Medicine is dedicated to improving care both in and out of the clinic through quality improvement and research programs. As part of our affiliation with the University of Toronto, we are a training site for students from medicine, chiropractic care, psychology, nursing, dietetics and pharmacy.\nAs a patient of the St. Michael’s Hospital Academic Family Health Team, you are provided with more than a doctor. You also gain access to a variety of services including:	\N	\N	416-867-7426 or 416-867-7428	M5C	\N	\N	\N	\N	https://www.stmichaelshospital.com/programs/familypractice/
866	rho	st-michaels-hospital-academic-family-health-team	St. Michael’s Hospital Academic Family Health Team	Toronto	\N	St. Michael’s Academic Family Health Team provides care to all patients, including those who identify as trans*, gender non-binary and gender non-conforming. We strive to provide expedited access to primary health care for you and to link you with a trans* sensitive provider. You can directly contact Pegi Kohut at 416 867 7460 extension 8340 and self-identify your desire for trans*sensitive primary health care. Our goal is to decrease barriers to accessing care related to social, medical and surgical gender transition, all within the context of safe and thorough primary health care.	\N	\N	416 864 3076	\N	\N	\N	Sue Hranilovic\nNP-PHC, MN	\N	https://www.stmichaelshospital.com/programs/familypractice/
867	rho	st-michaels-hospital-otolaryngology-head-and-neck-surgery-ear-nose-throat-surgery	St. Michael’s Hospital Otolaryngology-Head and Neck Surgery (Ear, Nose, & Throat Surgery)	30 Bond Street\n8-163 CC North\nToronto, M5B 1W8	\N	I offer voice and voice box evaluation using high definition laryngoscopic equipment including video stroboscopy in clinic, transgender voice therapy with highly skilled speech pathologists, and surgical treatment options including vocal fold surgeries for various voice issues, as well as pitch alternating surgeries and laryngeal framework surgeries to facilitate transition.	\N	\N	416-864-6039	M5B	\N	\N	R. Jun Lin\nMD, FRCSC, MSc	\N	https://www.otolaryngology.utoronto.ca/content/jun-lin
868	rho	stacey-love-jolicoeur	Stacey Love-Jolicoeur	362 Grills Road\nBelleville, K8N 4Z5	\N	Independent educator/support worker for the LGBTQ community. I provide workshops and presentations on Creating LGBT Cultural Competency, I also provide peer to peer re-integration counseling for trans identified offenders within the Canadian Prison system.\nMy presentations on LGBT Cultural Competency is provide to businesses, organization, medical care facilities and employment agencies and many more community stakeholders and correctional facilities across Ontario.	staceyjenniferlove@gmail.com	\N	705-313-5124	K8N	\N	\N	Stacey Love-Jolicoeur\nIndependent Educator/Support Worker, Coodinator for TRANSforum Group Belleville/Quinte.	\N	https://www.facebook.com/StaceyLoveJolicoeur
869	rho	star-wellness	Star Wellness	392 Edward Street South\nPrescott, K0E 1T0	\N	We have specialized in Microscopic Electrolysis Hair Removal since 2008. We are experienced in gender surgery preparation. We cater to Ottawa, Kemtpville, Brockville, Kingston, Cornwall & Surrounding Areas.	Christa@StarWellness.ca	\N	613-925-1777	K0E	\N	\N	Christa Johnson\nCertified Electrologist	\N	http://www.StarWellness.ca
870	rho	stefan-andrejicka-medicine-profession-corporation	Stefan Andrejicka Medicine Profession Corporation	692 Euclid Avenue\nToronto, M6G 2T9	\N	Psychodynamic Psychotherapy.	stefan5585@rogers.com	\N	519-661-9675	M6G	\N	\N	Stefan Andrejicka\nMedical Professional Psychotherapist, Guest Toronto Psychoanalytic Society, Infant-Parent Psychotherapist	\N	\N
871	rho	stefanie-gorendar-psychotherapist-performance-life-coach	Stefanie Gorendar – Psychotherapist & Performance Life Coach	80 Centre Street\nVaughan, L4J 1E9	\N	This  practice provides a safe and comfortable environment to explore common mental health concerns such as, anxiety, depression, life transitions, stress, coping, relationships and professional development and self-esteem enhancement. Stefanie has experience working with the LGBTQ community on issues associated with issues such as depression, anxiety, life transitions, familial interactions, stress and coping.	stefaniegorendar@gmail.com	\N	4169088590	L4J	\N	\N	Stefanie Gorendar\nB.A. Spec. Hons, MA, ECPC. CAPT	\N	https://www.paramountlifecoaching.com
872	rho	steff-armstrong-rsw	Steff Armstrong RSW	1983 Ambassador Dr.\nWindsor, N9G 3R5	I can provide secondary assessments for transition-related bottom surgeries	I am queer and trans* social worker in private practice. I mostly work with individuals – primarily youth or adults. I have experience working in the HIV sector.\nI am continuously working on my education not only to improve my practice but to become a better activist and ally.\nI am currently an MSW student being supervised by Gisele Harrison and am offering both in person (Covid-19 safe) and virtual counselling.\n\n	steff.armstrong@gmail.com	Monday 4:30-8pm, Tuesday 9am-5pm, Thursday 9am-12:30pm Flexible Hourse	2263456979	N9G	\N	70\nSliding scale range - $/Hour Minimum: 0 Maximum: 70	Steff Armstrong\nBA (Sexuality and Music), BSW, MSW (Candidate), RSW	\N	https://fb.me/SteffArmstrongRSW
873	rho	step-stone-psychology	Step Stone Psychology	1033 Bay Street\nSuite 221\nToronto, M5S 3A3	\N	Our practice is a downtown Toronto-based psychological service that provides LGBTQ-positive individual and group-based counselling, treatment, and assessment services to children, adolescents, adults, couples, and families.\nWorking from an approach that honours your own unique context, perspectives, and abilities, we collaborate with you towards the identification, exploration, and achievement of goals for your well-being and future. In cases where clinical issues are present, we utilize our experience and expertise to assess, identify, and provide clear feedback and formulations of issues to inform your understanding of yourself and your needs, and to develop comprehensive counselling or clinical treatment plans.\nWe are committed to providing comprehensive services that reach beyond the therapy or assessment room, providing as little or as much assistance and advocacy as your unique needs and circumstances require. In other words, you are not alone. We will walk alongside you, assisting you to be an agentic partner in navigating the challenges, relationships, and systems towards the achievement of your goals.\nWe can work in collaboration with your existing service providers, circle of care, and community supports (e.g., medical/psychiatry, school/educational settings, employers, OHIP, Workplace Safety and Insurance Board, private insurance providers, Children’s Aid Services, legal representatives, justice/police services, etc.) towards the facilitation of your comprehensive care and goals.\nKey Areas of Service:\nSexuality, sexual identity and coming out\nGender Identity, Gender Dysphoria, Gender Transition\nTrauma, abuse experiences, and Posttraumatic Stress Disorder\nDepression\nAnxiety (e.g., generalized or social anxiety, OCD, phobias, panic, etc.)\nSelf-regulation/emotion Dysregulation Difficulties\nSelf-esteem issues\nAssertiveness\nAutism Spectrum Disorder\nAttention Deficit/Hyperactivity Disorder\nAnger\nAddictions/Substance Use\nSleep difficulties\nGrief and loss\nFamily functioning\nParenting\nMarriage/Relationship issues	info@stepstonepsychology.com	\N	416 551 7284	M5S	\N	\N	Barbara Mancini\nPh.D., C.Psych	\N	https://www.stepstonepsychology.com
904	rho	teen-clinic-st-michaels-hospital	Teen Clinic, St Michael’s Hospital	61 Queen Street East\nToronto, M5C 2T2	\N	Teen clinic serving all youth but with special focus on LGBT youth.\nTeen Clinic at St. Michael’s Hospital (Thursday- all day)\nTeen Clinic at SickKids (Wednesday- afternoon only)	hjbonifa@gmail.com	\N	416-867-3655	M5C	\N	\N	Joey Bonifacio\nMD FRCPC MSc	\N	\N
874	rho	stephanie-cordes-naturopathic-doctor	Stephanie Cordes, Naturopathic Doctor	15 Yarmouth Street\nGuelph, N1H 4G2	\N	Hi! My name is Stephanie Cordes, and I’m a Naturopathic Doctor who practices trauma-informed care. Although people come to see me for a wide variety of issues, I see a lot of mental health concerns in my clinic including anxiety, depression, bipolar, BPD, addictions, trauma, and more. I also treat a lot of digestive concerns, as they commonly occur in those experiencing mental/emotional/spiritual challenges, and am passionate about providing naturopathic services to my LGBTQ community here in Guelph. Natural therapies I frequently recommend include botanical (herbal) medicine, nutritional supplements, diet and lifestyle counselling, stress management, acupuncture, and more.\nYou can find me at my private practice (Kura Naturopathic) or poking clients at Guelph Community Acupuncture. For more information visit www.drcordes.com, send an email to info@drcordes.com, call Kura at 519-766-9759, or call Guelph Community Acupuncture at 519-829-3000.	info@drcordes.com	KURA NATUROPATHIC Tue 9am-12:30pm Thu 2pm-8pm Fri 2:30-7:30pm GUELPH COMMUNITY ACUPUNCTURE usually open 6 days a week, call to make sure we're open again post-COVID	519-766-9759	N1H	\N	$45-$240\nSliding scale range - $/Hour Minimum: 60 Maximum: 150	Stephanie Cordes\nND	\N	https://www.drcordes.com
875	rho	stephen-buzzelli-rp-nd	Stephen Buzzelli RP, ND	Toronto, On , M6L 1M1	\N	I am a dually registered healthcare provider, who uses psychotherapy and naturopathic medicine to address mental health concerns.\nI identify as a gay cis-male who uses he / him pronouns.	stephenbuzzellirp@gmail.com	**Online only Tuesday: 10-3 Thursday: 11-3 / 6-10pm	647 492 1507	M6L	\N	$125 (psychotherapy) / $145 (naturopathic medicine)	Stephen Buzzelli\nRP ND MACP	\N	https://www.stephenbuzzelli.ca
876	rho	steven-mckeown-massage	Steven McKeown Massage	Toronto	\N	Steven McKeown is a Registered Massage Therapist in Toronto, offering a downtown clinic, where healing and relaxation are promoted. Skilled in a broad range of massage therapy techniques including Swedish/Deep Tissue, Craniosacral Therapy, Neuromuscular Intergration and Structural Alignment, and Reflexology, Clients receive the treatments they need.	steve@torontormt.ca	\N	416-878-5688	\N	\N	\N	\N	\N	https://www.torontormt.ca
877	rho	stg-health-and-wellness-osteopathy	STG Health and Wellness Osteopathy	5 Main Street North\nSaint George, N0E 1N0	\N	What is Osteopathy?\nOsteopathy is a form of manual therapy, discovered by Dr. A.T. Still in 1874. Osteopathic manual practitioners\nunderstand that the body functions as a unit, is capable of self-healing and self-regulation, and that the body’s ability to\nfunction is based upon its structural integrity. Through gentle manipulation, practitioners aim to restore movement\nwhere it has been lost and improve the quality of arterial, venous, nervous and lymphatic flow. By removing\nobstructions to this flow, the body demonstrates an amazing ability to heal.\nWho Can Benefit?\nOsteopathy can help individuals of any age, with both acute and chronic ailments. While osteopathic manual\npractitioners do not specifically treat diagnoses or medical conditions, osteopathic care can reduce symptoms and improve overall health. Some ailments that may benefit from osteopathic treatment include: acute and chronic musculoskeletal pain, sports injuries, repetitive strain injuries, headaches, breathing issues, digestive complaints, male and female reproductive issues, fatigue and difficulty sleeping.	\N	\N	(226) 401-2025	N0E	\N	\N	Dana McDonald\nOsteopathic Manual Practitioner	\N	https://stghealthandwellness.com/
878	rho	stittsville-whole-health-pharmacy	Stittsville Whole Health Pharmacy	1609 Stittsville Main Street\nUnit C\nOttawa, K2S 1B8	\N	Opioid Dependence Treatment (Methadone and/ Suboxone)\nRegular Medicine Dispensing, Refills and Renewals.\nTravel Health and Education. Medication Reviews. Smoking Cessation.\nOpen/ Inclusive/ Non-judgemental/ Supportive of LGBTQ+ Health and Well Being	stittsvillewhp@bellnet.ca	\N	6138312180	K2S	\N	\N	AVISH SHAH\nPharmacy / Pharmacist	\N	https://www.stittsvillewhp.com
879	rho	stonechurch-family-health-team-team-b	Stonechurch Family Health Team – Team B	1475 Upper Ottawa Street\nHamilton, L8W 3J6	\N	Stonechurch Family Health Centre (SFHC), a clinical teaching unit affiliated with McMaster University and Hamilton Health Sciences, is located in the rapidly growing southern part of the Hamilton Mountain.\nPlease call 905 575 7757 to reach Team B at Stonechurch Family Health Centre.	\N	\N	905 575 7757	L8W	\N	\N	\N	\N	https://stonechurchclinic.ca/
880	rho	stonetree-naturopathic-clinic	StoneTree Naturopathic Clinic	27 Third Street\nCollingwood, L9Y 1K4	\N	Helping people feel better with a focus on dietary and lifestyle habits.	sworts@stonetreeclinic.com	Monday-Thursday: 9:00 - 17:00 Friday: 8:00 - 13:00	705-444-5331	L9Y	\N	\N	Dr.Shelby Worts,BSc,ND\nNaturopathic Doctor (ND)	\N	https://stonetreeclinic.com
881	rho	strive-physiotherapy-performance	Strive Physiotherapy & Performance	260 Doon South Drive\nUnit 8\nKitchener, N2P 2L8	\N	Strive Physiotherapy & Performance was founded by Mike Major, also a Physiotherapist; as the owner of the company he has built a solid organization in which he and his team members believe in the company’s vision and mission statements.	robcastrokkt@gmail.com	\N	519-895-2020	N2P	\N	\N	Mike Major\nPT, BSc, MSc (PT)	\N	https://www.strivept.ca/
882	rho	sudbury-district-nurse-practitioner-clinics	Sudbury District Nurse Practitioner Clinics	200 Larch Street\nSudbury, P3C 1C5	I can provide transition related surgery assessments for top or bottom surgeries\nI can provide secondary assessments for transition-related bottom surgeries	As the first Nurse Practitioner-Led Clinic in Canada, our Mission is to provide comprehensive primary health care through an interdisciplinary approach.	communication@sdnpc.ca	Monday – Friday 9:00am - 12:00, 1:00 - 4:00pm	(705) 673-3721	P3C	\N	\N	\N	\N	https://sdnpc.ca/
883	rho	sue-arai-psychotherapy	Sue Arai Psychotherapy	129 Park Street\nWaterloo, N2M 1P3	\N	My practice focuses on providing individuals and couples with support during life challenges and transitions. I work within a relational and anti-oppressive approach to exploring relationships, stress, anxiety, coping following trauma, loss, growth and personal transformation, and conversations around gender, sexuality, race, and disability.\nI received training at the Toronto Institute for Relational Psychotherapy (TIRP) and I am a registered member of the Ontario Society of Psychotherapists. I also engage in the study, practice, and research of mindfulness, meditation, yoga and exploring trauma healing, and sensorimotor approaches to personal growth and transformation.\nIn Waterloo, I am located in the Uptown Waterloo area at 129 Park Street. My Toronto office is located at 455 Avenue Rd (near St Clair). Please contact me at 519-577-0995 or by email at arai.sue@gmail.com with inquiries or to schedule an appointment.	arai.sue@gmail.com	Monday through Friday, 9 am to 5 pm, one evening weekly.	519-577-0995	N2M	455 Avenue Rd, Toronto 519-577-0995Directions	\N	Sue Arai\nDiploma - Toronto Institute for Relational Psychotherapy, Clinical member- Ontario Society of Psychotherapists (OSP, #2125); Registered Psychotherapist- College of Registered Psychotherapists of Ontario (#002672), Ph.D.	\N	https://www.psychologytoday.com/ca/therapists/sue-arai-registered-psychotherapist-kitchener-on/163580
885	rho	sumac-creek-site-st-michaels-hospital-family-health-team	Sumac Creek Site – St. Michael’s Hospital Family Health Team	73 Regent Park Boulevard\nToronto, M5A 2B7	\N	I seek to provide non-judgmental, anti-oppressive, gender-affirming primary care for folks in the LGBTQ community, including access to hormone therapy and referrals for transition-related surgery. I have experience working with racialized communities, immigrants and refugees, indigenous folks, people experiencing homelessness or vulnerable housing, people who use drugs or alcohol, sex workers, people with disabilities, and people with HIV and Hep C. I provide Hep C treatment, but coordinate care with a specialist for HIV treatment. I am fluent in English, Hindi and Urdu, and speak conversational Spanish.	\N	\N	416-864-3076 (New Patient Intake Line for St. Michael's Family Health Team)	M5A	\N	\N	Ritika Goel\nMD, CCFP, MPH	\N	https://www.211toronto.ca/detail/en/219339
886	rho	summit-housing-outreach-programs	Summit Housing & Outreach Programs	871 Equestrian Court\nUnit #7\nOakville, L6L 6L7	\N	Summit Housing & Outreach Programs, a non-profit charitable organization, provides supportive housing and outreach case management services throughout Halton for people 18 years of age and older diagnosed with a serious mental illness.\nOur services are based on a inclusive, flexible and rehabilitative model of support and are tailored to meet the varied needs of the people we serve.	intake@summit-housing.ca	\N	9058473206	L6L	\N	\N	Gerrie der	\N	https://summit-housing.ca
887	rho	summit-travel-health-downtown-toronto	Summit Travel Health Downtown Toronto	141 Adelaide Street West\nSuite 701\nToronto, M5H 3L5	\N	The finest travel vaccine clinic in Toronto is located in Downtown Toronto. We are ready to help prepare your health for your trip to any destination. We are a designated Yellow Fever Centre by the Public Health Agency of Canada.	growth@summittravelhealth.com	\N	(647) 479-8808	M5H	\N	\N	\N	\N	https://www.summittravelhealth.com/toronto-travel-clinic/
888	rho	summit-travel-health-etobicoke	Summit Travel Health Etobicoke	1243 Islington Avenue\nSuite 700\nToronto, M8X 1Y9	\N	Learn from our experienced staff about the vaccines and medicine available to minimize specific health risks in your area of travel. We are a designated Yellow Fever Centre by the Public Health Agency of Canada.	growth@summittravelhealth.com	\N	(647) 812-0330	M8X	\N	\N	\N	\N	https://www.summittravelhealth.com/etobicoke-travel-clinic/
889	rho	summit-travel-health-mississauga-clinic	Summit Travel Health Mississauga Clinic	4275 Village Centre Court\nUnit 200\nMississauga, L4Z 1V3	\N	Our travel vaccine clinic near Square One Shopping Centre in Mississauga provides you with the immunizations you require for a safe journey. Our clinic locations are designated Yellow Fever Centre in the Ontario region by the Public Health Agency of Canada.	growth@summittravelhealth.com	\N	(289) 430-0120	L4Z	\N	\N	John G.\nDesignated Yellow Fever Centre in Ontario	\N	https://summittravelhealth.com/mississauga-travel-clinic/
890	rho	summit-travel-health-oakville	Summit Travel Health Oakville	345 Lakeshore Road East\nSuite 405\nOakville, L6J 1J5	\N	The leading travel clinic in Oakville. Physicians from across Halton refer their patients to us. Book now in under 2 minutes and travel safely and healthily. We are a designated Yellow Fever Centre by the Public Health Agency of Canada.	growth@summittravelhealth.com	\N	(289) 430-0116	L6J	\N	\N	\N	\N	https://www.summittravelhealth.com/oakville-travel-clinic/
891	rho	support-and-housing-halton	Support and Housing – Halton	599 Chartwell Road\nOakville, L6J 4A9	\N	A non-profit organization offering community-based housing, support and wellness programs to persons living with mental illness. Qualified support coordinators provide support and services based on the consumer’s level of need.\nRent-geared-to-income Supportive Housing Options:\n* transitional housing leading to independent living * collaborative shared housing * shared townhouse living * individual apartments.\nMental Health Community Support Programs:\nStaff assist with * case management * advocacy *life skill training * supportive counselling * activities of daily living * access to community services * 24/7 access to telephone support for program participants.\nReady4Life:\n* ongoing support and housing services to youth ready to transition into the adult system.\nPrograms & Services to Support Mental Wellness: (Consumer Survivor Initiatives)\n* T.E.A.C.H. – A peer to peer mental wellness initiative\n* training programs built on recovery philosophy\n* anxiety and self-esteem workshops\n* peer mentorship programs\n* “Circle of Care” recovery workshops for individuals/families.\n* recovery 101 workshops for individuals struggling with mental health	info@shhalton.org	\N	905-845-9212	L6J	\N	\N	\N	\N	https://www.shhalton.org
892	rho	supporting-our-youth-soy	Supporting Our Youth (SOY)	333 Sherbourne Street\nToronto, M5A 2S5	\N	SOY, a program of Sherbourne Health, is an exciting, dynamic community development project designed to improve the lives of lesbian, gay, bisexual, transsexual and transgendered youth in Toronto through the active involvement of youth and adult communities. We work to create healthy arts, culture and recreational spaces for young people; to provide supportive housing and employment opportunities; and to increase youth access to adult mentoring and support. SOY works within an anti-oppression framework to create opportunities for queer and trans youth and adults to build an inclusive, welcoming community together.	soy@sherbourne.on.ca	\N	416-324-5077	M5A	\N	\N	\N	\N	https://www.soytoronto.org
893	rho	susan-blackburn-psychology	Susan Blackburn Psychology	2300 Yonge Street\nSuite 1600\nToronto, M4P 1E4	\N	Susan Blackburn Psychology provides goal-oriented counselling and psychotherapy for anxiety, depression, self-confidence, self-esteem, stress management, insomnia, life balance, perfectionism, relationships and more.	hello@susanblackburn.com	\N	(416) 549-5089	M4P	\N	\N	Susan Blackburn\nRegistered Psychologist	\N	https://www.SusanBlackburn.com
894	rho	susan-garofolo-child-psychotherapy	Susan Garofolo – Child Psychotherapy	2349 Fairview Street\nBurlington, L7R 2E3	\N	A drug-free alternative which produces profound long-term changes in attitude and behaviour.\n*Fees are covered by most extended health plans	playtherapy1@gmail.com	\N	905-580-7529	L7R	\N	\N	Susan Garofolo\nCertified Child Psychotherapist	\N	https://www.playtherapyforchildren.com
895	rho	susan-tarshis-counselling	Susan Tarshis Counselling	410 Bronte Street South\nSuite 205\nMilton, L9T 0H8	\N	I am a registered private practice psychotherapist with a general practice catering to adult and young adult individuals. I have a clinical concentration in LGBTTTIQ communities as well as Kink and Poly communities. My approach is Humanist, Relational and I also have EMDR training (specialized approach to trauma and PTSD) from an EMDRIA certified training institute.	susan@susantarshis.ca	\N	416-820-9752	L9T	\N	\N	Susan Tarshis\nM.Ed. (Counselling)	\N	https://www.susantarshis.ca
962	rho	toronto-psychology-clinic	Toronto Psychology Clinic	123 Edward Street\nSuite 1103\nToronto, M5G 0A8	\N	Individual and Couple therapy using evidence-based approaches. Focus of clinic is on cultural, religious and sexual diversity.	info@torontopsychologyclinic.ca	\N	416-551-1759	M5G	\N	\N	Saunia Ahmad\nPhD CPsych	\N	https://www.torontopsychologyclinic.ca
896	rho	suzanne-welstead-psychotherapy	Suzanne Welstead Psychotherapy	24 Sinclair Street\nGuelph, N1L 1R6	\N	Relationships matter. They affect our physical, mental, emotional, and sexual health. Let me help you improve and strengthen the relationships in your life. For over 20 years, I have worked with individuals and couples to resolve relationship difficulties, manage anxiety and/or depression, improve self-esteem and work through trauma. I am a Registered Psychotherapist (CRPO), Registered Marriage and Family Therapist (CAMFT/OAMFT), and Certified Sex Therapist (BESTCO). Sex therapy can help individuals to create the most life-enhancing context for the kind of sex that is worth wanting. As a member of the LGBTQ+ community, I welcome the opportunity to help individuals or same-sex couples work through sexual concerns, such as low desire, support after affairs, erectile difficulties, and pain during sex. I can also assist individuals with coming out issues, and exploring their gender identity and expression, as well as make recommendations for medical care.	smwelstead25@gmail.com	\N	519-994-3327	N1L	\N	\N	Suzanne Welstead\nMTS, RMFT, RP, CST	\N	https://www.suzannewelstead.com
897	rho	suzanne-welstead-therapy	Suzanne Welstead Therapy	24 Sinclair Street\nGuelph, N1L 1R6	\N	As a Registered Marriage and Family Therapist and a Certified Sex Therapist, I provide individual and couple relationship and sex therapy. Sex therapy involves processes and exercises which can be used to enrich both an individual’s sexuality and/or the sexual components of an intimate relationship. Sexuality is a vital part of a healthy lifestyle, and therapy can help an individual or couple to create the most life-enhancing context for the kind of sex that is worth wanting. Therapy is about the process of change, and it can help an individual to access these resources which lead to new and more satisfying possibilities for living. Areas of specialization include anxiety, depression, self-esteem, grief, self-harm, crises of meaning. I also specialize in sexual concerns, such as pain during sex, orgasm difficulties, premature ejaculation, erectile dysfunction, and transgender issues. I welcome the opportunity to work with members of the LGBTTTIQQ community.\nTherapy is conducted using cognitive-behavioural, narrative, and experiential approaches. Interventions can include Eye Movement Desensitization and Reprocessing (EMDR) and hypnosis.	suzanne@suzannewelstead.com	\N	519-994-3327	N1L	\N	\N	Suzanne Welstead\nRegistered Psychotherapist, Registered Marriage and Family Therapist and Certified Sex Therapist	\N	https://www.suzannewelstead.com
898	rho	taddle-creek-family-health-team	Taddle Creek Family health team	\N	\N	Medical care,prescriptions and referrals	voneill@tcfht.on.ca	\N	416-964-0800	\N	\N	\N	Shauna Sturgeon\nNP-PHC, MScN	\N	\N
899	rho	taddle-creek-family-health-team-2	Taddle Creek Family Health Team	790 Bay Street\nSuite 522\nToronto, M5G 1N8	\N	Primary Health Care provider accepting new patients.\nOHIP required.	\N	\N	4165911222	M5G	\N	\N	Victoria  O'Neill\nNurse Practitioner	\N	https://taddlecreekfht.ca/home/
900	rho	tala-jalili-asl-english-interpreter	Tala Jalili ASL/English Interpreter	Toronto	\N	I have been providing American Sign Language/English interpreting service since 2001. I identify as queer and a person of colour. I am able and interested in traveling to any community. I am an active member of the Association of Visual Language Interpreters of Canada (AVLIC) as well as Ontario Association of the Deaf (OAD).	talajalili@hotmail.com	\N	(416) 229-2925	\N	\N	\N	\N	\N	\N
901	rho	talk-to-tasha	Talk to Tasha	114 Greenlees Drive\nKingston, K7K 6P9	\N	I am a registered Social Worker and have been working in the field for the last 6 years. I have become frustrated in watching people struggle to find open-minded, non-judgemental and affordable counseling, so I have created this practice to fulfil that need. I am providing a community based service (which means I come to you), with flexible hours ( days,evenings,weekend and skype appointments available) for 60$ a session.\nI work at providing open-minded, non-judgemental, individual and couples counseling for those identifying as LGBTQQIP2SAA and/or alternative relationship dynamics.	Talk.2.twaddington@gmail.com	\N	1 613-817-4342	K7K	\N	\N	Tasha Waddington\nB.S.W, R.S.W	\N	https://www.facebook.com/TalkToTashaW/
902	rho	tall-tree-psychology	Tall Tree Psychology	1049 Somerset Street West\nOttawa, K1Y 3C4	\N	I am a registered psychologist with the College of Psychologists of Ontario and the Ordre des Psychologues du Québec and work with an adult clientele suffering from a wide range of psychological difficulties: trauma and stessor-related disorders (ex.: Posttraumatic Stress Disorder and Adjustment Disorder), Gender dysphoria or gender incongruence, Anxiety Disorders, depression, burnout, difficulties in regulating emotions, body image dissatisfaction, minority stress, stress management and building resilience.\nI strive to create an inclusive space in my practice for everyone to feel safe and welcome. I am respectful and supportive of my client’s gender identity and sexuality and wish to assist and help them connect with their true self. I adopt a gender-affirming stance within my work and wish to help remove barriers and obstacles in people’s gender exploration, discovery and affirmation. I also provide support to transgender/nonbinary people who wish to engage in a transition process. I am a member of the Canadian Professional Association for Transgender Health (CPATH) and work according to the 7th version of the World Professional Association for Transgender Health’s Standards of care (WPATH).\nLastly, I have received extensive training in delivering cognitive-behavioural therapy, existential-humanistic and mindfulness-based interventions. I combine and integrate those various modalities in order to allow for a better fit for each person’s needs.	jessiebosse@talltreepsychology.com	\N	\N	K1Y	\N	\N	Jessie Bosse\nD.Ps., C.Psych	\N	https://www.talltreepsychology.com/
903	rho	taunya-gaum-psychotherapy	Taunya Gaum Psychotherapy	Harbord Ave. & Roncesvalles Ave\nToronto, M5S 2K7	\N	Hello and thank you for inquiring about my services. I offer counselling and psychotherapy services for a range of issues including: grief, loss, anxiety, depression, loneliness, isolation, trauma, sexuality, gender identity & transitions, body image, relationships, adolescence, addictions, life transitions, and existential issues such as death, dying, and the search for meaning. I am warm, non-judgmental, open-minded, and queer/trans positive.\nI offer a sliding scale to clients who require a reduced fee for counselling services and our initial phone consultation together is free.\nMy counselling style is best described as person-centered, which means I follow the agenda of the client. I view clients as the experts of their own lives while I consider myself a consultant within their journeys toward enhanced wellness, strength, and joy.\nI employ tools and techniques from a number of different counselling models and approaches. Models I tend to use most often are solution-focused brief therapy, narrative therapy, emotion-focused therapy, and mindfulness-based therapy.\nFor many of us, our cultures, races, abilities, ages, sexualities, and genders are often compared to societal norms, which, in turn, labels many of our diversities as abnormal or other. Over time, such marginalization of our identities can affect how we experience the world and ourselves, often causing feelings of loss, isolation, and disempowerment. I approach these issues by working with clients from within a feminist perspective and an anti-oppressive framework which helps to facilitate the re-discovery of strengths and the courage to embrace diversity with empowerment, self-love, and confidence.\nMy goal within our work together is to genuinely listen to you and ask the right questions, which helps us to understand your pain together and to mutually identify your strengths, coping skills, hopes, and desired future. I respect that this is your personal journey and I feel privileged to be a witness to your growth, change, and self-discovery.	taunyagaum@yahoo.ca	\N	647-894-4286	M5S	\N	\N	Taunya Gaum\nM. Ed., OACCPP	\N	https://www.taunyagaum.com
905	rho	tender-heart-psychotherapy	Tender Heart Psychotherapy	Toronto, M5S3C2	\N	It is my belief that challenges with mental health, emotion, and relationships do not exist in a vacuum. These are more than personal failings at coping and functioning. Chronic stress, trauma, illness, relational challenges, systemic oppression, and the pressures of capitalism shape both our well-being and our attempts to get well. In welcoming this understanding, we can begin to uncover the deeper questions of your healing work.\nMy approach to psychotherapy is intuitive, deeply compassionate, and rooted in commitment to anti-oppression and social justice.  I value a highly collaborative approach: together, we can explore who and how you are in the world, and where you wish to go.  Working at the pace you set, we can strengthen your connection to self, and to the deep inner wisdom that will create the blueprint for your healing journey.	iryna@tenderhearttoronto.ca	Sunday through Wednesday, from 12-6PM	6476915220	M5S	\N	$145	Iryna\nDutko	\N	https://www.tenderhearttoronto.ca
906	rho	terrace-wellness-group	Terrace Wellness Group	120 Terence Matthews Crescent\nUnit C1 C2\nOttawa, K2M 2B2	\N	Terrace Wellness Group specializes in providing compassionate, individualized mental health care to people of all ages and backgrounds. We believe #BetterIsPossible and we are working to fix the mental health care system now and for good. Our team is comprised of a diverse group of mental health professionals, all dedicated to providing the highest level of care and service to our clients. We provide counselling, psychiatric services, psychological assessments, bio-feedback sessions, coaching, residential services, and our newest addition, our snapclarity„¢ app, that is soon to be launched nationally!	admin@terraceyouth.ca	\N	6138311105	K2M	\N	\N	Terri Storey	\N	https://www.terracewellness.com
907	rho	tg-innerselves	TG Innerselves	95 Pine Street\nGreater Sudbury, P3C 1W9	\N	TG Innerselves offers one on one and group support for transgender people and family members of transgender people. We run weekly transgender social support groups, and a biweekly group for parents, family members, and loved ones. Our direct client service support is available by phone or online for people who are unable to meet with us on site. We offer education services including workshops, presentations, and staff training to organizations, schools, and businesses that are looking to create safer and affirming spaces for transgender people. Our catchment area expands from Parry Sound to James Bay, and from the Quebec border to Wawa.	info@tginnerselves.com	\N	705-673-4396 ext 201	P3C	\N	\N	\N	\N	https://www.facebook.com/tginnerselves
908	rho	thames-valley-midwives	Thames Valley Midwives	434 Maitland Street\nSuite #1\nLondon, N6B 2Z2	\N	The Midwives represent a depth of diversity and experience in the Midwifery practice. Midwives are experts in normal birth and provides care to clients during pregnancy, labour and for the first six weeks postpartum. All midwives are graduates of the Ontario Midwifery Program at McMaster, Ryerson, or Laurentian Universities respectively or formal midwifery training abroad.\nThey have worked in a variety of rural and urban settings with clientele from all walks of life. They provide services to clients living in London, Middlesex Country, Oxford County, and Elgin County. Thames Valley Midwives holds clinic in London, Aylmer, and Woodstock. Midwifery offers clients the choice of giving birth at home, or in one of the two hospitals where our Midwives are credentialed; London Health Sciences Centre, and Woodstock General Hospital.\nThames Valley Midwives is committed to providing an inclusive, safe environment for all of our clients, regardless of race, sexual orientation, gender identity/expression, age, religion, relationship status, immigration/citizenship status or ethnic origin.	info@tvm.on.ca	24/7, everyday for immediate, urgent assistance. General Office Hours Mondays: 8 a.m. to 3 p.m. Tuesdays-Thursdays: 9 a.m. to 4:30 p.m. Fridays: 8 a.m. to 3 p.m.	519-433-5855	N6B	\N	\N	\N	\N	https://tvm.on.ca
909	rho	thames-valley-midwives-2	Thames Valley Midwives	\N	\N	Midwifery practice offering services to all women, partners, their families and surrogates regardless of gender identity.	mrshjross@gmail.com	\N	5194335855	\N	\N	\N	Hayley Ross\nRegistered Midwife	\N	https://tvm.on.ca/
910	rho	the-519	The 519	519 Church Street\nToronto, M4Y 2C9	\N	Anti-Violence Initiatives (AVI), works to empower LGBTQ2S+ communities to end all forms of violence through counselling support, advocacy, and education. The AVI coordinator works to support folks with individual and systemic experiences of violence, and trauma, as well as working collaboratively with the community to navigate these experiences in a healthy way. AVI also works with community and local neighborhoods to develop leadership to enhance and build external partnerships.\nAccess to Justice and Legal Initiatives programs support underserved LGBTQ2S+ communities to reduce barriers to accessing relevant legal services and educational resources in a safe, inclusive and accessible manner free of homophobia, biphobia, transphobia, and other forms of discrimination.\nWith funding support from The Law Foundation of Ontario, The 519 is continuing to advance and expand our legal programming – through partnership development, legal clinic expansion, capacity-building initiatives, and resource development.	kmehrizi@the519.org	Monday to Sunday: 8:30 a.m. to 5 p.m.	416-392-6874	M4Y	\N	\N	Kay Mehrizi	\N	https://www.the519.org
911	rho	the-aids-network	The AIDS Network	140 King Street East\nSuite 101\nHamilton, L8N 1A5	\N	The AIDS Network provides support services to people in Hamilton, Halton, Haldimand, Norfolk and Brant living with and affected with HIV and AIDS and populations vulnerable to HIV infection. We offer:\nIndividualized One on One Supports\nTrained counselors provide Client Centered supportive counselling to:\nAppointments are available in person, at various locations, or via the phone\nPractical Support for Individuals living with HIV\nGroup Social Support Activities\nThe AIDS Network hosts numerous social support activities throughout the year. These include:	info@aidsnetwork.ca	\N	905-528-0854 or 1-800-563-6919	L8N	\N	\N	\N	\N	https://www.aidsnetwork.ca
912	rho	the-allan-clinic-for-prep	The Allan Clinic for PrEP	200 Gerrard St. E\nSuite 311\nToronto, M5A 2E6	\N	We are a nurse-led clinic providing virtual care, as well as an on-site clinic in the heart of downtown Toronto (right across from Allan Gardens). We specialize in  providing improved access to HIV Pre-exposure Prophylaxis (PrEP) medication, HIV and Hep C prevention, counselling and education, and drug reimbursement coordination.  Any HIV negative cisgender or trans-identified man or woman is welcomed with no referral necessary.	admin@allanclinic.ca	Fridays 9 am to 5 pm	416-969-4000	M5A	\N	\N	Vivienne Cordeiro\nRegistered Nurse	\N	https://allanclinic.ca/
913	rho	the-beverley-clinic-of-electrolysis	The Beverley Clinic of Electrolysis	4 Cedar Pointe Dr Unit S\nBarrie, On, L4N 5R7	\N	Services include facial electrolysis, full body electrolysis and SRS/GCS preparatory electrolysis.	kevbev@rogers.com	Tuesday 8:00.am. - 8:00 p.m. Wednesday 8:00 a.m. - 8:00 p.m. Thursday 8:00 a.m. - 7:00 p.m. Friday 12:00 p.m.- 4:00 p.m. Saturday by appointment.	705-725-1221	L4N	\N	\N	Bev Gorham	\N	https://www.beverleyclinicofelectrolysis.com
914	rho	the-bridge-brant	The Bridge Brant	Brantford, n/a	\N	The Bridge is a grassroots committee that works to identify and address inequities that are experienced by the diverse 2SLGBTQ+ communities within Brantford and Brant County.\nWe do our best to connect 2SLGBTQ+ community members with appropriate local resources to support their well-being, and we organize trainings for organizations and the broader community to encourage everyone to create safer spaces. We also apply for grant funding to support advocacy and awareness projects in our local community.\nThe Bridge is made up of volunteers from the community and representatives from local social service, health and non-profit organizations. We meet monthly and use a consensus-based model to make decisions.\nPlease contact us via email to find out more information (thebridgebrant@gmail.com) or find us on FaceBook (https://www.facebook.com/TheBridgeBrantford).	thebridgebrant@gmail.com	n/a	n/a	\N	\N	\N	\N	\N	https://thebridgebrant.com/
915	rho	the-clarity-group	The Clarity Group	144 Courthouse Square\nGoderich, N7A 1M9	\N	Mary is a Registered Psychotherapist (RP) part of the Clarity Group located in Goderich. They provide individual therapy for individuals 12+ sessions are available online or in-person. Mary focuses on empowering clients and has experience working with 2SLGBTQIA+ individuals in rural spaces.	admin@claritypsych.ca	Thursdays online sessions 9:00 a.m. to 4 p.m. Fridays in-person 9:00 a.m. to 3 p.m.	519-612-3314	N7A	\N	110	Mary Ross\nMA, RP	\N	http://www.claritypsych.ca/our-people
916	rho	the-doula-dude	The Doula Dude	St. Thomas, N5P 2Y2	\N	Erich Otten is queer full-spectrum doula/perinatal support practitioner in Elgin County, Ontario. He has been in practice since 2008, providing holistic doula care, complementary therapies and pregnancy options counselling to women and reproductive people. He aims to provide accessible labour support across the full-spectrum of pregnancy outcomes.\nLabour Support\nAs your doula, I shine the light on those dark places during the childbearing year. My goal is to work with all five of your senses to provide you with physical comfort measures, psycho-social and informational support during labour and throughout the childbearing year. Childbirth preparation is available at request to explore all options you may be contemplating. Space is provided for you to discuss your options and gather information for your labour and eventual birth of your tiny human.\nCalm Baby Consults\nIn Calm Baby consults I help you to understand exactly what your baby is going through from a developmental standpoint and why they are crying, hard to settle, upset or struggling with something. I work with you to understand what is happening with feeding, sleeping, stimulation and teach you how to build pressure valves, decompression time and a calmer environment for your baby.\nBreastfeeding Help\nI offer in home evaluation, consultation and treatment plans for newborns and infants experiencing feeding difficulty. Emphasis is placed on the benefits of breastfeeding/chestfeeding your tiny human, visits include discussion on the pros and cons of alternative feeding methods. My goal as your doula/perinatal support practitioner is to foster a healthy, supportive, secure feeding relationship between you and your tiny human. Regardless of which feeding options you choose infant feeding support is provided throughout the childbearing year and beyond.	birthkeeper.erich@gmail.com	\N	\N	N5P	\N	\N	Erich Otten\nFull-Spectrum Doula/Perinatal Support Practitioner	\N	https://the-doula-dude.com
917	rho	the-downtown-psychology-clinic	The Downtown Psychology Clinic	65 Queen Street West\nSuite 510\nToronto, M5H 2M5	\N	I am a registered clinical psychologist and a Clinical Director and Founder of The Downtown Psychology Clinic, which is a group private practice located in Toronto. I am also an Adjunct Professor and the CBT Program Director at the University of Toronto. I offer assessment and Cognitive Behavioural Therapy (CBT) for a wide-range of difficulties, including mood and anxiety disorders (e.g., Social Phobia, OCD, Generalized Anxiety Disorder, and Panic Disorder), relationship issues, worry, as well as schizophrenia and other psychoses. I also work extensively with clients to return to work from short- and long-term disability.\nI completed my PhD at the Western University, and my residency at St. Joseph’s Healthcare, Hamilton. I have also worked in a number of psychological clinics before beginning work full-time in private practice. I am certified in the provision of CBT by the Canadian Association of Cognitive Behavioural Therapy (CACBT).\nThe goal of CBT is to change the way you think about situations and your behaviour in order to improve the way you feel. I take a non-judgmental, empathic and client-centred approach to my practice in order to suit the individual needs of each client.	DrLazar@DowntownPsychologyClinic.com	\N	647-508-1111	M5H	\N	\N	Noah Lazar\nPh.D., C.Psych.	\N	https://www.DowntownPsychologyClinic.com
918	rho	the-gilbert-centre-for-social-and-support-services	The Gilbert Centre for Social and Support Services	80 Bradford Street\nSuite 555\nBarrie, L4N 6S7	\N	The Gilbert Centre for Social and Support Services (formerly The AIDS Committee of Simcoe County) is a community-based, not-for-profit, charitable organization committed to supporting those living with HIV and the LGBTQ communities living in Simcoe County and Muskoka Region. Support programs include client case management, referrals to community services, peer based programs, and health promotion, social and support groups. The Gilbert Centre also offers educational programming to raise awareness of HIV and other sexually transmitted and blood-borne infections as well as capacity building for agencies interested in increasing their ability to serve LGBTQ individuals and families throughout the catchment area.\nServices:\nThe Gilbert Centre also runs gender journeys for trans folks. Contact ColinG@gilbertcentre.ca  for more info.\n	\N	\N	705-722-6778	L4N	\N	\N	\N	\N	https://www.gilbertcentre.ca
919	rho	the-griffin-centre-youth-services	The Griffin Centre – Youth Services	1124 Finch Avenue West\nUnit 1\nToronto, M3J 2E2	\N	reachOUT is a creative, inclusive & accessible program for lesbian, gay, bisexual, trans, two-spirit, gender nonconforming and queer (LGBTTGNCQ) people in the Greater Toronto Area. In particular, we recognize the needs of youth and adults who experience multiple oppressions and work to create spaces with and for people who are traditionally excluded from mainstream services, including people of colour, trans, two-spirit and gender nonconforming people, and disabled people. We are committed to social justice, community building, education and advocacy to increase access, visibility and to strengthen our communities. As part of equitable representation, our staff team reflects the diversity of our queer, trans, two-spirit and gender non-conforming communities with the majority of our team members identifying as Black, Indigenous and people of colour. We offer:\nAll services are free of charge!\nServices are available in English & French. An interpreter can be provided for youth who speak other languages.	contact@griffincentre.org	\N	4167381322	M3J	\N	\N	\N	\N	https://www.griffin-centre.org
920	rho	the-healing-oasis-program-hamilton	The Healing Oasis Program Hamilton	320 Paling Avenue\nHamilton, L8H 5J9	\N	The Healing Oasis Program provides practical support services and wholistic healing programs for those affected by trauma, crisis, addictions, and deep loss.\nIndividual as well as group counselling services are offered.\nLong-term support services are also available.	thehealingoasis@gmail.com	\N	(905)966-0468	L8H	\N	\N	Mary Jackson\nPastoral Counselling	\N	https://thehealingoasis.org/
921	rho	the-health-depot-pharmacy	The Health Depot Pharmacy	London , N6E2S8	\N	The Health Depot is family-owned and operated pharmacy. We bring the entire pharmacy to you, wherever you are, with FREE prescription delivery anywhere in Ontario! Visit our Health Store with more than 10,000 health essentials and home healthcare products that can be delivered with your prescriptions at no extra cost, to provide you with a one-stop-shop for everything pharmacy.	admin@thehealthdepot.ca	Monday to Friday 8 AM - 7 PM	2263300200	N6E	\N	\N	\N	\N	https://www.thehealthdepot.ca
922	rho	the-heitmann-centre	The Heitmann Centre	Main/Danforth\nToronto, M4C 1L4	\N	One of the key predictive factors in whether or not therapy will be successful is your connection with your therapist. It is incredibly important that you choose someone you connect with, can learn to trust, and believe in. With this in mind I offer the first session for free so that you can come in and see if we are a good fit.\nLots of us struggle with challenges that come up at various times in our lives. Sometimes it is one major event and sometimes it is many small events that can be overwhelming in time. Either way, accessing talk therapy as a means of being heard, organizing your thoughts, gaining clarity, and getting motivated is a healthy way of managing during those times that seem utterly unmanageable.\nOur goal at the Heitmann Centre is to support individuals in distress to regain their equilibrium, hope, self-esteem and joy. We support people in finding a way to accept where they are in this moment (rather than where they wish they were or think they should be) and take the steps necessary to help them move closer to the life they want to live	Cara@heitmanncentre.com	\N	647 569 4135	M4C	\N	\N	Cara Heitmann\nMSW, RSW	\N	https://www.heitmanncentre.com
923	rho	the-medical-station	The Medical Station	545 Wilson Ave\nToronto, M3H0C4	I can provide transition related surgery assessments for top or bottom surgeries	The Medical Station is a family health organization (FHO) based in North York right across the street from Wilson subway station.\nDr. Baron is a family physician accepting new patients who has special interest and training involving LGBTQ2S patients including primary trans care.	info@themedicalstation.com	Monday-Thursday: 9am-5pm Friday: 9am-3pm After Hours: Monday-Thursday: 5pm-8pm Saturday: 9am-12pm	416-633-2345	M3H	\N	\N	Dr. Matthew Baron\nMD, CCFP	\N	https://www.themedicalstation.com/site/home
924	rho	the-midwives-clinic-of-east-york-don-mills	The Midwives’ Clinic of East York – Don Mills	\N	\N	Registered Midwife	kaelobrien@gmail.com	\N	\N	\N	\N	\N	Katie O'Brien\nB.A., B.Sc., RM	\N	\N
925	rho	the-midwives-clinic-of-east-york-don-mills-2	The Midwives’ Clinic of East York – Don Mills	1 Leaside Park Drive\nUnit 3\nToronto, M4H 1R1	\N	Our midwifery clinic provides primary care during pregnancy, birth, and 6 weeks postpartum. We are a queer friendly practice, and work within an anti-oppressive framework. There is information on our website about our intake process, and we look forward to welcoming you into our care.	themidwivesclinic@bellnet.ca	\N	416-424-1976	M4H	\N	\N	\N	\N	https://themidwivesclinic.ca/
926	rho	the-midwives-clinic-of-east-york-don-mills-3	The Midwives Clinic of East York Don Mills	1 Leaside Park Drive\nToronto, M4H 1N9	\N	Midwives attend your birth at home, the Toronto Birth Centre or at Michael Garron Hospital; midwives will give you information to make decisions and choices that are right for you and your family. One of your midwives will always be on call 24 hours a day, 7 days a week, for urgent concerns. You will be cared for by well-trained, sensitive caregivers that respect individual differences of the birthing parent and their families. Cultural sensitivity is an important aspect of the care your midwives will provide.	themidwivesclinic@gmail.com	\N	416-424-1976	M4H	\N	\N	\N	\N	https://themidwivesclinic.ca
927	rho	the-mindfulness-clinic	The Mindfulness Clinic	700 Bay Street\nSuite 2200\nToronto, M5G 1Z6	\N	Dr. Paul Kelly started The Mindfulness Clinic in 2009 so patients could easily find effective therapists who were trained in the best, modern, psychotherapy approaches. Dr. Kelly has taken great care to find, mentor and support effective therapists. Ratings from over 7,600 patients confirmed that our team of over 30 therapists has helped almost 80% of patients fully recover or significantly improve.\nWe combine mindfulness psychotherapy in Toronto to help people feel better and reach their goals. We offer individual counselling, several types of group therapy and mindfulness workshops for a wide range of mental health difficulties. The treatment we offer is evidence-based and effective.\nWe also offer a comprehensive outpatient OCD Program for every level of severity from mild to severe.\nThe OCD Program can provide:\n– A thorough assessment and customized treatment plan\n– Group Therapy with skills training for OCD\n– Individual psychotherapy sessions\n– Guidance and support for home-based practice\n– Phone coaching for support between sessions\n– Training for family or friends so they can support your treatment\n– Home visits for assessment and treatment enhancement	themindfulnessclinic@protonmail.com	\N	416-847-7118	M5G	\N	\N	Paul Kelly	\N	https://www.themindfulnessclinic.ca/
928	rho	the-mindfulness-clinic-2	The Mindfulness Clinic	700 Bay Street\nSuite 2200\nToronto, M5G 1Z6	\N	Dr. Paul Kelly started The Mindfulness Clinic in 2009 so patients could easily find effective therapists who were trained in the best, modern, psychotherapy approaches. Dr. Kelly has taken great care to find, mentor and support effective therapists. Ratings from over 7,600 patients confirmed that our team of over 30 therapists has helped almost 80% of patients fully recover or significantly improve.\nWe combine mindfulness psychotherapy in Toronto to help people feel better and reach their goals. We offer individual counselling, several types of group therapy and mindfulness workshops for a wide range of mental health difficulties. The treatment we offer is evidence-based and effective.\nWe also offer a comprehensive outpatient OCD Program for every level of severity from mild to severe.\nThe OCD Program can provide:\n– A thorough assessment and customized treatment plan\n– Group Therapy with skills training for OCD\n– Individual psychotherapy sessions\n– Guidance and support for home-based practice\n– Phone coaching for support between sessions\n– Training for family or friends so they can support your treatment\n– Home visits for assessment and treatment enhancement	themindfulnessclinic@protonmail.com	\N	416-847-7118	M5G	\N	\N	Paul Kelly	\N	https://www.themindfulnessclinic.ca/
929	rho	the-nest-breastfeeding-prenatal-services-inc	The Nest Breastfeeding & Prenatal Services Inc.	30 Dupont St E Unit 103\nWaterloo, N2J 2G9	\N	We provide FREE OHIP COVERED breast/chest feeding and infant care support for new and soon-to-be parents.\nWe service, Guelph, KW, Cambridge and surrounding areas.	info@thekwnest.com	Mon-Wed, Fri: 9 a.m. - 6 p.m. Thurs: 10 a.m. - 8 p.m.	9058055430	N2J	\N	\N	Chest/Breastfeeding Support\nCLC, CBS, Specializing in Tongue & Lip Ties	\N	https://www.theKWnest.com/
930	rho	the-nesting-place	The Nesting Place	Toronto	\N	The Nesting Place provides fun and informative prenatal childbirth education classes as well as birth doula and postpartum doula services. We are here to support you from pregnancy through your first few month with baby(ies).	info@thenestingplace.ca	\N	1-877-BIRTH36	\N	\N	\N	Stefanie Antunes	\N	https://thenestingplace.ca
931	rho	the-sudbury-action-centre-for-youth	The Sudbury Action Centre for Youth	95 Pine Street\nGreater Sudbury, P3C 1W9	\N	I provide youth aged 12 to 25 with mental health counseling, case mgmt, and therapy as an outreach worker.	emilie.hirschfeld@sacy.ca	\N	7052071083	P3C	\N	\N	Emilie Hirschfeld\nRegistered SSW Psychotherapist	\N	https://www.sacy.ca
932	rho	the-teresa-group	The Teresa Group	124 Merton Street\n#104\nToronto, M4S 2Z2	\N	The Teresa Group is Canada’s oldest community-based charitable organization specifically serving children affected by HIV and AIDS and their families.\nFamily Support Program: Our Family Support Program helps by offering practical assistance options such as:\nFamily Food Program: Family Food Program focuses on helping families to provide healthy breakfasts, lunches and snacks for children on a monthly basis.\nBack to School Program: Back to School Program provides new backpacks filled with school supplies for children and youth in grades 1 – 12 on an annual basis.\nGet Ready for Winter Program: Get Ready for Winter Program provides warm hats and mitts for children.\nTTC public transit tokens: TTC public transit tokens are available to make it easier for our families to get to medical appointments, school and other services.\nFinancial Assistance: Financial Assistance helps families with some of the costs of telephone or utility bills, rent or help with clothing or other necessities for their children.\nWelcome Home Baby: Welcome Home Baby delivers a new diaper bag, filled with baby clothes, a toy, a blanket and bottles to new mothers while in the hospital or at home.\nDiapers: Diapers are available for infants and toddlers up until the child’s third birthday.\nBaby Formula Program: Baby Formula Program drastically reduces the risk of HIV transmission through breast milk by offering free formula for a year to new mothers who are HIV positive and who live anywhere in Ontario. The program is funded through the Ministry of Health and Long Term Care.\nClothing Bank: Clothing Bank offers new and used clothes as well as a limited number of childcare items such as strollers and car seats.\nBirthday Gifts: Birthday Gifts provides toys and games especially for children’s birthdays.	info@teresagroup.ca	\N	416-596-7703	M4S	\N	\N	\N	\N	https://www.teresagroup.ca
933	rho	the-village-pharmacy	The Village Pharmacy	535 Yonge Street\nToronto, M4Y 1Y5	\N	Toronto’s HIV, PrEP & PEP Pharmacy\nAll HIV medications in stock\nFree delivery in Ontario\nIn-depth HIV medication consultations (MedsCheck)\nMedication synchronization & medication management tools\nInsurance support\nHIV resources + referrals to HIV service organizations\nOnline Rx and refill requests + free app for prescription requests\nFree rapid HIV testing, every Friday & Saturday 10am to 5pm	yonge@thevillagepharmacy.ca	\N	416-960-2323	M4Y	473 Church Street, Toronto, Ontario416-967-9221Directions	\N	Zahid Somani\nRPh	\N	https://www.thevillagepharmacy.ca
934	rho	the-village-pharmacy-2	The Village Pharmacy	2518 Yonge Street\nToronto, M4P 2H7	\N	The Village Pharmacy is your local, full-service, community pharmacy.\nAll HIV medications in stock. HIV resources + referrals to HIV service organizations.\nIn-depth medication consultations.\nFree delivery. Easy transfers & refills. Insurance support.\nCustom pill packs for chronic medications.\nFree, easy-to-use app.\nNo hassles. No lineups.	midtown@thevillagepharmacy.ca	Monday to Friday: 9:30am to 6:30pm Saturday: 10:00am to 6:00pm Sunday: Closed	416-487-9128	M4P	\N	$8.99 Dispensing Fee for Prescription Medications	\N	\N	https://www.thevillagepharmacy.ca/
935	rho	the-voice-box-office	The Voice Box Office	12-111 Fourth Ave., Suite 143\nSt. Catharines, L2S3P5	\N	Voice and communication training provided by a registered Speech-Language Pathologist/Voice Therapist to help transgender and gender non-conforming individuals develop their own unique, authentic, and healthy voice and communication pattern.	natalia@voiceboxoffice.com	Daytime, evening, and weekend by appointment.	905-220-8377	L2S	\N	\N	Natalia Evans\nSpeech-Language Pathologist (Voice)	\N	https://www.voiceboxoffice.com
936	rho	the-youth-centre	The Youth Centre	360 Bayly Street West\nAjax, L1S 1P1	\N	The Youth Centre is a community health centre accessible to all youth of Ajax and Pickering. Our inter-disciplinary team of professionals offer health and wellness programs in a non-judgmental environment. We provide youth the opportunity to make informed choices that lead toward their personal growth and well-being.\nThe Youth Centre also runs a weekly drop in group for LGBTQ identified youth between 13 and 20 on Thursday evenings.	amyn@theyouthcentre.ca	\N	905-428-1212	L1S	\N	\N	\N	\N	https://www.theyouthcentre.ca
937	rho	thehealthline-ca-information-network	thehealthline.ca Information Network	190 Wortley Road\nSuite 104\nLondon, N6C 4Y7	\N	Not-for-profit organization that helps provide reliable and up-to-date online information about health and social services to the people of Ontario * includes information on health needs of Indigenous communities, LGBTQ+ individuals, and others	editor@thehealthline.ca	\N	519-660-5910	N6C	\N	\N	\N	\N	https://www.thehealthline.ca
938	rho	therapia	Therapia	Toronto, M5B 1S2	\N	Therapia provides in-home physiotherapy 7 days per week, 365 days a year. Our large and experienced team of expert physical therapists specialize in pre- and post-surgical care, neurological rehabilitation and medical rehabilitation. We look forward to helping you heal at home on your road to recovery.	info@therapia.com	\N	416-526-6933	M5B	\N	\N	\N	\N	https://therapia.com
939	rho	therapia-physiotherapy	Therapia Physiotherapy	Toronto	\N	Therapia provides in-home physiotherapy services throughout Toronto and the surrounding area.\nPatients can visit our website and find an ideal physiotherapist by selecting through the following filters:\nProfile Picture\nBiography\nRatings\nFees\nGender\nHave a home care physiotherapist come to you, at a date and time that is convenient for you.\nPlease visit our website www.therapia.life and explore our selection of therapists.\nTherapia brings physiotherapy to you!	info@therapia.life	\N	416-526-6933	\N	\N	\N	\N	\N	https://www.therapia.life
940	rho	therapy-by-bill-taekema	Therapy By Bill Taekema	304-36 Vodden Street East\nBrampton, L6V 1K4	\N	Client directed, in-the-moment, mind and body psychotherapy… that’s good for your soul.\n* I also specialize in supporting LGBT individuals with all the transitional changes and issues involved in retirement &beyon d time of life.	therapybybilltaekema@rogers.com	\N	9054572661	L6V	\N	\N	Bill Taekema\nCertified	\N	https://www.bramptonpsychotherapy.com
941	rho	thrivewell-counselling	ThriveWell Counselling	Toronto, M5S 1X6	I can provide secondary assessments for transition-related bottom surgeries		connect@thrivewell.ca	Monday, Wednesday, and Friday 6pm- 9pm Saturday 11am-4pm	(647) 490-2682	M5S	\N	125	Habibi E. Feliciano Perez\nMSW, RSW	\N	https://www.thrivewell.ca/
942	rho	thrivewell-counselling-2	ThriveWell Counselling	417 Bloor St. W., Lower Level\nToronto, M5S 1X6	\N	Dana is a Registered Social Worker with more than 20 years experience working with adolescents, youth, adults and families.\nDana works extensively with queer, trans, non-binary and LGBTQ+ populations, and those with chronic pain and other physical/mental health challenges. Specializing in trauma healing, Dana works to build resilience, tap into strengths, and lessen the challenges that come with anxiety, depression, PTSD/C-PTSD, OCD, and other mental health challenges.\nDana’s intersecting identities as a queer, adoptive parent within a transracial family, living with chronic pain, and both personal and professional insights in trauma recovery, have made Dana a passionate advocate for individual and family wellness, healing, and resilience.\n\n	connect@thrivewell.ca	Mon, Wed, Fri 9:00 am - 6:00 pm Tues, Thurs 9:00 am - 8:00 pm	6474902682	M5S	\N	$150/50 min session\nSliding scale range - $/Hour Minimum: 125.00 Maximum: 150	Dana Kamin (they/she)\nMSW, RSW	\N	https://www.thrivewell.ca
943	rho	thrivewell-counselling-3	ThriveWell Counselling	417 Bloor Street West\nLower Level\nToronto, M5S 1X6	\N	Do you identify as queer, trans or non-binary? Are you looking for support related to coming out, transitioning, self-esteem, relationships, or another aspect of your journey? Or, perhaps you are a family member, partner or friend struggling with your feelings related to the gender identity and/or sexual orientation of a loved one?  Has trauma, hurt or pain from the past come up as you navigate relationships, family, work, school, the pandemic or other areas of your life?\nThe growing team of counsellors at ThriveWell Counselling can help with all of these struggles and more. We provide individual, couples and family counselling through secure on-line video or telephone counselling, and may be able to provide in-person counselling where needed with safety precautions in place for COVID-19.\nThriveWell counsellors are LGBTQI2S+ affirming, and some of us identify as queer or on the LGBTQI2S+ spectrum ourselves. We work with youth/young adults, adults and older populations, and ground all that we do within values that are trauma-informed, anti-oppressive and anti-racist.\nWe work with you using integrative therapeutic approaches to live a more holistic, confident and peaceful life, both inside & out!\nContact ThriveWell Counselling to set up a free 30-min telephone consultation. We look forward to supporting these next steps in your journey…	connect@thrivewell.ca	9:00-5:00 pm Mondays, Wednesdays, Fridays 9:00-8:00 pm Tuesdays, Thursdays	647-490-2682	M5S	\N	$125-$150/50 min session\nSliding scale range - $/Hour Minimum: 75.00 Maximum: 150.00	MSW, RSW	\N	https://thrivewell.ca
944	rho	thulasi-shanmukanathan	Thulasi Shanmukanathan	5565 Wyandotte St E\nWindsor, N8S 4T9	I can provide transition related surgery assessments for top or bottom surgeries	Supportive environment for  trans youth and adults who require support for transition.\nDr. Shan can assist with HRT as well as evaluation of surgical procedures	dr.thulasishan@gmail.com	Monday: 9:00 AM - 4:00 PM Tuesday: 9:00 AM - 4:00 PM Wednesday: 9:00 AM - 4:00 PM Thursday: 9:00 AM - 4:00 PM Friday: 9:00 AM - 12:00 PM Saturday: CLOSED Sunday: CLOSED	5199740010	N8S	\N	\N	Thulasi Shanmukanathan\nMD	\N	https://www.facebook.com/advancecaremedicalclinic/
945	rho	thunder-bay-counselling	Thunder Bay Counselling	544 Winnipeg Avenue\nThunder Bay, P7B 3S8	\N	Education, support, advocacy and counselling available by appointment or through the free Walk-in Counselling Clinic. The clinic is offered Wednesdays from 12 pm to 8 pm and provides immediate single-session counselling services on a first come – first served basis.	community@tbaycounselling.com	\N	807-684-1895	P7B	\N	\N	\N	\N	https://www.tbaycounselling.com
946	rho	thunder-bay-pediatrics	Thunder Bay Pediatrics	1260 Golf Links Road\nSuite 104\nThunder Bay, P7B 0A1	\N	Provision of trans medical care for children and youth (before 18th birthday).	\N	\N	807-766-3370	P7B	\N	\N	Sarah Dineen\nPediatrician, MD, FRCP	\N	\N
947	rho	timeless-medispa	Timeless MediSpa	101 Union Street\nUnit 2\nSimcoe, N3Y2A6	\N	Timeless MediSpa, where our medical aesthetics team uses the latest innovations in advanced medical technology.\nOur next-generation platform of non-surgical, and non-invasive, cutting edge treatments correct and enhance your natural beauty. We offer a wide variety of treatments including skincare and tightening, micro-needling, hair removal, body contouring, and cosmetic injections and dermal fillers.\nWe are partnered with a leading global provider of innovative and award-winning medical technologies that harness novel radio-frequency (RF) based technology that leads the industry in enhancing beauty and well-being.\nWHAT IS DIOLAZEXL?\nDiolazeXL is an advanced laser hair removal procedure that safely and gently eliminates unwanted hair. It has one of the largest treatment spot sizes, making treatments convenient and fast. The combination of efficacy, patient comfort and speed make DiolazeXL a leader in laser hair removal. It is powerful enough to target and treat even the most stubborn hair.\nWHAT ARE THE BENEFITS?\nUnlike traditional methods (waxing, shaving, bleaching or using depilatory creams), DiolazeXL laser hair removal impacts the root of the problem, rather than offering a temporary solution. Traditional methods will require treatment forever, while DiolazeXL only requires a few sessions. Most patients immediately notice a significant reduction in hair growth and eventually smooth and hair-free skin.\nWHICH AREAS OF THE BODY CAN BE TREATED?\nDiolazeXL can be safely used on most areas of the body that have unwanted hair. Most commonly treated areas include bikini, legs, arms, chest, back, shoulders, stomach, neck, chin and sideburns.\n	info@timelessmedispa.ca	Monday through Saturday Closed Sunday	519-410-MEDI (6334)	N3Y	\N	\N	\N	\N	https://www.timelessmedispa.ca
948	rho	timmins-youth-wellness-hub	Timmins Youth Wellness Hub	Timmins, P4N 1B7	\N	In September 2018 the Timmins Youth Wellness Hub (TYWH) was established to provide programs and services (in English and in French) that support the wellbeing of all youth aged 12-25 in the community. The TYWH offers: mental health counselling and support; mental health, well being, and harm reduction resources; peer support; education and employment support/training, recreation and social support. Food and bus tickets are also provided.\nDuring regular operations, the TYWH offers hubs on a rotational basis throughout the community, utilizing thirteen community partner locations including schools/colleges, and outdoor locations in the summer. During the COVID-19 pandemic, the TYWH is offering virtual programming.	youthwellness@cdspc.org	During the COVID-19 pandemic, the TYWH is offering virtual programming. Our schedule is available on our website.	N/A	P4N	\N	\N	\N	\N	https://www.ywhtimmins.ca/
949	rho	tina-brigley-health-coach	Tina Brigley Health Coach	730 N Rear Rd Rr3\nEssex, N8M 2X7	\N	Ever wonder why you try to make healthier choices only to resort to old habits?\nEver wonder why you start feeling really energized then “fall off the wagon”?\nHave you ever lost weight only to gain it back later?\nDo you obsess about food and dieting but don’t get the results you want?\nI’ve been there. It sucks. BUT IT DOESN’T HAVE TO BE THAT WAY!\nWork with a wellness coach to stop the pattern and break free.	info@tinabrigley.com	\N	\N	N8M	\N	\N	Tina Brigley\nLandmark Forum Training	\N	https://tinabrigley.com
950	rho	tobys-place	Toby’s Place	33 East Road\nToronto, M1N 1Z9	\N	Toby’s Place is drop-in space for LGBTQ+ youth and their friends under 23. We are open Mondays from 3:30pm-8:30pm for dinner, an activity/ workshop, and discussion. We have a ping pong table, board games, books/ zines, arts and craft supplies, laptops, and shower facilities. We also have a clothing boutique. Everything is free, and we provide TTC tokens if needed. Volunteers who assist with the space include social workers, retired teachers and librarians, and nurses/ health care workers.	tobys.place33@gmail.com	\N	647-915-2475	M1N	\N	\N	\N	\N	https://www.facebook.com/tobysplacebbuc/
951	rho	todd-adamowich-psychotherapist	Todd Adamowich Psychotherapist	9 Livingston Avenue\nC/O Grimsby Counselling\nGrimsby, L3M 1K6	\N	Psychotherapist providing counselling, Reiki and consultations for individuals, couples, families and groups. Offices are in Burlington, St. Catharines and Grimsby, Ontario.	todd.zachary@gmail.com	\N	289-253-7126	L3M	\N	\N	Todd Adamowich\nB.A., M.S.W., RSW	\N	https://abalancedlife.webs.com
952	rho	toni-jacobs-msw-rsw	Toni Jacobs, MSW, RSW	Orillia, L3V6T2	\N	Hello,\nMy name is Toni, and I identify as a cisgender female. My pronouns are she/her.\nAs a Registered Social Worker with the Ontario College of Social Workers and Social Service Workers of Ontario, I am pleased to provide therapeutic counselling and psychotherapy to individuals, aged 18 and up. Services are provided exclusively via phone or video.\nI bring a psycho-spiritual orientation to my approach to therapy which incorporates elements of Cognitive-behavioural therapy (CBT), Cognitive-Processing Therapy (CPT), Dialectical Behavioural Therapy (DBT), Narrative Therapy, Mindfulness-Based CBT (MCBT), Solution-Focused Brief Therapy (SFBT), and Acceptance and Commitment Therapy (ACT)\n*Approved NIHB mental Health Counselling Provider delivering culturally adapted psychotherapy to First Nations, Metis, and Inuit (FNMI) community members in Ontario.\n	4tjacobs.rsw@gmail.com	Virtual services only via video or phone. Weekday and evening appointments available. 180.00 per 50 minute session Payment via e-transfer	7059554450	L3V	\N	Individuals - $180.00 per 50 minute session	\N	\N	https://www.empowerandachieve.ca
953	rho	toni-lombardo-dental-hygienist	Toni Lombardo Dental Hygienist	4154 Dundas Street West\nToronto, M8X 1X3	\N	$99. teeth cleaning (exam, dental cleaning, stain removal), in office whitening-$200, periodontal treatment, sealants, fluoride treatments and education/information	dundasdentalhygieneclinic@gmail.com	\N	416 233 1933	M8X	\N	\N	Toni Lombardo\nRegistered Dental Hygienist	\N	https://www.dundasdentalhygieneclinic.com
954	rho	toronto-bisexual-network-tbn	Toronto Bisexual Network (TBN)	c/o The 519 Community Centre\nToronto, M4Y 2C9	\N	The Toronto Bisexual Network’s mandate is to provide a community where bisexuals and people questioning their sexuality can share diverse perspectives on bisexual issues and experiences.\nWe offer support, a social network, information and referrals. Friends, partners and allies are also welcome. We provide support by welcoming people into a bisexual community and creating non-judgmental spaces to share feelings, experiences and fears.\nThe Toronto Bisexual Network also acts as an umbrella group for two gender specific groups for bisexuals – Bisexual Women of Toronto (http://biwot.org) and Bisexual Men of Toronto (http://bimot.ca).	info@torontobinet.org	\N	\N	M4Y	\N	\N	\N	\N	https://torontobinet.org
955	rho	toronto-centre-for-advanced-reproductive-technology	Toronto Centre for Advanced Reproductive Technology	150 Bloor Street West\nSuite 210\nToronto, M5S 1M4	\N	Additional Services: Menstrual Irregularity, Menopause, General Gynecological Care	paul_ti_chang@hotmail.com	\N	416-972-0110	M5S	\N	\N	Paul Chang\nReproductive Endocrinology & Infertility Specialist	\N	\N
956	rho	toronto-centre-for-naturopathic-medicine	Toronto Centre for Naturopathic Medicine	475 Broadview Avenue\nToronto, M4K 2N4	\N	The Toronto Centre for Naturopathic Medicine is dedicated to the idea that great health is central to the successful enjoyment of your life. Our promise is to care about you first, and to do everything we can to help you achieve the state of health and wellness you deserve.\nTCNM is a Safe Space for our LGBTQ+ patients, their partners, and family. Everyone here has been trained and certified in their specific roles, and has honed their skills in real world, clinical conditions. Every service you receive from us will be carefully tailored to your exact needs and delivered with care, respect, and sensitivity.\nIf you are new to our office, or have any questions, contact us and we can help pair you with whichever of us is the best fit for your health condition, health goals and personality.\nOur practitioners are:\nDr. Du La, ND, TCMP, R.Ac\nDr. Jonah Lusis, ND, Bowen Therapist\nDr. John MacIntosh, ND, RMT\nDr. Jennifer Parsons, ND\nMelissa Dunseith, RMT, Reflexologist	info@tcnm.ca	\N	416-598-8898	M4K	\N	\N	Multiple Practitioners\nNaturopathic Doctor	\N	https://www.tcnm.ca
957	rho	toronto-community-massage-wellness	Toronto Community Massage & Wellness	489 College St Suite 206\nToronto, M6G 1A5	\N	Smooth Transitionz is a program catered to providing pre- and post-surgical care for individuals who are undergoing/pursuing gender affirming surgery. Individuals who experience gender incongruence (GI) typically fall through cracks in the medical system when attempting to regain quality of life after surgery. Including massage therapy into the circle of care during this rehabilitation period decreases inflammation and swelling, decreases pain, increases range of motion, and improves scar mobility and aesthetics. Many individuals are living with the joy of finally having the gender affirming body they desire, however, are suffering with the unnecessary restrictions that exist with post-surgical trauma. Smooth Transitionz aims to bridge the gap from hospital to home and reduce/eliminate the discomforts and restrictions that are unique to this community. The high-quality and trauma informed services offered extend to all states of chest-specific concerns including: binding, top-surgery and breast augmentation. Compassionate pricing options available at Toronto Community Massage & Wellness!	contact@torontocommunitymassage.com	Weekends: 8 am - 9 pm	647-803-6388	M6G	\N	Sliding scale range - $/Hour Minimum: 56.50 Maximum: 135	Kim Goode\nRMT BA	\N	https://kindredtherapy.janeapp.com/locations/toronto-community-massage-and-wellness/book
958	rho	toronto-distress-centres	Toronto Distress Centres	Box 243\nAdelaide P.O\nToronto, M5C 2J4	\N	Our Programs\n408-HELP Line – 24/7 Distress and Crisis Line\nSurvivor Support Program\nCaller Reassurance Program\nCommunity Outreach and Education\nDistress Centres\n416-408-HELP (4357)\n24 hours a day\n151-language interpreter service\nTTY service for the hearing impaired: 416-408-0007	Info@TorontoDistressCentre.com	\N	416-408-4357	M5C	\N	\N	\N	\N	https://www.torontodistresscentre.com/
959	rho	toronto-people-with-aids-foundation	Toronto People With AIDS Foundation	200 Gerrard Street East\n2nd Floor\nToronto, M5A 3Y1	\N	Providing services is what we do best. The Toronto People With AIDS Foundation (PWA) is the largest direct practical support service provider for people living with HIV/AIDS in Canada.\nPWAs programs include:\nWe offer free massage, acupuncture, haircuts, a pet program including food and kitty litter, free tickets to events throughout the City and much more. Check out our website for all the details.\nAs host of the Toronto HIV/AIDS Network your Case Manager can make referrals to over 40 community partners providing services to people living with HIV/AIDS in Toronto.	gdowner@pwatoronto.org	\N	416-506-1400	M5A	\N	\N	\N	\N	https://www.pwatoronto.org
960	rho	toronto-people-with-aids-foundation-2	Toronto People With AIDS Foundation	\N	\N	Providing services is what we do best. The Toronto People With AIDS Foundation (PWA) is the largest direct practical support service provider for people living with HIV/AIDS in Canada.\nPWAs programs include:\nWe offer free massage, acupuncture, haircuts, a pet program including food and kitty litter, free tickets to events throughout the City and much more. Check out our website for all the details.\nAs host of the Toronto HIV/AIDS Network your Case Manager can make referrals to over 40 community partners providing services to people living with HIV/AIDS in Toronto.	gdowner@pwatoronto.org	\N	416-506-1400	\N	\N	\N	\N	\N	https://www.pwatoronto.org
961	rho	toronto-plastic-surgery	Toronto Plastic Surgery	790 Bay St.\nSuite 410\nToronto, M5G1N8	I can provide transition related surgery assessments for top or bottom surgeries	Gender Confirmation Surgery – Top Surgery	info@torontoplasticsurgery.com	Mon - Fri 9am - 5 pm	416-323-6336	M5G	\N	\N	Dr Rayisa Hontscharuk\nMD, MSc, FRCSC	\N	https://www.torontoplasticsurgery.com
963	rho	toronto-psychology-clinic-2	Toronto Psychology Clinic	\N	\N	Our approach to psychotherapy involves customizing a treatment program for you based on your current concerns and goals. We use a bio-psycho-social systems framework to create a program unique to the challenges you are dealing with, with each team member specializing in issues related to culture and diversity, accessibility and gender.	info@torontopsychology.com	\N	416-551-1759	\N	\N	\N	\N	\N	https://torontopsychology.com
964	rho	toronto-psychotherapists	Toronto Psychotherapists	511 Davenport Road\nToronto, M4V 1B8	\N	Choosing the right therapist is as important as making the decision to see one in the first place. Not only will you want to be assured that your psychotherapist is highly qualified but you will have a much better experience if your therapist is someone you can trust to help you find your way. Let us help you choose a therapist that you can trust and connect with. If you have any questions or comments about our site, we would like to hear from you.	torontopsychotherapists1@gmail.com	\N	4165800771	M4V	\N	\N	Toronto Psychotherapists	\N	https://torontopsychotherapists.ca/
965	rho	toronto-wellness-centre	Toronto Wellness Centre	12 Wellesley Street West\nToronto, M4Y 1E7	\N	Putting your health and wellness first with Chiropractic care, Acupuncture, Naturopathy, Orthotics, and Massage in our welcoming and dynamic clinic.	torontowellnesscentre1@gmail.com	\N	416-920-2722	M4Y	\N	\N	Jonathan Cartile\nDoctor of Chiropractics	\N	https://torontowellnesscentre.ca
966	rho	toronto-wellness-centre-2	Toronto Wellness Centre	\N	\N	At the Toronto Wellness Centre, our goal is making you feel your best, and keeping you feeling that way for the long-term. We offer a comprehensive array of holistic health services from our team of experienced, fully licensed practitioners. Your wellness is a lifestyle choice, we give you the tools and support to achieve your optimum health goals! Services include: Naturopathy, Acupuncture, Registered Massage Therapy and Chiropractic care. All practitioners are LGBTQ affirming.	torontowellnesscentre1@gmail.com	\N	(416) 920-2722	\N	\N	\N	\N	\N	https://www.torontowellnesscentre.ca
967	rho	total-health-healing-arts-centre	Total Health Healing Arts Centre	A-165 Charlotte Street South\nNewmarket, L3Y 3S7	\N	The team of professionals at our beautiful multidisciplinary clinic is committed to assisting you on your path to total health. We provide a range of complementary healthcare services (including Registered Massage Therapy, Naturopathy and Acupuncture) to meet your physical and mental health needs. RMTs provide treatment options from relaxation and couples massage: Sport/Therapeutic, Women’s Health, pregnant women, Vodder Lymphatic Drainage, TENS therapy, Kinesio taping, Hotstone, and Swedish Massage. Call or visit website for information.	info@totalhealthhac.ca	\N	905-235-4292	L3Y	\N	\N	\N	\N	https://www.totalhealthhac.ca
968	rho	total-health-healing-arts-centre-2	Total Health Healing Arts Centre	\N	\N	The team of professionals at our beautiful multidisciplinary clinic is committed to assisting you on your path to total health. We provide a range of complementary healthcare services (including Registered Massage Therapy, Naturopathy and Acupuncture) to meet your physical and mental health needs. RMTs provide treatment options from relaxation and couples massage: Sport/Therapeutic, Women’s Health, pregnant women, Vodder Lymphatic Drainage, TENS therapy, Kinesio taping, Hotstone, and Swedish Massage. Call or visit website for information.	info@totalhealthhac.ca	\N	905-235-4292	\N	\N	\N	\N	\N	https://www.totalhealthhac.ca
969	rho	total-wellness-centre	Total Wellness Centre	10 Roden Place\nToronto	\N	Acupuncture, Chinese medicine, Naturopathic Medicine and Doula services. We focus on fertility treatments, pregnancy support and birth planning and support. We also support those undergoing IVF or other reproductive medical treatments.	info@totalwellnesscentre.ca	\N	416-532-9094	\N	\N	\N	\N	\N	https://www.totalwellnesscentre.ca
970	rho	tracey-taylor-psychotherapy	Tracey Taylor Psychotherapy	308 Wellington Street\nSuite 402 (4th floor)\nKingston, K7K 7A8	\N	Hello!  I offer counselling and psychotherapy for older teens and adults on an individual basis.  Located in downtown Kingston, Ontario.  Services in person, by phone or video call.\nI am registered with the College of Registered Psychotherapists of Ontario.\nPlease see my website for more information: traceytaylor.ca	tracey@traceytaylor.ca	Mondays, Wednesdays and Thursdays: 8:30 a.m. to 4:30 p.m. by appointment	6138878151	K7K	\N	$120 + HST / hour	Tracey Taylor\nMACP, RP	\N	https://traceytaylor.ca/
971	rho	trans-wellness-ontario	Trans Wellness Ontario	1435 Tecumseh Road East\nWindsor, N8W 1C2	I can provide secondary assessments for transition-related bottom surgeries	The mission of Trans Wellness Ontario is to enhance and sustain the health and wellness of Transgender, Genderqueer, Two-Spirit, Non-Binary, Queer and Questioning communities and their families.\nWe offer:\nOur physical location is in Windsor, Ontario, but our services are available to people across the province through virtual platforms or phone call.	reception@transwellness.ca	Monday to Friday, 10am to 6pm (when the office is physically open).	(226) 674-4745	N8W	\N	\N	\N	\N	https://www.transwellness.ca/
972	rho	transfeminine-vocal-coaching-female-vocal-presentation	Transfeminine vocal coaching + female vocal presentation	9 Beaucourt Place\nHamilton, L8S 2P8	\N	Hi there! My name is Nicole and I’m offering vocal coaching for transfeminine individuals who want to begin using and practicing with their new voices. Transition can be a challenging process, but with the right advice, you can definitely make some parts easier on yourself than others. Did you know that there are only two octaves (at the very highest and lowest end) of the vocal spectrum that people who are AFAB or AMAB can’t reach? That means that the vast majority of human sounds are possible by everyone! Yes, that includes you!\nMy sessions focus on some of the mechanical sides to speaking in a feminine voice, but I also focus on the social aspects of female speech that will help others register you as the gender you choose to identify as.	nicole.aridana@gmail.com	Make an appointment and we will see what we can do! I work from home, so all hours are on the table.	9059025600	L8S	\N	$80/session. Session lasts one hour.	Nicole	\N	https://mtfvoicelessons.weebly.com
973	rho	transformation-counselling	Transformation Counselling	22 King Street South\nWaterloo, N2J 1N8	\N	LGBTQ + friendly and affirmative individual, relational, and sex therapy. Carling gained extensive experience and training during her time at HIV/AIDS Resources & Community Health and Transgender Health Clinic. She works from an anti-stigma and strengths-based perspective and has an in-depth understanding of how homophobia, mononormativity, racism, sexism, colonialism, and transphobia impacts mental health and relationships.	carling@transformationcounselling.com	\N	(519) 954-5900	N2J	\N	\N	Carling Mashinter\nMSc. Couple & Family Therapy, Registered Psychotherapist	\N	https://www.transformationcounselling.com
974	rho	transforming-emotions	Transforming Emotions	320 Danforth Avenue\nToronto, M4K 1N8	\N	We provide LGBTQ2SS+ counselling services for a range of mental health needs including anxiety, depression, healing from past trauma, relationship support, grief, identity/coming out, and life transitions.	transformingemotions@gmail.com	\N	647-931-6617	M4K	\N	\N	Sarah Thompson\nPhD., C.Psych.	\N	https://transformingemotions.ca
975	rho	transgender-voice-coaching-with-sophie	Transgender Voice Coaching With Sophie	Toronto, M6R2A2	\N	If you’re a transgender woman, you know how bitter the sting of dysphoria feels. And that can be even more acute when it comes to your voice. If you’re tired of being misgendered over the phone, transgender voice training near me with Sophie Edwards can help.\nA transgender woman herself, Sophie understands how messy the process of transitioning can be. And while she can’t do anything to change your gender, she can help you find a voice that makes you more comfortable.\nSophie offers virtual sessions through Zoom, so she is accessible from any location with a stable internet connection.\nBook your FREE introductory session with Sophie today.	sbedwards5@gmail.com	Wednesday - 11am-7pm Thursday - 11am-7pm	2268065075	M6R	true	Sliding scale range - $/Hour Minimum: 20 Maximum: 145	Voice Coaching For Trans Women	\N	https://goo.gl/maps/WAiPSovYsiz3J9MJ6
976	rho	transitions-massage	Transitions Massage	31 Boler Street\nToronto, M6P 2Y2	\N	Home based Massage Therapy practice in the Junction neighborhood of Toronto for LGBTQ community focusing on pre and post op surgery clients (Top/Mastectomy/ and Breast Re/Construction) as well as other health concerns such as diabetes, effects from chemotherapy, lymphedema, PTSD, HIV, insomnia, anxiety, depression, headache. Sliding scale for underemployed, new immigrants, and or youth.\nPrivate and Safe location. Unfortunately *not* WC accessible at this time (stairs). Street parking. TTC accessible. Allergen free.	helen@transitionsmassage.ca	\N	4169977073	M6P	\N	\N	Helen Stiller\nRN RMT	\N	https://www.transitionsmassage.ca
977	rho	transitions-massage-2	Transitions Massage	\N	\N	Recovering from surgery is no easy feat. You have your reasons for having surgery: you elected for gender realignment Top Surgery (or Breast Construction); you opted to have a Mastectomy (or Breast Reconstruction) with the intention of living longer despite a cancer diagnosis; or perhaps you needed a lower limb procedure in order to facilitate tissue healing due to diabetes complications. At Transitions Massage, we will help heal your wounds, release your scar tissue, decrease your anxiety and tension, build your confidence, and ease your transition into the new you.\nAs an RMT and an RN, I see beyond your surgery. I see you as someone who is ready to take on the world, one who has faced challenges with courage, and a person who wants a good ally in their corner.\nThese are your times of transition and you deserve a recovery expert who has seen the insides of the operating room and understands the challenges that brought you here.\nI provide massage therapy in a safe, quiet, and private space with ample time set aside between bookings so that you neither feel rushed nor as though you are on as assembly line.	\N	\N	4169977073	\N	\N	\N	Helen Stiller\nRN RMT	\N	https://www.transitionsmassage.ca
978	rho	trent-student-health-services	Trent Student Health Services	Suite 111-Blackburn Hall\n1600 West Bank Drive\nPeterborough, K9L 0G2	\N	Gender affirming care for trans and non-binary individuals (including hormone provision and surgical planning)	healthservices@trentu.ca	September to April: Monday-Friday: 9:00am - 12:00pm and 1:30pm - 4:00pm Closed over winter holidays in accordance with Trent University Holiday. Closed on the Fridays of both the Fall and Spring Reading Week. Reduced Spring to Summer hours: May & June: Tuesday, Wednesday & Thursday 9:00am - 12:00pm and 1:30pm - 4:00pm July: Tuesday & Thursday 9:00am - 12:00pm and 1:30pm - 4:00pm August: Closed	705-748-1481	K9L	\N	\N	\N	\N	https://www.trentu.ca/wellness/health
979	rho	trenton-massage-and-lymphedema-clinic	Trenton Massage and Lymphedema Clinic	20 Joseph Street\nUnit 1\nTrenton, K8V 5M8	\N		trentonmassage@gmail.com	Monday 8:00am - 7:30pm Tuesday 8:00am - 7:30pm Wednesday 8:00am - 8:00pm Thursday 8:00am - 8:00pm Friday 8:00am - 8:00pm Saturday 9:00am - 4:00pm	613-394-3636	K8V	\N	Including HST: $70 - 30 mins, $90 - 45 mins, $110 - 60 mins, $130 - 75 mins, $145 - 90 mins	\N	\N	https://trentonmassage.com
980	rho	trevor-hart-psychologist	Trevor Hart Psychologist	691 Bloor Street West\nToronto, M6G 1L3	\N	I provide cognitive-behavioural therapy for a variety of emotional problems and life concerns. Some of the problems for which I provide psychotherapy and counselling include anxiety, worry, depression, stress management, sexual functioning problems, and adjustment problems. I also provide psychotherapy and counselling to help people coping with chronic diseases and illnesses such as HIV, cardiovascular disease, cancer, chronic pain, and diabetes. My practice is built upon the values of therapy conducted in a respectful, collaborative and problem-solving manner, within the context of a safe and trusting therapeutic relationship. I am committed to drawing on the latest advances in psychological practice treatment and giving you access to the most scientifically validated treatments. I am a gay man with significant experience working with a wide diversity of LGBT people and people living with HIV.	\N	\N	416-979-5000 ext1-6192	M6G	\N	\N	Trevor Hart\nPh.D. C. Psych	\N	https://www.drhart.ca
981	rho	triada-health-ottawa	Triada Health Ottawa	250 Greenbank Rd, Suite 233\nOttawa, K2H8X4	\N	Triada Health Ottawa is a multidisciplinary health clinic in Ottawa, ON.  Woman-owned and run we provide Chiropractic, Physiotherapy, Registered Acupuncture, and Massage Therapy services.\nTriada Health strives to be a very safe space for our LGBT2SQ community because we ARE the community. Our practitioners are very LGBT2SQ-friendly or LGBT2SQ themselves.  If you are looking specifically for LGBT2SQ practitioners you have come to the right place!\nSpecial interests include:\nPhysiotherapy-Post surgical treatment of scar tissue and  range of motion.\nAcupuncture- Mental health,  hormone health, fertility/IVF and pain.	admin@triadahealthottawa.com	Mon: 8 a.m. to 8 p.m. Tues: 8 a.m. to 8 p.m. Wed: 8 a.m. to 8 p.m. Thurs: 9 a.m. to 8 p.m. Fri: 9 a.m. to 6 p.m. Sat: 9 a.m. to 3 p.m. Sun: 9 a.m. to 1 p.m.	6136951213	K2H	\N	\N	\N	\N	https://www.triadahealthottawa.com
982	rho	trillium-counselling	Trillium Counselling	684 Belmont Avenue West\nSuite 301\nKitchener, N2M 1N6	\N	Our counselling center servicing Kitchener Waterloo provides Individual, couple, relationship, marriage and trauma counselling services.	DJORGE@TRILLIUMCOUNSELLING.CA	\N	2267528857	N2M	\N	\N	Devon Jorge\nPsychotherapist, MSW RSW	\N	https://www.trilliumcounselling.ca/
983	rho	tripod-fertility	Tripod Fertility	2225 Sheppard Ave E, Suite 901\nToronto, M2J 5C2	\N	Tripod Fertility focuses on every individual’s journey, guiding them through the experience of fertility treatment.\nServices offered by Tripod Fertility include infertility assessment, IUI, IVF, Natural IVF, family planning, immune testing and treatment as well as complete pre-natal care and gynecologic consultations.\nWe support the growth of families with high quality, personalized, and compassionate patient care. Contact us today to book a consultation.	info@tripodfertility.com	Tripod Fertility is currently open by appointment only*. Our Cycle Monitoring hours: Monday-Friday 7am-9am Clinic hours: Monday-Friday 8am-3pm *Due to COVID-19, please do not come to the clinic without first booking an appointment.	9052013420	M2J	\N	Fees will vary with treatment options	Reproductive Endocrinology & Infertility Specialist (REI)\nMD, FRCSC, REI	\N	https://www.tripodfertility.com
984	rho	twig-fertility	Twig Fertility	313 Eglinton Avenue West\nToronto, M5N 1A1	\N	LGBT2SQ+ Family Building\nWe believe that everybody should feel empowered to have their own family and understand that there are a number of ways to achieve this. We are delighted to welcome all patients and have an inclusive and affirming approach to care.\nWe have a diverse range of fertility treatments and support for everybody and every situation- you can see the full details here https://twigfertility.com/services/lgbt2sq-family-building/	hello@twigfertility.com	9:00am - 5:00pm	(416) 855-8944	M5N	\N	\N	\N	\N	https://www.twigfertility.com
985	rho	twin-sisters-mastectomy-boutique	Twin Sister’s Mastectomy Boutique	440 Brown's Line\nSuite L101\nToronto, M8W 3T9	\N	Our mission is to improve the quality of life of women who have lost a breast to cancer. We provide non-surgical restoration of their body image and biomechanical balance.\nWe are very proud to extend our services to the  LGBT2SQ community and we assure privacy, respect and the right fitting with the most natural breast forms (prostheses) to make you look as good as you feel.\nWe provide breast prostheses and mastectomy bras for all shapes, sizes and color of people in the community no matter what stage of life they are enjoying. You’ll leave our boutique feeling good about how you look and confident in your appearance.	sheri@tsmastectomy.com	Monday 10:00 am - 3:00 pm Tuesday 10:00 am - 3:00 pm Wednesday 10:00 am - 3:00 pm Thursday 2:00 pm - 7:00 pm Friday 10:00 am - 3:00 pm Weekends and holidays - Closed We work by appointment only please.	416 259-1328	M8W	\N	We offer "medical devices" which has partial coverage under the ADP program for qualified individuals. Private insurance may also participate in fee coverage.	Sheri Panesar\nProstheses Fitter	\N	https://www.tsmastectomy.com
986	rho	umbrella-medical-clinic-thunder-bay	Umbrella Medical Clinic Thunder Bay	63 Algoma Street North\nSuite 350\nThunder Bay, P7A 4Z6	\N	We are passionate about Sexual Health and firmly believe that Love is Love. We are fully covered for Canadian Residents. You do not need a referral. We have an accessible location and are fully confidential. Services include, but are not limited to, Birth Control Options; Emergency Contraception; HIV Testing & Prevention; IUD Insertions & Removals; Pregnancy Termination Medication; Sexually Transmitted Infections (STI); Transgender Healthcare; Vaccines (Hepatitis A, Hepatitis B, HPV); Other Services (Pap Tests, Sexual Dysfunction, etc).	info@umbrellaclinic.com	Monday to Friday 9:00am to 4:30pm * with some exceptions - please see website for updated information	8076987200	P7A	\N	\N	Annabella Zawada\nMD	\N	https://www.umbrellaclinic.com
987	rho	umbrella-mental-health-network	Umbrella Mental Health Network	691 Bloor Street West\nToronto, M6G 1L3	\N	We are a collective of like-minded mental health professionals who work primarily in the lesbian, gay, bisexual, trans and queer (LGBTQ+) community. We represent a group of highly skilled, compassionate psychologists, psychotherapists, clinical therapists and social workers who have shared expertise in supporting and promoting health and wellness within an LGBTQ+ mental health framework.\nOur therapeutic approach utilizes a social justice lens, incorporating trauma-informed mental health care. We understand how systemic oppression (e.g. racism, sexism, ableism, homophobia, transphobia) can contribute to symptoms of anxiety, depression, post-traumatic stress and substance use issues.\nOur therapists actively engage in regular training that emphasizes professional development, team support, and sharing the current knowledge in LGBTQ+ mental health, in order to ensure the highest level of care for our clients.	info@umhn.ca	\N	647-687-6543	M6G	\N	\N	Christopher Shillington\nM.A., C.C.C.	\N	https://www.umhn.ca
988	rho	unison-edgeov	Unison – EdgeOV	501 Oakwood Avenue\nToronto, M6E 2W8	\N	Non-judgemental, anti-oppressive, trans/LGBTQ-inclusive drop in health care for youth 13-29. Doctor or nurse practitioner can address any health concern, sexual health info, pregnancy testing and options, STI testing, emergency contraception, vaccinations and more. Mental health support services including referrals and drop in counselling.	steff.pinch@unisonhcs.org	\N	6477980441	M6E	\N	\N	Steff Pinch\nClient Access and Intake Worker	\N	https://unisonhcs.org/
989	rho	unison-health	Unison Health	591 Oakwood Avenue\nToronto, M6E 2W8	\N	Edge OV Youth Clinic is a sexual health clinic in affiliation with Unison Health & Community Services that provides a range of care (primary care, sexual health, hormone therapy) for youth from 13-29 years old.\nWe also provide primary health care for all ages at the Oakwood Vaughan site.	\N	\N	6477980441	M6E	\N	\N	Megan Gao\nMD	\N	https://unisonhcs.org/
990	rho	unison-health-and-community-services	Unison Health And Community Services	1541 Jane Street\nToronto, M9N 2R3	\N	Unison Health and Community Services has four full-service locations, Unison is now serving over 22,000 clients and offers core services that include primary health care, counselling, health promotion, early years programs, legal services, harm reduction programs, housing assistance and adult protective services as well as special programs like Pathways to Educations and Diabetes Education and Prevention.\nUnison Health and Community Services is a non-profit, community-based organization governed by a Board of Directors who are elected every year at our Annual General Meeting. At Unison we strive to:	\N	\N	416-645-7575	M9N	\N	\N	\N	\N	https://unisonhcs.org/
991	rho	unison-health-and-community-services-oakwood-vaughan	Unison Health and Community Services Oakwood-Vaughan	501 Oakwood Avenue\nToronto, M6E 2W8	\N	Drop-In Health Care and Counselling Services for Youth – ages 13 to 29 years\nPrimary Health Care Services (all ages) by appointment	\N	\N	647-798-0441	M6E	\N	\N	Gillian Graham\nRN(EC), Nurse Practitioner- PHC, MN.	\N	https://unisonhcs.org/
992	rho	unison-oakwood-vaughan	Unison- Oakwood Vaughan	501 Oakwood Avenue\nToronto, M6E 2W8	\N	drop-in Care – Trans-friendly, gender-affirming, sexual health and family planing/birth control and mental heal care for Youth ages 13 to 29	\N	\N	647-798-0441	M6E	\N	\N	Gillian Graham\nRNN(EC),PHC-NP, MN	\N	https://unisonhcs.org
1002	rho	village-family-health-team	Village Family Health Team	102-171 East Liberty Street\nToronto, M6K 3P6	I can provide transition related surgery assessments for top or bottom surgeries\nI can provide secondary assessments for transition-related bottom surgeries	Village FHT provides a full range of primary health care services through an inter-professional team including: doctors, a nurse practitioner, registered nurses, a social worker, a registered dietician and a pharmacist. Village FHT is located in Liberty Village.\nUnfortunately our practice is full at this time.	info@villagefht.ca	Monday: 9 a.m. – 8 p.m. Tuesday: 9 a.m. – 8p.m. Wednesday: 9 a.m. – 8p.m. Thursday: 9 a.m. – 8p.m. Friday: 9 a.m. – 5p.m. Saturday: 9 a.m. – 12 p.m. Sunday: Closed	416-599-8348	M6K	\N	\N	\N	\N	https://www.villagefht.ca
1003	rho	village-physiotherapy-and-rehabilitation-center	Village Physiotherapy and Rehabilitation Center	103-57 Village Centre Place\nMississauga, L4Z 1V9	\N	Physiotherapy, Registered Massage Therapy, Acupuncture, Chiropody, Corporate Wellness, Motor vehicle accidents, Pre natal massage, Weight loss, Infertility, Stress management, weightloss	seovillagephysio@gmail.com	\N	9052760015	L4Z	\N	\N	Villeage Therapy\nvillage physiotherapy	\N	https://www.villagephysiotherapy.ca/acupuncture/
993	rho	unity-project-for-relief-of-homelessness-in-london	Unity Project – For Relief of Homelessness in London	717 Dundas Street\nLondon, N5W 2Z4	\N	The Unity Project provides emergency shelter and transitional housing, and promotes community values in a safe, secular and home-like environment for people aged 18 and over. Out of our two buildings on our Old East Village property, we accommodate between 45-60 people per night, and typically operate at 129% over-capacity. Our shelter is open 24 hours every day offering comfortable dorms, nutritious meals and access to programs and services. Life skills and our values of respect, cooperation, interdependence and compassion are embedded throughout our programming. Upon intake residents choose to cook, clean and perform day to day maintenance based on their interests, abilities and disabilities. This process is integral to creating a sense of personal accountability, through the respectful expectation that we take care of ourselves, each other and our community. We have no janitorial or kitchen staff – residents and frontline staff do it all. We keep the peace and get the dishes done. We run a tight ship with good values – like any good home!\nOur Frontline Support Workers manage a caseload of up to 10 residents, providing one-to-one support assisting in the advancement of their personal action plans for stability and independence. Residents may also access resources from the Community Support Worker and Life Skills Coordinator to further advance their goals – whether it is housing, employment or reconnecting with one’s family	info@unityproject.ca	\N	519-433-8700	N5W	\N	\N	\N	\N	https://unityproject.ca/
994	rho	university-of-guelph	University of Guelph	50 Stone Road East\nGuelph, N1G 2W1	\N	OUTline is an anonymous and confidential resource and support service specializing in questions about sexual orientation and gender identity. OUTline serves the University of Guelph and surrounding community, and is funded entirely by students.\nOUTline offers support and resources on the web and through the operation of a confidential and anonymous phone line. These support services are staffed by LGBTIQ2 volunteers who complete a rigorous 35-hour training program.\nPeople call for a variety of reasons: they’re looking for local events, resources or referrals, in need of information about a particular topic or often, just interested in connecting to chat. Whatever the reason, we’re hear to listen. Our services are open to anyone, including straight allies who may be looking for information on supporting their LGBTIQQ2 friends, family members and/or co-workers.\nAnonymous and Confidential Phone Line: 519-836-4550\nPhone Line Hours for March 1 – August 31, 2009:\nTuesdays & Wednesdays 6 pm – 9 pm\nOUTline also participates in a number of awareness activities and training sessions throughout the year, actively engaging the University of Guelph and surrounding community in conversations about LGBTIQQ2 issues.\nOUTline is always looking for bright and enthusiastic volunteers from on and off campus. Training programs are held three times per year in early January, May and September.\nAll activities are organized by the OUTline Coordinator and monitored by an Advisory Committee with a majority of students and composed of a variety of campus and community stakeholders.	outline@uoguelph.ca	\N	519-836-4550	N1G	\N	\N	\N	\N	https://www.uoguelph.ca/~outline
995	rho	university-of-toronto-health-and-wellness	University of Toronto Health and Wellness	214 College Street\nToronto, M5T 1S2	\N	At U of T Health and Wellness we have an experienced set of providers, including family physicians who prescribe hormones and refer for surgery for patients in transition as well as psychologists, social workers and psychiatrists to support mental health care needs of our patients. NOTE: only students attending U of T are eligible to use our clinic services.	\N	\N	416-978-8030	M5T	\N	\N	\N	\N	\N
996	rho	valerie-spironello-social-worker	Valerie Spironello Social Worker	150 Locke Street South\nHamilton, L8P 4A9	\N	I offer counselling, groups and workshops using a holistic approach to assist others in addressing challenges and creating plans for living well in body, mind and spirit.\nI have a special interest in mindfulness and working with care providers to address the impact of working in the ‘helping professions’. Through exploring the ‘cost of caring’ we create plans for life/work wellness.\nPlease see my website for further information.\nPlease note: appointment times are variable dependent on need.	valerie@choosewellness.ca	\N	905-730-0754	L8P	\N	\N	Valerie Spironello\nMSW, RSW	\N	https://www.choosewellness.ca
997	rho	valleyview-psychotherapy-services	Valleyview Psychotherapy Services	Throughout Ontario, N0M 2P0	\N	Valleyview Psychotherapy Services is a virtual provider of psychotherapy to older children (greater than 12 years), youth and young adults who are experiencing life stresses. Given services are provided via video conferencing, clients are able to access the services regardless of where they reside in the province of Ontario.	valleyviewpsychotherapy@gmail.com	Flexible	5198789797	N0M	\N	\N	Todd Wharton\nRP, OATR, CPT	\N	https://www.valleyviewpsychotherapy.com
998	rho	vanina-walsh-np	Vanina Walsh, NP	14 Cedar Pointe Drive\nBarrie, L4N 5R7	\N	Walk-in clinic at David Busby Centre (underneath United Church) in downtown Barrie. Primary Health Care Nurse Practitioner services available on a first-come, first-served basis.	vanina.hewlett@von.ca	\N	7057375044, ext 248	L4N	\N	\N	Vanina Walsh\nNurse Practitioner	\N	https://www.von.ca
999	rho	veronica-rmt	Veronica RMT	Oakwood Village\nToronto , M6E1V4	\N	Registered Massage Therapy focused on providing an inclusive LGBT2SQ-friendly space	veronicarmt@gmail.com	Monday to Thursday 10-6	4163150640	M6E	\N	varies depending on service, please see website	Veronica Lelchuk	\N	httpss://www.veronicarmt.ca
1000	rho	victor-feunekes-rsw	Victor Feunekes, RSW	London, N6B2M2	\N		victor@bpcounselling.com	Flexible	2262128272	N6B	\N	$120	\N	\N	https://www.bpcounselling.com/london-ontario-counsellors/p/victor-feunekes
1001	rho	vidya-therapy-communmication	Vidya Therapy And Communication	Toronto, m4c1j7	\N	I work with families of LGBTQIA+ folks to help support and validate their experiences as they come to terms with their loved-ones’ explorations and expressions of identity, and working with health care providers to unpack implicit bias. I also work with folks who are Neurodivergent, folks who are struggling with chronic or newly diagnosed illness, and folks considering career change. I take a holistic view of health and well-being, and work to support client’s self-determination.\nMy approach is anti-oppressive, incorporates critical race theory and aims to be de-colonial. I hold and honours BSW and MSW focusing on social justice and mental health, and am completing a PhD in Medicine examining critical Whiteness in psychiatry, and the pathway to address health care provider bias.\nWho I work with:\nI work with adults in many areas, including:\nI also work with teens and their families in a variety of areas, including:\nHealth Care providers and administrators: I have a special interest in supporting your work related to:	vidyatherapycommunciation@gmail.com	Flexible. Generally available for clinical/ counselling support Tuesday and Thursday afternoons. Currently meeting virtually. Outdoor "walk and talk" therapy is available as well.	n/a	\N	\N	individuals $160/hour; couples or families $200	Vashti Campbell\nMSW, PhD in progress	\N	https://www.healingcollective.ca/collective-members/vashti-campbell/
1004	rho	virtual-care-rehab	Virtual Care Rehab	Toronto, M3B 0A3	\N	\nVirtual Care Rehab is a team of ON healthcare professionals who work collaboratively to address patients’ health and well-being. Our online clinic includes medical doctors, psychotherapists, physiotherapists, chiropractors, dietitians, naturopathic doctors and fitness professionals. Our team is certified to treat all patients\n\n	info@virtualcarerehab.com	M-F 8:00am - 11:00pm Sat 9:00am - 5pm	1-888-927-3422	M3B	\N	Service fees vary depending on the healthcare service, medical doctors are covered by OHIP	\N	\N	https://www.virtualcarerehab.com
1005	rho	visage-clinic-plastic-surgery	Visage Clinic – Plastic Surgery	133 Hazelton Ave\nSuite 101\nSuite 101, M5R 0A6	\N	1. Classic aesthetic procedures for women, men and transgender patients.\n2. Breast augmentation\n3. Buttock implants\n4. Hip implants\n5. Facial feminization:\n– Tracheal shave\n– Rhinoplasty\n– Frontal bossing shaving, brown lifting and scalp advancement\n– Feminizing upper lids\n– Fat grafting to lips and cheeks for ladies\n– Fat grafting to chin and angles of jaw for males\n– Chin reduction, shaving and augmentation with implants (oval for ladies, square for males)\n– Cheek implants\n– Jaw angle implants\n– Chin implant\n6. Pectoral implants\n7. Etching\n8. Differential abdominal muscle tightening for a better hourglass shape when performing a tummy-tuck\n9. Calf implants\n10. Brazilian butt lift with fat grafting to butt and hips\n11. FTM Top surgery (Mastectomy and chest wall reconstruction).\n12. Fat Grafting	info@visageclinic.com	\N	4169299800	M5R	\N	\N	Marc DuPere\nPlastic Surgeon - M.D., C.M., F.R.C.S.C	\N	https://www.visageclinic.com
1006	rho	voice-muskoka	Voice Muskoka	351 Gryffin Lodge Road\nUtterson, P0B 1M0	\N	Gender affirming voice services offered in a safe space virtually or in Muskoka.	voicemuskoka@gmail.com	Monday-Friday 10-6	705-349-0456	P0B	\N	$60/30 mins, $90/45 mins, $120/1 hour	Cara Schiedel\nMS. S-LP Reg CASLPO	\N	http://www.voicemuskoka.ca
1007	rho	waves-family-medicine	Waves Family Medicine	101 Thompsons Road\nPenetanguishene, L9M0V3	\N	Waves is a family practice built on ideals of inclusivity and person-centered care. We celebrate 2SLGBTQ+ pride and strive to provide care that makes all feel welcome. Our providers have been trained in 2SLGBTQ+ health and are able to provide services such as puberty blockade and hormone therapy for transitioning. For more info give us a call or email us!	operations@wavesfamilymedicine.ca	Phones are answered 10am-4pm Monday to Friday	7053559283	L9M	103D-240 Penetanguishene Road, Midland ON L4R 4P47053559283Directions	\N	\N	\N	http://www.wavesfamilymedicine.ca
1008	rho	wawa-family-health-team	Wawa Family Health Team	17 Government Road\nWawa, P0S 1K0	\N	• Providing healthcare services for trans-identified patients of all ages\n• Assess holistically and provide services to trans patients in all developmental stages\n• Complete health assessments, including health history and physical examination\n• Formulate and communicate medical diagnoses\n• Determine the need for, and order from, an approved list of screening and diagnostic laboratory tests and interpret the results\n• Monitor the ongoing therapy of patients with chronic stable illness by providing effective pharmacological, complementary or counselling interventions\n• Prescribe drugs according to scope of practice\n• Provide health education and health promotion information to individuals and groups\n• Consult with physicians, and/or refer the client to another health care professional if needed	jhunter@wawafht.com	Monday-Friday 8:30 a.m. - 4:30 p.m. Closed from lunch 12 p.m -1 p.m.	(705) 856-1313	P0S	\N	\N	Julie Hunter\nNurse Practitioner	\N	http://wawafamilyhealthteam.com/
1009	rho	waxman-counselling-and-consulting	Waxman Counselling and Consulting	3080 Yonge Street\nToronto, M4N 3N1	\N	I am a generalist practitioner and I have many areas in which I focus my practice. I am skilled at working with adult men, children, teens and young adults of any gender. ADHD, anxiety, depression, friendship and social issues, coming out, sexual orientation and gender, divorce, loss\nTwo offices. Offering evening and weekend appointments. Midtown Toronto and Maple/Richmond Hill.	mbwaxman@gmail.com	\N	416.575.9458	M4N	9505 Keele Street, Toronto, ONDirections	\N	Michael B. Waxman\nBSW MSW RSW	\N	https://www.michaelbwaxman.com
1010	rho	wellfort-community-health-services-four-corners-health-centre	WellFort Community Health Services – Four Corners Health Centre	3233 Brandon Gate Drive\nMississauga, L4T 3V8	\N	WellFort is a not-for-profit organization providing health promotion, primary health care, oral health care, diabetes, and HIV and Hep C education in Peel Region. Four Corners is a community health centre and a member of the WellFort family, located in Malton. Four Corners works towards building a healthier Malton by providing primary care, community programs, health promotion and diabetes education, and by being reflective and responsive to the diverse needs of the community. Our programs and services are geared towards Malton residents who experience barriers to good health, including families who are under resourced; isolated seniors; newcomers; members of racialized communities and youth. Our innovative services are delivered through the use of interdisciplinary/ inter-professional teams, including health promoter/ educators, physicians, nurse practitioner, nurses, chiropodist, physiotherapist, social worker and diabetes educators.	mail.fourcorners@wellfort.ca	\N	905-677-9599	L4T	\N	\N	\N	\N	https://www.fourcornershealthcentre.ca
1011	rho	wellth-pharmacy-clinic	Wellth Pharmacy + Clinic	85 Church Street\nToronto, M5C 2G2	\N	Wellth is a full service compounding pharmacy and multidisciplinary clinic. Our goal is to be our patients “best self partner” by optimizing their vitality with holistic solutions designed for them. We will inspire each client’s unique wellness pursuit through innovative product discovery, easy to understand advice and connection to the community. Independent & Local.\nServices include: Full Service Pharmacy, Specialty Compounding, Vitamins & Supplement, Naturopathic Doctor, Acupuncture, IV Nutrient Therapy, Holistic Nutrition, Functional Medicine.	info@yourwellth.ca	\N	4165049355	M5C	\N	\N	\N	\N	https://www.yourwellth.ca
1012	rho	wellwood-cancer-support	Wellwood – Cancer Support	501 Sanatorium Road\nHamilton, L9C 0C3	\N	Wellwood is a community based not-for-profit organization that offers free supportive care programs and services to those living with cancer or caring for someone with cancer. Programs range from public lectures to peer support to coping strategies including art, yoga, touch therapy, meditation and more. Wellwood is also located in the Juravinski Hospital, on the main level in E Wing. Hours of service include Monday and Thursday evenings 6:30 to 8:30 p.m. at our community site.	wellwood@hhsc.ca	\N	905-667-8870	L9C	\N	\N	\N	\N	https://www.wellwood.on.ca
1013	rho	wentworth-halton-x-ray-and-ultrasound	Wentworth-Halton X-Ray and Ultrasound	Hamilton	\N	X-Ray and Ultrasound\nMammogram\nBMD\nBreast Biopsy	info@whxray.com	\N	905-572-6868	\N	BurlingtonDirections\nOakvilleDirections\nStoney CreekDirections\nWaterdownDirections	\N	\N	\N	https://www.whxray.com
1014	rho	west-end-family-practice-georgian-bay-fht	West End Family Practice – Georgian Bay FHT	30 45th Street South\nUnit 2\nWasaga Beach, L9Z 0A6	\N	Small family health team in Wasaga Beach that is LGBTQ affirming and has training on hormone therapy for trans clients.	\N	\N	705-429-9445	L9Z	\N	\N	\N	\N	https://www.gbfht.ca/
1017	rho	western-ottawa-community-resource-centre	Western Ottawa Community Resource Centre	2 MacNeil Court\nOttawa, K2L 4E3	\N	We offer a vast array of community, health and social services and programs to benefit individuals of all ages in the Goulbourn, Kanata and West Carleton area. We also offer community support services to residents of Nepean.	info@wocrc.ca	\N	(613) 591-3686	K2L	\N	\N	\N	\N	https://www.wocrc.ca
1018	rho	western-university-psychological-services	Western University Psychological Services	1151 Richmond St\n4th floor Western Student Services Building\nLondon, N6A 3K7	\N	Psychotherapy services for Western students	\N	\N	519-661-3031	N6A	\N	\N	Elspeth Evans\nPh.D., C. Psych.	\N	\N
1019	rho	wg-psychology	WG Psychology	Toronto, M4K3P5	\N	Dr. Watson-Gaze provides psychotherapy for adults experiencing issues with anxiety, mood (depression and bipolar disorder), psychosis, substance misuse, emotion dysregulation, and life and relationship distress.	drjames@wgpsychology.com	Monday-Friday: 11am-6pm	6479056512	M4K	\N	Sliding scale range - $/Hour Minimum: 200 Maximum: 275	James Watson-Gaze\nPh.D., C.Psych	\N	https://www.wgpsychology.com/
1020	rho	white-pine-psychology	White Pine Psychology	5195 Harvester Road\nBurlington, L7L 6E9	\N	We offer evidence-based psychotherapy and psychological assessments for a wide range of struggles. We are very experienced in working with trans clients, and are happy to help with assessments for surgical readiness.	contact@whitepinepsychology.ca	\N	289 427-5577	L7L	\N	\N	Carmen Weiss\nClinical Psychologists, Registered Social Workers	\N	https://www.whitepinepsychology.ca
1021	rho	whitewater-bromley-community-health-center	whitewater Bromley community health center	20 Robertson Drive\nBeachburg, K0J 1C0	\N	LGBTQ positive space…3 np’s and one MD who will support hormone rx, hormone initiation, referrals.	\N	\N	613-582-3685	K0J	\N	\N	jacqueline kirkland\nNP	\N	\N
1022	rho	whitewater-bromley-community-healthcentre	Whitewater Bromley Community HealthCentre	20 Robertson Drive\nBeachburg, K0J 1C0	\N	Primary health care, multidisciplinary team and many community partners. Serve all ages. Must be a client of the CHC to access most of the services. Our clinic offers some programing open to the community.	jkirkland@wbchc.on.ca	\N	613-582-3685	K0J	\N	\N	Jacqueline Kirkland\nNurse Practitioner	\N	\N
1023	rho	william-cooke-and-associates-counselling	William Cooke and Associates – Counselling	2200 Bloor Street West\nSuite 6\nToronto, M6S 1N4	\N	William Cooke and Associates is a collaborative counselling and clinical supervision practice founded in 1996. We are well-qualified and experienced caring professionals. We are here to help when problems impact your life or relationships. We work with individuals, couples and families on a broad range of concerns. We are specialists in grief counselling and couples counselling. We meet in person or over telephone or video.	info@williamcooke.ca	\N	416-762-0330	M6S	\N	\N	William Cooke\nMSW, RSW, MDiv, RMFT	\N	https://www.williamcooke.ca
1024	rho	willow-breast-cancer-support-canada	Willow Breast Cancer Support Canada	30 Saint Patrick Street\n4th Floor\nToronto, M5T 3A3	\N	Willow Breast Cancer Support Canada, founded in 1994, is a national not-for-profit breast cancer organization that provides free support and information today for those who cannot wait for tomorrow’s cure. From the individual diagnosed, to their family and caregivers, Willow makes sure no one needs to face breast cancer alone. Willow’s programs include Peer Support (Telephone, Web/Electronic and In-Person), Community Support (Support Groups in more than 120 locations across Canada), and In Our Genes (information and support for people at high risk for Hereditary Breast and Ovarian Cancer).	info@willow.org	\N	1-888-778-3100	M5T	\N	\N	\N	\N	https://www.willow.org
1025	rho	windsor-essex-county-health-unit	Windsor-Essex County Health Unit	1005 Ouellette Avenue\nWindsor, N9A 4J5	\N	Confidential pregnancy testing (urine) and counseling.\nBirth Control (at cost)\nHIV testing (Anonymous or Confidential)\nTesting for Sexually Transmitted Infections\nTreatment for Sexually Transmitted Infections\nPap tests.\nFree Hepatitis A & B Immunization for eligible adults.\nHPV vaccine\nFree Condoms.\nAssessments by a public health nurse or clinic doctor as requested.	nicholefisher@hotmail.com	\N	519-258-2146	N9A	\N	\N	\N	\N	https://www.wechealthunit.org
1026	rho	windsor-family-health-team	Windsor Family Health Team	2475 McDougall Street\nWindsor, N8X 3N9	\N	An interprofessional team of primary care providers comprising physicians, nurse practitioners, nurse, social worker, dietitian and administrative staff offering a LGBTQ positive environment to receive primary care services.\nWindsor FHT also runs programming such as Gender Journeys (for trans* people and people questioning gender) and BSide (for people who identify as bisexual).	reception@windsorfht.ca	\N	519-250-5656	N8X	\N	\N	\N	\N	https://www.windsorfht.ca
1027	rho	windsor-pride-community-and-resource-centre	Windsor Pride Community and Resource Centre	422 Pelissier Street\nWindsor, N9A 4K9	\N	Provides social and educational outreach and suport to community; offers diversity training to general public; support groups (trans, rainbow recovery), potlucks, etc.	info@windsorpride.com	\N	5199734656	N9A	\N	\N	\N	\N	https://www.windsorpride.com
1028	rho	windsor-shelter	Windsor Shelter	263 Bridge Avenue\nWindsor, N9B 2M1	\N	Shelter for women experiencing homelessness, provide space for 12 women at a time to access a bed, meals, basic needs, housing and income supports as well as any resources and referrals. Drop in program for any woman in the community every Tuesday: provides a meal basic need items, information and referrals. Food Bank: Mondays and Wednesdays from 12-3pm for women and their families living west of Crawford, can access monthly. All programs are LGTBQ friendly.	socialwork@wellcomecentre.ca	\N	5199717595	N9B	\N	\N	\N	\N	https://www.well-comecentre.com
1029	rho	windsor-team-care-centre	Windsor Team Care Centre	2475 McDougall St. Suite 150\nWindsor, N8X 3N9	\N	The Team Care Centre provides multidisciplinary care in collaboration with Primary Care Providers in Windsor-Essex for patients with chronic conditions, mild to moderate mental health conditions, and addictions through team-based allied health care. As a program of the Windsor Family Health Team, we are here to work with you towards achieving your health and wellness goals.\nWe provide all patients 16 and up the opportunity to receive the best care possible to produce optimal outcomes. The team will use their expertise and work with you to develop a plan of care.\nThe Windsor Family Health Team and Team Care Centre is committed to providing an inclusive and welcoming space to receive care, void of stigma, racism and oppression.\nOur team embraces the Francophone, Indigenous, LGBTQ+, and the multicultural communities of Windsor-Essex. Our employees receive ongoing training as we continually strive towards providing equitable and inclusive, culturally sensitive, and safe care.	windsortcc@windsorfht.ca	Monday and Wednesday: 8:30AM – 8PM Tuesday, Thursday and Friday: 8:30AM – 4:30PM	5192505524	N8X	\N	\N	\N	\N	https://windsortcc.ca/
1030	rho	windsor-women-working-with-immigrant-women	Windsor Women Working With Immigrant Women	1368 Ouellette Avenue\nWindsor, N8X 1J9	\N	The Windsor Women Working With Immigrant Women is a multi-cultural, non-profit and community based organization. We function in an anti-oppressive, feminist and anti-racist framework. Our approach is holistic, recognizing that our clients are multi-faceted identities, and that negation of any aspect of that is detrimental to their full participation in Canadian society. We are committed to assisting women and their families with priority to immigrant, racialized, individuals with multiple barriers and youth.\nOur programs are designed to address and meet the needs within the community as they serve to help our clients achieve their goals.\nPrograms:\nFinancial Literacy	info@wwwwiw.org	\N	(519) 973-5588	N8X	\N	\N	\N	\N	https://wwwwiw.org
1031	rho	womancare-midwives	Womancare Midwives	345 Westminster Avenue\nLondon, N6C 5H5	\N	Providing primary care for pre-natal, labour to low risk clients including choice of birthplace of home or hospital. Midwives also provide 6 weeks post-partum care to newborn, and delivering client. Midwifery is based on informed choice care, and Womancare Midwives supports access to quality midwifery care regardless of a client’s gender identity, gender expression, sexual orientation or definition of family.	admin@midwives.on.ca	\N	5196450316	N6C	\N	\N	Laurie Murphy\nAdministrator	\N	https://www.midwives.on.ca
1032	rho	women-warriors-healing-garden	Women Warriors’ Healing Garden	305-2995 Albion Road North\nOttawa, K1V 8Z2	\N	The Women Warriors’ Healing Garden provides certified peer support and therapy to Women and LGBTQ2+ living with trauma related to military service, or service as a First Responder.	WWHG@womenwarriorshg.org	\N	613-612-1099	K1V	\N	\N	Erin Kinsey\nPh.D.	\N	https://www.womenwarriorshg.org
1033	rho	womens-centre-of-york-region	Women’s Centre of York Region	120 Harry Walker Parkway North\nNewmarket, L3Y 7B2	\N	Women’s Centre of York Region offers a range of support and services for women to make positive changes in their lives. Our clients come from York Region – they are mothers, sisters, aunts, neighbors and co-workers. In some cases, our clients may be experiencing significant financial hardship or even violence. One thing our clients share in common is they have identified a deep need and desire for improvement and change in their lives.\nPrograms: We offer a range of group programs and one-on-one support, all of which are designed to meet each woman where she’s at and to help foster meaningful steps and actions in her life. All of these programs are provided at no charge. Explore our programs below to find which one(s) are right for you.\nGroup Programs\nOne-on-One Support\nWCYR is a LGBTQ affirming space and welcomes people of all identities.	Info@wcyr.ca	\N	905-853-9270	L3Y	\N	\N	\N	\N	https://www.wcyr.ca/
1034	rho	womens-college-hospital	Women’s College Hospital	76 Grenville Street\nToronto, M5S 1B2	\N	The Reproductive Life Stages Program is a specialized program at Women’s College Hospital that offers assessment and short-term treatment for women experiencing new or recurrent mental health problems, including anxiety, depression, mania and psychosis during the reproductive life stages (such as menstrual cycle, pregnancy, postpartum and the menopausal transition).Treatment options include individual, couple, family and group therapy in addition to pharmacological interventions.	\N	\N	416 323-6230	M5S	\N	\N	\N	\N	https://www.womenscollegehospital.ca/programs-and-services/mental-health/RLS/
1035	rho	womens-college-hospital-2	Women’s College Hospital	\N	\N	Primary care provider	\N	\N	4163236060	\N	\N	\N	Jessica Bawden\nNP PHC, IBCLC	\N	\N
1036	rho	womens-health-in-womens-hands-chc	Women’s Health In Women’s Hands CHC	2 Carlton Street\nSuite 500\nToronto, M5B 1J3	\N	The mandate of Women’s Health in Women’s Hands [WHIWH] Community Health Centre is to provide primary health care to Black Women and Women of Colour from the Caribbean, African, Latin American and South Asian communities in Metropolitan Toronto and surrounding municipalities.\nOur speciality services include: HIV/ AIDS, Foot Care, Pre and Post Natal Care, Reproductive Health Care, Diabetes, Hyper-Tension, Mental Health, Research on the Health Care of Black Women and Women of Colour.\nWHIWH is inclusive of queer women, trans women and non-binary people. They will see any woman regardless of (residency/refugee) status.	fernanda@whiwh.com	\N	416-593-7655 ext 4980	M5B	\N	\N	\N	\N	https://www.whiwh.com
1037	rho	womens-house-serving-grey-and-bruce	Women’s House Serving Grey and Bruce	Owen Sound	\N	Women’s House services include: In-House safe shelter services, community counselling, 24 hour telephone support line, transitional support program, child witness program and sexual assault counselling.\nThe Women’s House is LGBTQ positive.\nBusiness Line 519.396.9814\nSupport Line 519.396.9655\nToll Free 1.800.265.3026\nSexual Assault Support Line 1.866.578.5566	\N	\N	519.396.9655	\N	\N	\N	\N	\N	https://whsbg.on.ca/
1038	rho	womens-place-of-south-niagara	Women’s Place of South Niagara	\N	\N	Women’s Place provides a 24 hour crisis line, safety planning and crisis support, outreach and counselling services and two shelters including transitional housing support.\nCrisis Lines:\n905-788-0113 (Welland, Port Colborne, Wainfleet, Pelham and surrounding areas)\n905-356-5800 (Niagara Falls, Fort Erie and surrounding areas)	\N	\N	\N	\N	Fort Erie905-356-5800Directions\nNiagara Falls905-356-5800Directions\nPelham 905-788-0113Directions\nPort Colborne 905-788-0113Directions\nSt. Catherines905-356-5800Directions\nWainfleet905-788-0113Directions\nWelland 905-788-0113Directions	\N	\N	\N	https://womensplacesn.org/
1039	rho	womens-sexual-assault-centre-of-renfrew-county	Women’s Sexual Assault Centre of Renfrew County	Box 1274\nPembroke, K8A 6Y6	\N	We offer support to women over the age of 16 who have experienced or are experiencing some form of sexual violence.  We also offer support to family members, partners and the community.  We are a non-profit organization funded by the Ministry of the Attorney General and the generous support of people in Renfrew County.\nThe centre opened its doors in Renfrew County in 1993 to support sexually assaulted women by listening, sharing information and offering resources.  Since then we have grown to include:\nWomen’s Sexual Assault Centre of Renfrew County has undergone extensive LGBTQ training and is inclusive and affirming of LGBTQ people.	\N	\N	1 800 663 3060	K8A	\N	\N	\N	\N	https://wsac.ca/
1040	rho	womens-support-network-of-york-region	Women’s Support Network of York Region	1110 Stellar Drive\nUnit 109\nNewmarket, L3Y 7B7	\N	Women’s Support Network receives approximately two thousand calls on the 24-hour Crisis Line annually, responding to individuals who have been affected by sexual assault, childhood sexual abuse, sexual harassment, date rape and any form of violence. The Crisis Line operates 24-hours/per day every day of the year.\nThe Counselling Program provides crisis counselling within forty-eight hours of the initial contact. WSN also offers 3 months or up to 6 months of ongoing individual counselling. The counselling program will also be offering workshops throughout the year.\nThrough our public education/community outreach program WSN provides education and awareness on issues of sexual violence, to schools community agencies, businesses, service clubs, community groups etc.	jfariawsn@rogers.com	\N	905-895-3646	L3Y	\N	\N	\N	\N	https://www.womenssupportnetwork.ca
1041	rho	xpressions-community	Xpressions Community	P.O. Box 223\nStation A\nToronto, M5W 1B2	\N	Xpressions is a accepting community of crossdressers and Trans Men and Women across Ontario. Centered in the GTA, Xpressions provides numerous social events such as monthly dinners, Pub Nights, Dance Nights and special long weekend events throughout the year. Thought these events we support attendees with friendship and understanding in an atmosphere that is safe and educational. Partners, family and friends included and welcome!\nIn addition, Xpressions extends its support to the community and its members through the Xpressions website, a ‘members only’ private message board, monthly newsletters and referrals to a vast array of proven service providers that support our community.\nXpressions also actively supports the broader community through its support for the Sherbourne Health, the Gender Journey program, Trans Health Ontario, the Trans March/Pride, sister groups in Ottawa, Gals Spring Fling and many other Trans related events.\nCurious? Check out our website (xpressions.org) or join us, dressed or drab at our next Pub Night.	xpressions@xpressions.org	\N	416 689 8305	M5W	\N	\N	\N	\N	https://www.xpressions.org
1042	rho	yellow-brick-house-shelter	Yellow Brick House – Shelter	52 West Beaver Creek Road\nUnit 4\nRichmond Hill, L4B 1G5	\N	Helping survivors of domestic abuse extends beyond offering emergency shelter. The path to safety and self-sufficiency can include support groups, legal advocacy, life skills training, parenting classes, and transitional housing. Whether they are victims or witnesses of abuse, children also need love and support to heal.\nYellow Brick House offers a wide variety of programs in the shelter and throughout York Region to help women and children rebuild their lives. Our programs address each individual’s unique circumstances, whether they are in an abusive relationship or have recently fled one.\nServices at a Glance\nServices are available in 27 languages. All services are free of charge and fully confidential.	info@yellowbrickhouse.org	\N	905 709-0900	L4B	\N	\N	\N	\N	https://www.yellowbrickhouse.org/
1043	rho	yorktown-family-services	Yorktown Family Services	300-2010 Eglinton Ave. W\nToronto, Ontario, M6E 2K3	\N		info@yorktownfamilyservices.com	Rapid Virtual Service (walk-in) Monday & Thursday: 11:00a - 2:30p Tuesday & Wednesday: 3:00p - 6:30p Friday: 10:30a - 2:00p Saturday: Two spots available by appointment only - 10:00a & 12:00p Clients can call reception for general enquiries Mondays to Fridays from 9: 00a - 5:00p.	416-394-2424	M6E	\N	\N	\N	\N	https://www.yorktownfamilyservices.com/
1044	rho	yorkville-sports-medicine-clinic	Yorkville Sports Medicine Clinic	55 Avenue Road\nSuite 2000A\nToronto, M5R 3L2	\N	We are a collection of quality healthcare providers that will get you back to your active lifestyle and prevent pain from coming back.\nWe specialize in fixing pain, no matter how long you have had it, using physiotherapy, chiropractic care, massage and more.	info@yorkvillesportsmed.com	\N	(416) 880-7246	M5R	\N	\N	\N	\N	https://www.yorkvillesportsmed.com/
1045	rho	your-story-counselling	Your Story Counselling	20 Floral Pkwy unit A3\nConcord , L4K 4R1	\N	Hello, and thanks for taking the time to read about me, Louriecar (pronounced Lori + car)! I have a passion for the human mind, which has led me to a BA in psychology from Carleton University and a graduate certificate in victimology from Algonquin College and Dubrovnik University.\nThroughout my life, I have dealt with the challenges and pressures of being a first-generation Canadian and wrestling with mental health challenges. My experiences have led me to work with the Ottawa Rape Crisis Centre and the Canadian Resource Centre for Victims of Crime, where I listened to clients in a 2SLBGTQ safe space with compassion, empathy and unconditional positive regard. I believe the client is the expert in their lives, and I am ecstatic to collaborate in taking small steps towards meaningful change using narrative and strength-based approaches.\nOutside the clinical setting, I enjoy knitting socks and napping with my Shiba-Inu. I have a curious mind about learning about your story, so feel free to contact me for a free 15-minute consultation (or to see a photo of my dog!). I will be accepting clients for online appointments. As a practicum student, I will see clients under the supervision of Judy Lui, Msc, CCC, RP. and MacGyver Kou, Msc, RP.	louriecarc.ysc@gmail.com	Tuesdays and Wednesdays. For other dates and times, please contact via me by email or telephone.	+1 289 963 9868 ext 5	L4K	true	40-75\nSliding scale range - $/Hour Minimum: 0	Louriecar Cabanayan\nRegistered Psychotherapist (Qualifying)	\N	https://www.yourstorycounselling.com/
1046	rho	your-story-counselling-services	Your Story Counselling Services	20 Floral Parkway\nConcord, L4K1R4	\N	My name is Antonia, and I am a therapist intern at Your Story Counselling Services under the supervision of Judy Lui, registered psychotherapist. I am currently a student at Yorkville University in my masters of arts in counselling psychology. I hold a degree in psychology from the University of Toronto and a graduate certificate in infant and early childhood mental health from Seneca College. I have four years of experience working for the school board as a special education assistant with students identified with developmental delays such as Autism and behavioural issues such as Opposition Defiance. I also have volunteer experience in grief and trauma as a patient family care coordinator with the University Health Unit. I hold a degree in psychology from the University of Toronto, and a graduate certificate in infant and early childhood mental health from Seneca College. In my studies I have learned and practiced CBT, SBT, MBCT, and TBCT choosing these as my therapeutic preferences. I aim to pursue my professional development through the practicum experience and create a non-judgemental safe space where clients can feel free to express themselves and build on their strengths. It is my belief that we all possess the ability and capability to break through barriers and overcome obstacles in a collaborative journey towards mental wellness and personal success.	antonian.ysc@gmail.com	Monday -> Friday 8:00AM -> 2:00PM online and in-office availability https://yourstory.janeapp.com/	416-473-3333	L4K	\N	Sliding scale range - $/Hour Minimum: 30 Maximum: 60	Antonia Nimpo\nBSc(H), IMH, HC, MACP(Q)	\N	https://www.yourstorycounselling.com/antonia-nimpo
1047	rho	your-story-counselling-services-individual-couple-family-sex-trauma-psychotherapy	Your Story Counselling Services – Individual, Couple, Family, Sex, Trauma Psychotherapy	20 Floral Parkway\nUnit A3\nConcord, L4k4R1	\N	Providing safe and secure counselling online and in office at Concord/Vaughan. We offer individual, couple, family, & sex therapy.\nWe provide low cost and reduced fees for those with financial need. Give our website a visit and book your free 15 minute consultation today! www.yourstorycounselling.com/contact\nLGBTQ2+ BIPOC identified therapists available.\nCoverage under Registered Psychotherapist and  Registered Social Work available.	info@yourstorycounselling.com	By Appointment only. Weekday and Weekends (Morning, Afternoon, Evenings)	1-416-473-3333	\N	\N	Sliding scale range - $/Hour Minimum: 40 Maximum: 160	MSc, CCC, RP	\N	https://www.yourstorycounselling.com
1048	rho	youth-services-bureau	Youth Services Bureau	2675 Queensview Drive\nOttawa, K2B 8K2	\N	Our Youth Health Clinic is a safe environment, free of judgement. No health card necessary and no appointment necessary – just walk in! We offer health care, dental care and addictions counselling, and our nurse practitioner can prescribe some medications. We also offer Mental Health Services for young people aged 16 to 24. Young people also have access to clean needles and other harm reduction supplies through YSB’s HIV/AIDS and Hepatitis C (HCV) Prevention Education Program. This program also talks about the risks of HIV/AIDS and the Hepatitis C virus, the steps to take to prevent infection and various treatment options. Our workers can put you in touch with crisis counsellors and other community programs and resources.\nYSB also has services to address: homelessness, employment, belonging and being involved with the law.\nYSB runs two LGBTTQ drop in groups: Wednesday: LGBTTQ Drop-in 7 pm to 9 pm (offered at Pink Triangle Services  at 251 Bank Street and SHAG’ed: Last Thursday of every month, Gay Zone LGBTTQ Drop-in 6 pm to 8 pm.	headoffice@ysb.on.ca	\N	613-729-1000	K2B	\N	\N	\N	\N	https://www.ysb.on.ca/
1049	rho	ywca-kitchener-waterloo	YWCA Kitchener Waterloo	153 Frederick Street\nKitchener, N2H 2M2	\N	YWCA Kitchener-Waterloo provides essential programs for women and children. We provide programs in the areas of homelessness and housing, community outreach, early childhood education, youth development, summer camp and an annual conference for girls. Services include: supportive housing, emergency shelter services, downtown community outreach, childcare, summer camps and more.\nYWCA KW is a LGBTQ affirming space and is trans inclusive.	general@ywcakw.on.ca	\N	519-576-8856	N2H	\N	\N	\N	\N	https://www.ywcakw.on.ca/
1050	rho	zac-schraeder-work-in-progress-mental-health-collective	Zac Schraeder @ Work in Progress Mental Health Collective	1304 Dundas Street West\nToronto, M6J1Y1	\N	Seeking and starting psychotherapy can be intimidating, especially if you’re part of a community that has been historically over-diagnosed or if you are worried about being judged. As a queer person, I am familiar with this experience and understand the reservations that come with trusting a professional with personal stories, thoughts, and emotions.\nI believe that the bedrock of effective psychotherapy is rooted in the relationship we cultivate. Getting to know the real you is important to me! As such, I pay close attention to your needs and goals, your values, your identity, and your comfort level. Life problems and intense emotions are valid and worthy of compassionate exploration.\nI am drawn to positive approaches that help you safely express yourself and your problems, and that lay the groundwork for sustainable and meaningful change. We will focus on what works, re-work or rearticulate what doesn’t, and weave together new ways of thinking and being that are in line with your authentic self.\nI specialize in LGBTQ+ identity formation, coming out, life transitions, work and school stress, motivation, and negative experiences with religion.  My practice is always grounded in anti-oppression, is queer affirming, and welcome to everyone.	zac@workinprogressto.ca	Mondays: 4:30-7:30 Tuesdays: 4:30-7:30 Wednesdays: 5pm-9pm Thursdays: 4:30-7:30 Fridays: 2pm-6pm	647-417-7294	M6J	\N	$140, sliding scale available\nSliding scale range - $/Hour Minimum: 100 Maximum: 140	Zac Schraeder\nRP(Qualifying), BA, MA	\N	https://www.workinprogressto.ca/
1051	rho	zach-chan-physio	Zach Chan Physio	1505-18 Yonge Street\nToronto, M5E 1Z8	\N	Toronto Home Care Physiotherapy, Delivered in your space, at your pace.	zach@zachchanphysio.ca	Monday-Thursday: 8am-7pm Friday: 8am-1pm	647-468-0073	M5E	\N	Sliding scale range - $/Hour Minimum: 100 Maximum: 90	Zach Chan\nBScH, MScPT, DPT	\N	https://zachchanphysio.ca
1052	rho	zoe-ferguson-psychotherapy	Zoë Ferguson Psychotherapy	800 Bathurst Street\nToronto, M5R 3M8	\N	I offer individualized, non-judgemental psychotherapy to individuals and couples. Experienced in trauma recovery, but I also work with anxiety, depression, relationship issues and more.	zoeferguson13@gmail.com	\N	6472097290	M5R	\N	\N	Zoë Ferguson\nRegistered Psychotherapist. CRPO#004652	\N	https://www.zoeferguson.ca
\.


--
-- Data for Name: provider_expertise; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.provider_expertise (provider_id, characteristic_id) FROM stdin;
1	1
1	2
1	3
1	4
1	5
1	6
1	7
1	8
1	9
1	10
2	1
2	2
2	3
2	4
2	5
2	6
2	7
2	8
2	9
2	10
3	1
3	22
3	23
3	3
3	25
3	26
3	5
3	28
3	6
3	7
3	8
3	32
3	10
4	1
4	2
4	3
4	4
4	5
4	6
4	7
4	8
4	9
4	10
5	1
5	3
5	4
5	8
5	10
6	1
6	3
6	5
6	6
6	7
6	8
6	10
7	1
7	2
7	3
7	5
7	6
7	8
7	10
8	1
8	22
8	2
8	23
8	3
8	25
8	4
8	26
8	5
8	28
8	6
8	7
8	8
8	32
8	9
9	1
9	2
9	4
9	5
9	6
9	7
9	8
10	1
10	2
10	4
10	7
10	8
11	1
11	22
11	2
11	23
11	3
11	25
11	4
11	26
11	5
11	28
11	6
11	7
11	8
11	32
11	9
11	10
12	1
12	2
12	3
12	4
12	5
12	6
12	7
12	8
12	10
13	22
13	23
13	28
13	6
13	8
14	1
14	22
14	2
14	23
14	3
14	25
14	4
14	5
14	28
14	6
14	7
14	8
14	32
14	10
15	1
15	3
15	4
15	5
15	6
15	7
15	8
15	10
16	1
16	22
16	2
16	23
16	3
16	25
16	4
16	26
16	28
16	6
16	8
16	32
16	9
17	1
17	22
17	2
17	23
17	3
17	25
17	4
17	26
17	5
17	28
17	6
17	7
17	8
17	32
17	9
17	10
18	1
18	22
18	2
18	23
18	3
18	25
18	4
18	26
18	5
18	28
18	6
18	7
18	8
18	32
18	10
19	1
19	2
19	4
19	7
20	1
20	22
20	2
20	23
20	25
20	4
20	7
20	8
20	32
20	9
21	1
21	22
21	23
21	3
21	25
21	4
21	26
21	5
21	28
21	6
21	7
21	8
21	32
21	9
21	10
22	1
22	2
22	3
22	6
22	7
22	8
22	9
22	10
23	1
23	22
23	23
23	25
23	4
23	5
23	6
23	8
23	32
23	9
24	1
24	22
24	2
24	23
24	25
24	4
24	5
24	6
24	7
24	8
24	32
24	9
25	1
25	2
25	3
25	4
25	5
25	6
25	7
25	8
25	9
25	10
26	1
26	2
26	3
26	4
26	5
26	6
26	7
26	8
26	10
27	1
27	4
27	6
28	1
28	5
28	6
28	8
29	1
29	22
29	23
29	25
29	26
29	6
29	8
29	32
30	1
30	22
30	23
30	25
30	4
30	26
30	5
30	8
30	32
31	1
31	2
31	4
31	7
31	8
32	1
32	2
32	3
32	4
32	5
32	6
32	7
32	8
32	10
33	1
33	22
33	23
33	3
33	25
33	4
33	28
33	7
33	8
33	32
33	10
34	1
34	2
34	4
34	7
34	8
35	1
35	3
35	4
35	5
35	6
35	7
35	8
35	10
36	1
36	2
36	4
36	7
36	8
37	1
37	2
37	3
37	4
37	5
37	6
37	7
37	8
37	9
37	10
38	1
38	2
38	4
38	5
38	7
38	8
39	1
39	2
39	3
39	4
39	5
39	6
39	7
39	8
39	10
40	1
40	8
41	1
41	2
41	3
41	4
41	5
41	6
41	8
41	9
41	10
42	1
42	22
42	2
42	23
42	25
42	4
42	5
42	28
42	6
42	7
42	8
42	32
42	9
42	10
43	1
43	2
43	3
43	4
43	5
43	6
43	7
43	8
43	10
44	1
44	2
44	4
44	7
44	8
45	1
45	2
45	3
45	4
45	5
45	6
45	7
45	8
45	9
46	1
46	2
46	4
47	1
47	22
47	2
47	23
47	25
47	4
47	26
47	5
47	28
47	6
47	7
47	8
47	32
47	9
48	1
48	2
48	3
48	5
48	6
48	7
48	8
48	10
49	1
49	22
49	2
49	23
49	25
49	4
49	26
49	5
49	6
49	7
49	8
49	32
49	9
50	1
50	2
50	4
50	7
50	8
50	10
51	1
51	2
51	5
51	6
51	7
51	8
52	1
52	22
52	23
52	3
52	25
52	5
52	8
52	32
52	9
52	10
53	1
53	6
53	8
53	32
53	9
53	10
54	1
54	22
54	23
54	3
54	4
54	28
54	6
54	7
54	8
54	32
55	1
55	22
55	2
55	23
55	3
55	25
55	4
55	26
55	5
55	28
55	6
55	7
55	8
55	32
55	9
55	10
56	1
56	2
56	3
56	4
56	5
56	6
56	7
56	8
56	9
57	1
57	22
57	2
57	23
57	25
57	5
57	6
57	8
57	32
57	9
58	1
58	2
58	3
58	4
58	5
58	6
58	7
58	8
58	10
59	1
59	22
59	23
59	3
59	25
59	4
59	26
59	5
59	6
59	32
60	1
60	2
60	3
60	4
60	5
60	6
60	7
60	8
60	9
60	10
61	1
61	22
61	2
61	23
61	25
61	4
61	5
61	28
61	7
61	8
61	32
61	9
62	1
62	2
62	3
62	5
62	6
62	7
62	8
62	10
63	1
63	2
63	3
63	4
63	5
63	6
63	7
63	8
63	10
64	1
64	2
64	4
64	8
65	1
65	2
65	4
65	7
65	8
66	1
66	22
66	23
66	25
66	4
66	5
66	6
66	7
66	32
66	10
67	1
67	2
67	4
67	6
67	7
67	8
67	10
69	1
69	22
69	23
69	3
69	25
69	4
69	5
69	28
69	6
69	7
69	8
69	32
70	1
70	3
70	5
70	6
70	7
70	8
70	10
71	1
71	2
71	4
71	6
71	8
72	1
72	22
72	23
72	3
72	25
72	4
72	5
72	28
72	7
72	8
72	32
72	9
72	10
73	1
73	22
73	2
73	23
73	3
73	25
73	4
73	8
73	32
73	9
73	10
74	1
74	22
74	2
74	23
74	3
74	25
74	4
74	8
74	32
74	9
75	1
75	2
75	4
75	8
76	1
76	2
76	3
76	4
76	5
76	6
76	7
76	8
76	9
76	10
77	1
77	22
77	2
77	23
77	3
77	25
77	6
77	8
77	32
77	9
78	1
78	2
78	3
78	4
78	6
78	7
78	8
78	9
78	10
79	1
79	22
79	23
79	25
79	26
79	5
79	28
79	6
79	7
79	8
79	32
80	1
80	22
80	2
80	23
80	3
80	25
80	4
80	26
80	5
80	28
80	6
80	7
80	8
80	32
80	9
80	10
81	1
81	2
81	3
81	4
81	5
81	6
81	7
81	8
81	10
82	1
82	2
82	3
82	4
82	5
82	6
82	7
82	8
82	9
82	10
83	1
83	2
83	3
83	4
83	5
83	6
83	7
83	8
83	9
83	10
84	1
84	2
84	3
84	4
84	5
84	6
84	7
84	8
84	9
84	10
85	1
85	2
85	3
85	4
85	5
85	6
85	8
85	10
86	1
86	2
86	4
86	7
86	8
87	1
87	2
87	4
87	5
87	7
87	8
88	1
88	2
88	3
88	4
88	5
88	6
88	7
88	8
88	10
89	1
89	2
89	3
89	4
89	5
89	6
89	7
89	8
89	9
89	10
90	1
90	2
90	3
90	4
90	5
90	6
90	7
90	8
90	9
90	10
91	1
91	2
91	3
91	4
91	5
91	6
91	7
91	8
91	9
91	10
92	1
92	2
92	3
92	4
92	5
92	6
92	7
92	8
92	9
92	10
93	1
93	22
93	2
93	23
93	3
93	25
93	4
93	5
93	6
93	8
93	32
93	9
93	10
94	1
94	22
94	2
94	3
94	25
94	4
94	28
94	6
94	8
94	32
94	9
94	10
95	1
95	2
95	3
95	4
95	5
95	6
95	7
95	8
95	9
95	10
96	1
96	4
96	5
96	6
96	7
96	8
97	1
97	22
97	2
97	23
97	25
97	4
97	26
97	5
97	6
97	7
97	9
98	1
98	22
98	23
98	25
98	4
98	7
98	8
98	32
98	10
99	1
99	2
99	3
99	4
99	5
99	6
99	7
99	8
99	9
99	10
100	1
100	4
101	1
101	3
101	4
101	5
101	6
101	8
101	10
102	1
102	2
102	3
102	4
102	8
104	1
104	6
104	8
105	1
105	5
105	6
105	7
105	8
106	1
106	2
106	3
106	4
106	5
106	6
106	7
106	8
106	9
106	10
107	1
107	2
107	3
107	4
107	5
107	6
107	7
107	8
107	10
108	2
108	3
108	5
108	6
108	8
108	9
108	10
109	1
109	2
109	8
109	32
110	1
110	22
110	2
110	23
110	25
110	4
110	26
110	5
110	28
110	6
110	7
110	8
110	32
110	9
110	10
111	1
111	22
111	23
111	25
111	4
111	5
111	28
111	6
111	7
111	8
111	32
111	10
112	1
112	2
112	23
112	25
112	26
112	5
112	7
112	8
112	32
113	1
113	2
113	7
113	8
114	1
114	4
114	7
114	8
115	1
115	2
115	4
115	7
115	8
116	1
116	2
116	4
116	7
116	8
116	10
117	1
117	2
117	3
117	4
117	5
117	6
117	7
117	8
117	9
117	10
118	1
118	2
118	3
118	4
118	5
118	6
118	7
118	8
118	9
118	10
120	1
120	22
120	23
120	3
120	25
120	4
120	26
120	5
120	28
120	6
120	7
120	8
120	32
120	10
121	1
121	22
121	23
121	3
121	25
121	4
121	26
121	5
121	28
121	6
121	7
121	8
121	32
121	10
122	1
122	22
122	23
122	25
122	6
122	8
122	32
123	1
123	22
123	2
123	23
123	3
123	25
123	4
123	26
123	5
123	28
123	6
123	7
123	8
123	32
123	9
123	10
124	1
124	22
124	2
124	23
124	25
124	4
124	28
124	6
124	8
124	32
124	9
125	1
125	22
125	23
125	25
125	4
125	26
125	28
125	6
125	8
125	32
125	10
126	1
126	2
126	8
127	1
127	2
127	3
127	4
127	5
127	6
127	7
127	8
127	10
128	1
128	2
128	4
128	5
128	6
128	7
128	8
129	1
129	2
129	3
129	4
129	5
129	6
129	8
129	9
129	10
130	1
130	2
130	5
130	6
130	7
130	8
131	1
131	22
131	2
131	23
131	3
131	25
131	4
131	26
131	5
131	28
131	6
131	7
131	8
131	32
131	9
131	10
132	1
132	2
132	3
132	4
132	5
132	6
132	7
132	8
132	10
133	1
133	2
133	3
133	4
133	5
133	6
133	7
133	8
133	9
133	10
134	1
134	2
134	3
134	4
134	5
134	6
134	7
134	8
134	10
135	1
135	2
135	3
135	5
135	6
135	7
135	8
135	10
136	1
136	2
136	4
136	8
138	1
138	22
138	2
138	3
138	25
138	4
138	7
138	8
138	32
138	10
139	1
139	22
139	23
139	3
139	25
139	4
139	8
139	32
139	9
139	10
140	1
140	22
140	2
140	23
140	25
140	4
140	26
140	5
140	6
140	7
140	8
140	32
140	9
141	1
141	22
141	2
141	23
141	3
141	25
141	4
141	26
141	5
141	6
141	7
141	8
141	32
141	9
141	10
142	1
142	22
142	23
142	3
142	25
142	4
142	5
142	6
142	7
142	8
142	32
142	10
143	1
143	22
143	2
143	23
143	3
143	25
143	4
143	5
143	28
143	6
143	7
143	8
143	32
143	9
143	10
144	1
144	2
144	4
144	7
144	8
145	1
145	4
145	6
145	8
146	1
146	2
146	3
146	4
146	5
146	6
146	7
146	8
146	9
146	10
147	1
147	4
147	7
147	8
148	1
148	3
148	5
148	6
148	7
148	8
148	10
149	1
149	2
149	3
149	4
149	5
149	6
149	7
149	8
149	9
149	10
150	1
150	22
150	2
150	23
150	3
150	25
150	4
150	8
150	32
150	9
150	10
151	1
151	3
151	4
151	5
151	8
151	10
152	1
152	2
152	3
152	4
152	5
152	6
152	7
152	8
152	9
152	10
153	1
153	2
153	3
153	4
153	5
153	6
153	7
153	8
153	9
153	10
154	2
154	4
154	8
154	9
155	1
155	2
155	3
155	6
155	8
155	10
156	1
156	2
156	3
156	4
156	5
156	6
156	7
156	8
156	10
157	1
157	2
157	4
157	5
157	7
157	8
158	1
158	22
158	2
158	23
158	3
158	25
158	4
158	26
158	5
158	28
158	6
158	8
158	32
158	9
158	10
159	1
159	2
159	5
159	6
159	7
159	8
160	1
160	22
160	2
160	23
160	3
160	25
160	4
160	26
160	5
160	28
160	6
160	7
160	8
160	32
160	9
160	10
161	1
161	22
161	2
161	23
161	4
161	5
161	28
161	6
161	8
161	32
161	9
162	1
162	22
162	2
162	23
162	3
162	25
162	4
162	26
162	5
162	28
162	6
162	8
162	32
162	9
162	10
163	1
163	22
163	2
163	23
163	3
163	25
163	4
163	26
163	5
163	28
163	6
163	7
163	8
163	32
163	9
163	10
164	1
164	22
164	23
164	25
164	26
164	5
164	28
164	6
164	7
164	8
164	32
164	10
165	1
165	2
165	3
165	4
165	5
165	6
165	7
165	8
165	10
166	1
166	22
166	2
166	23
166	25
166	4
166	5
166	7
166	8
166	32
166	9
167	1
167	22
167	23
167	3
167	25
167	4
167	5
167	28
167	6
167	8
167	32
168	1
168	22
168	23
168	25
168	26
168	5
168	6
168	8
168	32
169	1
169	4
170	2
171	2
171	9
172	1
172	2
172	4
172	7
172	8
173	1
173	2
173	4
173	7
173	8
174	1
174	2
174	3
174	4
174	5
174	6
174	7
174	8
174	9
174	10
175	2
175	3
175	4
175	5
175	6
175	9
175	10
176	1
176	22
176	2
176	23
176	3
176	25
176	4
176	26
176	5
176	28
176	6
176	8
176	32
176	9
176	10
177	1
177	22
177	2
177	23
177	3
177	25
177	4
177	5
177	28
177	6
177	7
177	8
177	32
177	9
177	10
178	1
178	22
178	23
178	25
178	26
178	5
178	6
178	8
178	32
178	10
179	1
179	22
179	23
179	25
179	4
179	8
179	32
180	1
180	3
180	4
180	5
180	6
180	7
180	8
180	10
181	1
181	22
181	2
181	23
181	25
181	4
181	26
181	5
181	6
181	8
181	32
181	9
181	10
182	1
182	2
182	3
182	4
182	5
182	6
182	7
182	8
182	9
182	10
183	1
183	22
183	2
183	23
183	3
183	4
183	28
183	6
183	8
183	32
184	1
184	2
184	3
184	4
184	7
184	8
184	9
184	10
185	1
185	22
185	23
185	3
185	25
185	4
185	26
185	5
185	28
185	6
185	7
185	8
185	32
185	9
185	10
186	1
186	2
186	7
186	8
187	1
187	2
187	3
187	4
187	7
187	8
187	10
188	1
188	2
188	3
188	4
188	5
188	6
188	7
188	8
188	9
188	10
189	1
189	22
189	2
189	23
189	3
189	25
189	4
189	26
189	5
189	28
189	6
189	7
189	8
189	32
189	9
189	10
190	1
190	2
190	7
190	8
191	1
191	2
191	3
191	7
191	8
191	10
192	1
192	2
192	4
192	7
192	8
193	1
193	4
193	7
193	8
194	1
194	2
194	3
194	4
194	5
194	6
194	8
194	10
195	1
195	22
195	2
195	23
195	25
195	26
195	28
195	6
195	7
195	8
195	9
196	1
196	2
196	5
196	6
196	7
196	8
197	1
197	3
197	4
197	5
197	8
197	10
198	1
198	22
198	23
198	25
198	4
198	26
198	5
198	28
198	6
198	8
198	32
199	1
199	2
199	4
199	5
199	6
199	8
200	1
200	22
200	23
200	3
200	25
200	4
200	26
200	5
200	6
200	8
200	32
200	9
200	10
202	1
202	22
202	23
202	3
202	25
202	4
202	5
202	28
202	7
202	8
202	32
203	1
203	22
203	2
203	23
203	25
203	4
203	5
203	7
203	8
203	32
203	9
204	1
204	7
205	1
205	22
205	23
205	3
205	25
205	4
205	26
205	5
205	28
205	6
205	7
205	8
205	32
206	1
206	3
206	4
206	5
206	6
206	8
206	10
207	1
207	2
207	3
207	4
207	5
207	6
207	7
207	8
207	9
207	10
208	1
208	2
208	3
208	4
208	5
208	6
208	7
208	8
208	9
208	10
209	1
209	2
209	3
209	4
209	5
209	6
209	7
209	8
209	9
209	10
211	1
211	2
211	3
211	4
211	5
211	6
211	7
211	8
211	9
211	10
212	1
212	2
212	5
212	7
212	8
213	1
213	2
213	4
213	7
213	8
214	1
214	2
214	3
214	4
214	5
214	6
214	7
214	8
214	10
215	1
215	2
215	3
215	4
215	5
215	6
215	8
215	9
215	10
216	1
216	2
216	3
216	4
216	5
216	6
216	7
216	8
216	9
216	10
217	1
217	2
217	3
217	4
217	5
217	6
217	8
217	10
219	1
219	22
219	2
219	23
219	25
219	6
219	8
219	32
219	9
219	10
220	1
220	22
220	23
220	25
220	4
220	26
220	5
220	28
220	6
220	7
220	8
220	32
221	1
221	22
221	2
221	23
221	3
221	25
221	4
221	26
221	5
221	6
221	8
221	32
222	1
222	2
222	3
222	4
222	5
222	6
222	7
222	8
222	9
222	10
224	1
224	22
224	2
224	23
224	3
224	25
224	4
224	26
224	5
224	28
224	6
224	7
224	8
224	32
224	9
224	10
225	1
225	2
225	8
226	1
226	2
226	4
226	8
227	1
227	2
227	4
227	8
228	2
228	4
229	1
229	22
229	23
229	25
229	6
229	8
229	32
230	1
230	2
230	3
230	4
230	5
230	6
230	8
230	9
230	10
231	1
231	3
231	4
231	5
231	6
231	7
231	8
231	10
232	1
232	2
232	3
232	4
232	5
232	6
232	7
232	8
232	9
232	10
233	1
233	2
233	3
233	4
233	5
233	6
233	7
233	8
233	10
234	1
234	2
234	3
234	4
234	5
234	7
234	8
235	1
235	2
235	3
235	4
235	5
235	6
235	7
235	8
235	9
235	10
236	1
236	23
236	25
236	5
236	6
236	8
236	32
237	1
237	22
237	2
237	23
237	25
237	4
237	5
238	1
238	2
238	4
238	7
238	8
239	1
239	22
239	23
239	4
239	5
239	32
240	2
240	6
240	8
241	1
241	2
241	4
241	5
241	6
241	7
241	8
242	1
242	22
242	23
242	3
242	25
242	4
242	5
242	28
242	6
242	7
242	8
242	32
243	1
243	2
243	3
243	4
243	5
243	6
243	7
243	8
243	9
243	10
244	1
244	2
244	4
244	7
244	8
245	1
245	2
245	4
245	7
245	8
246	1
246	2
246	4
246	8
246	9
246	10
247	1
247	4
247	5
247	7
247	8
248	1
248	3
248	4
248	5
248	6
248	7
248	8
248	10
250	1
250	2
250	4
250	7
250	8
251	1
251	2
251	4
251	7
251	8
252	1
252	2
252	4
252	7
252	8
253	1
253	22
253	2
253	23
253	25
253	4
253	26
253	5
253	7
253	8
253	32
253	9
254	1
254	3
254	8
254	32
254	10
255	1
255	22
255	23
255	25
255	8
255	32
256	1
256	4
256	7
256	8
257	1
257	22
257	2
257	23
257	3
257	25
257	4
257	26
257	5
257	28
257	6
257	7
257	8
257	32
257	9
257	10
258	1
258	2
258	4
258	5
258	6
258	7
259	1
259	2
259	25
259	4
259	5
259	7
259	9
260	1
260	3
260	7
260	8
260	10
261	1
261	22
261	2
261	23
261	3
261	25
261	4
261	5
261	28
261	6
261	8
261	9
261	10
262	1
262	22
262	2
262	23
262	7
262	8
262	32
263	1
263	22
263	2
263	23
263	7
263	8
263	32
264	1
265	1
265	2
265	3
265	4
265	5
265	6
265	8
265	10
266	1
266	22
266	2
266	23
266	3
266	25
266	4
266	26
266	5
266	28
266	6
266	7
266	8
266	32
266	9
266	10
267	1
267	2
267	3
267	4
267	5
267	6
267	7
267	8
267	9
267	10
268	1
268	2
268	3
268	4
268	5
268	6
268	7
268	8
268	9
268	10
269	1
269	22
269	23
269	3
269	25
269	4
269	26
269	5
269	28
269	6
269	8
269	32
269	10
270	1
270	4
270	8
271	1
271	3
271	4
271	5
271	6
271	7
271	8
271	10
272	2
272	8
273	8
274	1
274	2
274	5
274	7
274	8
275	1
275	8
275	32
276	1
276	22
276	23
276	3
276	25
276	4
276	26
276	5
276	28
276	6
276	7
276	8
276	32
276	9
276	10
277	1
277	2
277	4
277	6
277	7
277	8
278	1
278	2
278	3
278	4
278	5
278	6
278	7
278	8
278	9
279	1
279	3
279	4
279	5
279	6
279	7
279	8
279	10
280	1
280	2
280	4
280	5
280	7
280	8
281	1
281	22
281	2
281	23
281	3
281	25
281	4
281	26
281	5
281	6
281	7
281	8
281	32
281	9
281	10
282	1
282	22
282	2
282	23
282	25
282	4
282	26
282	28
282	6
282	7
282	8
282	32
282	9
283	1
283	2
283	3
283	4
283	5
283	6
283	7
283	8
283	9
283	10
284	1
284	3
284	4
284	6
284	7
284	8
284	10
285	1
285	22
285	2
285	23
285	25
285	5
285	7
286	1
286	22
286	23
286	25
286	4
287	1
287	22
287	23
287	25
287	6
288	1
288	2
288	3
288	4
288	5
288	6
288	7
288	8
288	9
288	10
289	1
289	2
289	3
289	4
289	5
289	6
289	7
289	8
289	9
289	10
290	1
290	22
290	2
290	23
290	3
290	25
290	4
290	28
290	8
290	32
290	9
290	10
291	1
291	22
291	2
291	23
291	25
291	5
291	28
291	7
291	9
292	1
292	2
292	4
292	7
292	8
293	1
293	2
293	3
293	4
293	5
293	6
293	7
293	8
293	9
293	10
294	1
294	7
294	8
295	1
295	6
295	7
295	8
296	1
296	32
297	1
297	22
297	23
297	25
297	26
297	6
298	22
298	2
298	23
298	3
298	25
298	4
298	26
298	5
298	28
298	6
298	8
298	32
298	9
298	10
299	1
299	2
299	4
299	5
299	6
299	7
299	8
300	1
300	2
300	3
300	4
300	5
300	6
300	7
300	8
300	10
301	1
301	2
301	4
301	7
301	8
302	1
302	2
302	3
302	4
302	5
302	6
302	7
302	8
302	10
303	1
303	2
303	4
303	7
303	8
304	1
304	2
304	3
304	4
304	7
304	8
304	9
304	10
305	1
305	2
305	3
305	4
305	5
305	6
305	8
305	9
305	10
306	1
306	2
306	4
306	7
306	8
307	1
307	2
307	4
307	8
308	1
308	22
308	2
308	23
308	25
308	4
308	26
308	5
308	28
308	6
308	7
308	8
308	32
308	10
309	1
309	22
309	2
309	23
309	3
309	25
309	4
309	5
309	28
309	6
309	7
309	8
309	32
309	9
309	10
310	1
310	2
310	3
310	4
310	5
310	6
310	7
310	8
310	10
311	1
311	2
311	3
311	4
311	6
311	7
311	8
311	10
312	1
312	22
312	23
312	3
312	25
312	4
312	6
312	8
312	32
312	10
313	1
313	2
313	3
313	4
313	5
313	6
313	8
313	10
314	1
314	22
314	2
314	23
314	25
314	4
314	5
314	28
314	6
314	7
314	8
314	32
314	10
315	1
315	22
315	2
315	23
315	3
315	25
315	4
315	5
315	6
315	8
315	32
315	9
316	1
316	4
316	7
317	1
317	2
317	3
317	4
317	5
317	6
317	7
317	8
317	9
317	10
318	1
318	2
318	3
318	5
318	6
318	8
318	10
319	1
319	2
319	4
319	7
319	8
320	1
320	2
320	4
320	7
320	8
321	1
321	22
321	2
321	23
321	3
321	25
321	4
321	5
321	28
321	6
321	7
321	8
321	32
321	9
321	10
322	1
322	2
322	3
322	4
322	5
322	6
322	7
322	8
322	9
322	10
323	8
324	1
324	2
324	8
325	1
325	2
325	7
325	8
326	1
326	22
326	2
326	23
326	3
326	25
326	4
326	5
326	28
326	6
326	8
326	32
326	9
326	10
327	1
327	22
327	2
327	23
327	3
327	25
327	4
327	5
327	28
327	6
327	8
327	32
327	9
327	10
328	1
329	1
329	8
330	1
330	4
330	7
331	1
331	22
331	2
331	23
331	3
331	25
331	4
331	26
331	5
331	28
331	6
331	7
331	8
331	32
331	9
331	10
332	1
332	22
332	23
332	25
332	26
332	6
332	8
332	32
332	9
333	1
333	22
333	23
333	3
333	25
333	4
333	26
333	5
333	28
333	6
333	7
333	8
333	32
333	10
334	1
334	2
334	4
334	5
334	6
334	7
334	8
334	10
335	1
335	2
335	4
335	5
335	7
336	2
337	2
337	4
337	9
338	1
338	22
338	23
338	25
338	32
339	1
339	22
339	23
339	25
339	4
339	26
339	28
339	6
339	7
339	8
339	32
340	1
340	22
340	2
340	23
340	3
340	25
340	4
340	26
340	5
340	28
340	6
340	7
340	8
340	32
340	9
340	10
341	1
341	2
341	3
341	4
341	5
341	6
341	7
341	8
341	9
341	10
342	1
342	2
342	3
342	4
342	5
342	6
342	7
342	8
342	9
342	10
343	1
343	2
343	3
343	4
343	9
343	10
344	1
344	22
344	23
344	3
344	25
344	4
344	8
344	32
344	10
345	2
345	4
346	1
346	2
346	3
346	4
346	5
346	6
346	7
346	8
346	9
346	10
347	1
347	3
347	4
347	5
347	6
347	7
347	8
347	10
348	1
348	2
348	3
348	4
348	5
348	6
348	7
348	8
348	9
348	10
349	1
349	2
349	4
349	7
349	8
350	1
350	2
350	3
350	4
350	5
350	6
350	7
350	8
350	9
350	10
351	1
351	2
351	4
351	8
352	1
352	4
352	8
353	1
353	3
353	5
353	6
353	7
353	8
353	10
354	1
354	2
354	3
354	4
354	5
354	6
354	7
354	8
354	32
354	10
356	1
357	1
357	22
357	23
357	3
357	25
357	4
357	26
357	5
357	28
357	6
357	32
358	1
358	22
358	23
358	25
358	4
358	26
358	6
358	8
358	32
359	1
359	4
359	6
359	7
359	8
359	10
361	1
361	2
361	3
361	5
361	6
361	7
361	8
361	10
362	1
362	2
362	3
362	4
362	5
362	6
362	8
362	9
362	10
364	1
364	22
364	23
364	3
364	25
364	4
364	26
364	5
364	6
364	8
364	32
364	9
365	1
365	22
365	2
365	23
365	3
365	25
365	4
365	8
365	32
365	9
366	1
366	2
366	4
366	7
366	8
367	1
367	2
367	3
367	4
367	5
367	6
367	7
367	8
367	9
367	10
368	1
368	2
368	4
368	7
368	8
369	1
369	3
369	4
369	7
369	8
369	10
370	1
370	22
370	2
370	23
370	3
370	25
370	4
370	5
370	6
370	7
370	8
370	32
370	9
370	10
371	1
371	3
371	4
371	5
371	7
371	8
371	10
372	1
372	22
372	23
372	3
372	25
372	4
372	5
372	28
372	6
372	7
372	8
372	32
372	10
373	1
373	22
373	23
373	25
373	4
373	28
373	8
374	1
374	22
374	23
374	3
374	25
374	6
374	8
374	32
374	10
375	1
375	2
375	3
375	4
375	5
375	6
375	7
375	8
375	9
375	10
376	1
376	22
376	2
376	23
376	25
376	4
376	26
376	5
376	6
376	7
376	8
376	32
376	9
376	10
377	1
377	2
377	8
378	1
378	2
378	3
378	4
378	5
378	6
378	7
378	8
378	9
378	10
379	1
379	22
379	23
379	3
379	25
379	4
379	26
379	5
379	28
379	6
379	7
379	8
379	32
379	10
381	1
381	2
381	3
381	4
381	5
381	6
381	8
382	1
382	22
382	23
382	25
382	28
382	6
382	7
382	8
382	32
383	1
383	22
383	23
383	25
383	4
383	6
383	8
383	32
383	10
384	1
384	2
384	3
384	4
384	6
384	7
384	8
384	9
384	10
385	1
385	2
385	4
385	5
385	7
385	8
385	10
386	1
386	2
386	3
386	4
386	5
386	6
386	7
386	8
386	9
386	10
388	4
388	7
389	1
389	2
389	3
389	4
389	5
389	6
389	7
389	8
389	9
389	10
390	1
390	2
390	4
390	8
390	10
391	1
391	2
391	3
391	4
391	5
391	6
391	8
391	10
392	1
392	2
392	4
393	1
393	2
393	4
393	7
393	8
394	1
394	2
394	3
394	4
394	5
394	6
394	8
394	10
395	1
395	2
395	3
395	5
395	6
395	7
395	8
395	10
396	1
396	22
396	2
396	23
396	25
396	4
396	26
396	5
396	6
396	8
396	32
396	10
397	1
397	2
397	8
398	1
398	2
398	4
398	5
398	8
399	1
400	1
400	22
400	2
400	23
400	3
400	25
400	4
400	5
400	28
400	6
400	7
400	32
400	9
400	10
401	4
401	8
402	1
402	22
402	2
402	23
402	25
402	4
402	6
402	8
402	32
402	9
403	1
403	2
403	3
403	4
403	5
403	6
403	7
403	8
403	9
403	10
404	1
404	22
404	23
404	25
404	5
404	8
404	32
405	1
405	3
405	5
405	6
405	7
405	8
405	10
406	1
406	22
406	2
406	23
406	26
406	6
406	8
407	1
407	2
407	5
407	6
407	8
407	9
408	22
408	23
408	3
408	25
408	5
408	28
408	6
408	8
408	32
408	10
409	1
410	1
410	2
410	3
410	4
410	5
410	6
410	8
410	10
411	1
411	2
411	4
411	7
411	8
412	1
412	2
412	3
412	4
412	5
412	6
412	7
412	8
412	9
412	10
413	1
413	22
413	2
413	23
413	3
413	25
413	4
413	28
413	6
413	8
413	32
413	9
414	1
414	22
414	23
414	3
414	25
414	4
414	5
414	28
414	8
414	32
414	9
414	10
415	2
416	1
416	22
416	2
416	23
416	3
416	25
416	4
416	26
416	5
416	28
416	6
416	7
416	8
416	32
416	9
416	10
417	1
417	22
417	23
417	3
417	25
417	4
417	26
417	5
417	28
417	7
417	8
417	32
417	9
417	10
418	1
418	2
418	3
418	4
418	5
418	6
418	7
418	8
418	9
418	10
419	1
419	22
419	2
419	23
419	3
419	25
419	4
419	5
419	6
419	7
419	8
419	32
419	9
419	10
420	1
420	22
420	23
420	3
420	25
420	4
420	26
420	5
420	28
420	6
420	8
420	32
420	10
421	1
421	4
421	8
422	1
422	2
422	4
422	5
422	8
422	9
423	1
423	3
423	4
423	5
423	6
423	7
423	8
423	10
424	1
424	4
424	5
424	6
424	7
425	1
425	22
425	2
425	23
425	3
425	25
425	4
425	5
425	6
425	7
425	8
425	32
425	9
425	10
426	1
426	3
426	4
426	5
426	6
426	7
426	8
426	10
427	1
427	2
427	3
427	5
427	6
427	7
427	8
427	10
428	1
428	3
428	4
428	5
428	6
428	7
428	8
428	10
429	1
429	2
429	3
429	4
429	6
429	7
429	8
429	10
430	1
430	5
430	6
430	7
430	8
431	1
431	22
431	23
431	25
431	4
431	26
431	5
431	28
431	6
431	8
431	32
431	9
431	10
432	1
432	2
432	3
432	4
432	5
432	6
432	7
432	8
432	9
432	10
433	1
433	2
433	3
433	4
433	5
433	6
433	8
433	10
434	1
434	22
434	23
434	25
434	4
434	5
434	8
434	32
435	1
435	22
435	2
435	23
435	25
435	4
435	28
435	7
435	8
435	32
435	9
436	1
436	22
436	2
436	23
436	25
436	4
436	26
436	5
436	28
436	6
436	7
436	8
436	32
436	9
436	10
437	1
437	6
437	7
437	8
438	1
438	2
438	3
438	4
438	5
438	6
438	7
438	8
438	9
438	10
439	1
439	2
439	5
439	7
439	8
440	1
440	2
440	3
440	4
440	5
440	6
440	7
440	8
440	9
440	10
441	1
441	4
442	1
442	22
442	2
442	23
442	3
442	25
442	4
442	5
442	28
442	6
442	7
442	8
442	32
442	9
443	1
443	22
443	23
443	3
443	25
443	4
443	8
443	32
443	9
443	10
444	1
444	2
444	3
444	4
444	5
444	6
444	7
444	8
444	9
444	10
445	1
445	4
445	5
445	7
445	8
445	10
446	1
446	22
446	23
446	25
446	6
446	8
446	32
447	1
447	2
447	3
447	4
447	5
447	6
447	7
447	8
447	9
447	10
448	1
448	2
448	3
448	4
448	8
448	9
449	2
449	4
449	8
450	1
450	2
450	3
450	5
450	6
450	7
450	8
451	1
451	22
451	25
451	26
452	1
452	22
452	23
452	25
452	5
452	28
452	6
452	7
452	8
452	32
452	10
453	1
453	22
453	23
453	25
453	4
453	5
453	28
453	7
453	8
453	32
454	1
454	22
454	2
454	23
454	3
454	25
454	4
454	26
454	5
454	28
454	6
454	7
454	8
454	32
454	9
454	10
455	1
455	2
455	4
455	5
455	6
455	7
455	8
456	1
456	2
456	4
456	7
456	8
456	9
457	1
457	4
457	6
457	7
457	8
457	10
458	1
458	2
458	7
458	8
459	1
459	2
459	4
459	5
459	7
459	8
459	10
460	1
460	2
460	4
460	7
460	8
461	1
461	22
461	23
461	3
461	25
461	26
461	5
461	28
461	6
461	7
461	32
462	1
462	4
462	7
462	8
463	1
463	22
463	23
463	25
463	4
463	26
463	5
463	6
464	1
464	4
464	26
464	5
464	32
466	1
466	2
466	4
466	8
467	1
467	3
467	4
467	5
467	6
467	7
467	8
468	1
468	2
468	4
468	7
468	8
469	1
469	2
469	4
469	7
469	8
470	1
470	22
470	23
470	3
470	25
470	4
470	26
470	5
470	28
470	6
470	7
470	8
470	32
470	10
471	1
471	8
471	10
472	2
473	1
473	2
473	3
473	4
473	5
473	6
473	7
473	8
473	10
474	1
474	22
474	2
474	23
474	3
474	25
474	4
474	6
474	8
474	32
474	9
474	10
475	1
475	22
475	23
475	25
475	6
475	8
475	32
476	1
476	22
476	2
476	23
476	25
476	4
476	26
476	6
476	8
476	32
476	9
476	10
477	1
477	8
478	1
478	2
478	4
478	5
478	8
479	1
479	2
479	4
479	8
480	1
480	2
480	3
480	4
480	5
480	6
480	7
480	8
480	9
480	10
481	1
481	22
481	23
481	25
481	4
481	5
481	6
481	8
481	32
481	9
482	1
482	22
482	23
482	25
482	4
482	26
482	5
482	6
482	8
482	32
483	1
483	22
483	2
483	23
483	3
483	25
483	4
483	26
483	5
483	28
483	6
483	8
483	32
483	10
484	1
484	2
484	4
484	6
484	8
484	10
485	1
485	25
485	26
485	5
485	6
485	7
486	1
486	22
486	2
486	23
486	3
486	25
486	4
486	5
486	7
486	8
486	32
486	9
487	1
487	2
487	3
487	4
487	5
487	6
487	7
487	8
487	9
487	10
488	1
488	2
488	3
488	4
488	5
488	6
488	7
488	8
488	9
488	10
489	1
489	2
489	7
489	8
490	1
490	2
490	4
490	7
490	8
490	9
491	2
491	3
491	8
491	9
493	2
494	1
494	22
494	2
494	23
494	25
494	4
494	5
494	6
494	32
495	1
495	22
495	23
495	25
495	4
495	26
495	5
495	6
495	8
499	1
499	22
499	23
499	3
499	25
499	26
499	5
499	28
499	6
499	7
499	8
499	32
499	10
500	1
500	2
500	3
500	4
500	7
500	8
500	9
500	10
501	1
501	3
501	4
501	6
501	7
501	8
501	10
502	1
502	2
502	3
502	4
502	5
502	6
502	7
502	8
502	9
502	10
503	1
503	2
503	3
503	4
503	5
503	6
503	7
503	8
503	9
503	10
504	1
504	22
504	2
504	23
504	3
504	25
504	4
504	26
504	5
504	28
504	6
504	7
504	8
504	32
504	9
504	10
505	1
505	2
505	3
505	4
505	6
505	8
505	9
505	10
506	1
506	2
506	3
506	4
506	7
506	8
506	10
507	1
507	2
507	3
507	4
507	5
507	6
507	7
507	8
507	9
507	10
508	2
508	3
508	4
508	5
508	6
508	8
508	9
508	10
509	1
509	22
509	23
509	3
509	4
509	6
509	8
509	32
509	10
510	1
510	2
510	3
510	4
510	5
510	6
510	7
510	8
510	9
510	10
511	1
511	22
511	23
511	25
511	26
511	5
511	6
511	8
511	32
512	1
512	2
512	3
512	4
512	5
512	6
512	8
512	9
513	1
513	2
513	3
513	4
513	5
513	6
513	7
513	8
513	9
513	10
514	1
514	22
514	23
514	25
514	28
514	6
514	8
514	32
515	1
515	2
515	3
515	4
515	6
515	7
515	8
515	10
516	1
516	22
516	2
516	23
516	3
516	25
516	4
516	26
516	5
516	28
516	6
516	7
516	8
516	32
516	9
516	10
517	1
517	22
517	2
517	23
517	3
517	25
517	4
517	26
517	5
517	28
517	6
517	7
517	8
517	32
517	9
517	10
518	1
518	22
518	2
518	23
518	3
518	25
518	4
518	28
518	6
518	7
518	8
518	32
518	9
519	1
519	4
519	7
519	8
520	1
520	3
520	8
520	10
521	1
521	2
521	23
521	26
521	5
521	6
521	7
521	8
521	32
521	10
522	1
522	2
522	3
522	4
522	5
522	6
522	7
522	8
522	9
522	10
523	1
523	2
523	4
523	7
523	8
524	1
524	2
524	3
524	4
524	5
524	6
524	7
524	8
524	9
524	10
525	1
525	2
525	3
525	4
525	5
525	6
525	7
525	8
525	9
525	10
526	1
526	2
526	3
526	4
526	5
526	6
526	7
526	8
526	9
526	10
527	1
527	2
527	4
527	7
527	8
529	1
529	2
529	4
529	6
529	8
529	9
529	10
530	1
530	2
530	3
530	4
530	5
530	6
530	7
530	8
530	9
530	10
531	1
531	3
531	4
531	5
531	6
531	8
531	10
532	1
532	3
532	4
532	5
532	6
532	8
532	10
533	1
533	2
533	4
533	7
533	8
534	1
534	2
534	4
534	7
534	8
535	1
535	2
535	3
535	4
535	5
535	6
535	7
535	8
535	9
535	10
536	1
536	2
536	3
536	4
536	5
536	6
536	7
536	8
536	9
536	10
537	1
537	2
537	4
537	7
537	8
538	4
538	7
538	8
540	1
540	2
540	4
540	7
540	8
541	1
541	2
541	4
541	7
541	8
543	1
543	23
543	26
543	5
543	6
543	7
544	1
544	2
544	4
544	7
544	8
545	1
545	22
545	2
545	23
545	25
545	4
545	5
545	28
545	6
545	7
546	1
546	2
546	3
546	4
546	5
546	6
546	7
546	8
546	9
546	10
547	1
547	2
547	4
547	7
547	8
548	1
548	2
548	3
548	4
548	5
548	6
548	7
548	8
548	9
548	10
549	1
549	2
549	3
549	4
549	5
549	6
549	7
549	8
549	9
549	10
550	1
550	22
550	23
550	3
550	25
550	4
550	6
550	8
550	32
550	10
551	1
551	4
551	6
551	7
551	8
551	10
552	2
552	4
553	1
553	2
553	3
553	4
553	5
553	6
553	8
553	9
553	10
554	1
554	2
554	4
554	5
554	6
554	7
554	8
554	9
554	10
555	1
555	8
556	1
556	22
556	23
556	25
556	4
556	26
556	5
556	28
556	6
556	7
556	8
556	32
557	1
557	22
557	23
557	25
557	4
557	26
557	5
557	28
557	6
557	7
557	8
557	32
558	1
558	2
558	3
558	4
558	5
558	6
558	7
558	8
558	9
558	10
559	1
559	2
559	3
559	4
559	5
559	6
559	7
559	8
559	9
559	10
560	1
560	4
560	8
561	1
561	2
561	3
561	4
561	5
561	6
561	7
561	8
561	9
561	10
562	1
562	22
562	23
562	25
562	6
562	8
562	32
562	10
563	1
563	2
563	4
563	7
563	8
564	1
564	22
564	2
564	23
564	3
564	25
564	4
564	26
564	5
564	28
564	6
564	7
564	8
564	32
564	9
564	10
565	1
565	2
565	3
565	4
565	5
565	6
565	7
565	8
565	10
566	1
566	2
566	4
566	7
566	8
567	1
567	2
567	3
567	4
567	5
567	6
567	7
567	8
567	9
567	10
568	1
568	4
568	8
569	1
569	2
569	3
569	4
569	5
569	6
569	7
569	8
569	9
570	2
570	4
570	8
570	9
571	1
571	22
571	2
571	23
571	25
571	4
571	26
571	5
571	6
571	10
572	1
572	22
572	23
572	3
572	25
572	5
572	28
572	6
572	7
572	8
572	32
572	10
573	1
573	2
573	3
573	4
573	7
573	8
574	1
574	2
574	3
574	4
574	5
574	6
574	7
574	8
574	9
574	10
575	1
575	4
575	8
575	10
576	1
576	2
576	4
576	7
576	8
578	1
578	2
578	3
578	8
578	9
578	10
579	1
579	22
579	23
579	25
579	4
579	5
579	28
579	7
579	8
579	32
580	1
580	22
580	23
580	3
580	25
580	4
580	26
580	5
580	28
580	6
580	8
580	32
580	10
581	1
581	3
581	4
581	5
581	6
581	7
581	8
581	10
582	1
582	2
582	4
582	7
582	8
583	1
583	2
583	8
584	1
584	2
584	4
584	7
584	8
585	1
585	2
585	3
585	4
585	5
585	6
585	7
585	8
585	9
585	10
586	1
586	2
586	3
586	4
586	5
586	6
586	7
586	8
586	9
586	10
587	1
587	2
587	3
587	4
587	5
587	6
587	7
587	8
587	9
587	10
588	1
588	2
588	3
588	4
588	5
588	6
588	7
588	8
588	9
588	10
589	1
589	22
589	23
589	3
589	4
589	26
589	5
589	28
589	6
589	7
589	8
589	32
589	10
590	1
590	2
590	3
590	4
590	5
590	6
590	8
590	9
590	10
591	1
591	22
591	2
591	23
591	25
591	4
591	5
591	7
591	8
591	32
592	1
592	2
592	4
592	5
592	6
592	7
592	8
592	10
593	1
593	2
593	3
593	4
593	5
593	6
593	7
593	8
593	10
594	1
594	22
594	2
594	23
594	25
594	26
594	5
594	6
594	8
594	32
594	9
595	2
595	4
595	5
595	8
596	1
596	3
596	4
596	5
596	6
596	7
596	8
596	10
597	1
597	2
597	3
597	4
597	5
597	6
597	7
597	8
597	9
597	10
598	1
598	2
598	3
598	4
598	5
598	6
598	7
598	8
598	10
599	1
599	2
599	23
599	25
599	4
599	5
599	28
599	6
599	8
599	32
599	9
599	10
600	1
600	4
600	5
600	6
600	8
601	1
601	22
601	2
601	23
601	3
601	25
601	4
601	5
601	28
601	6
601	7
601	8
601	32
601	9
601	10
602	1
602	2
602	4
602	7
602	8
603	1
603	22
603	2
603	23
603	25
603	4
603	28
603	7
603	8
603	32
603	9
604	1
604	4
605	1
605	2
605	3
605	4
605	5
605	6
605	7
605	8
605	9
605	10
606	1
606	2
606	4
606	7
606	8
607	1
607	2
607	4
607	7
607	8
608	1
608	22
608	2
608	23
608	3
608	25
608	4
608	26
608	28
608	6
608	8
608	32
608	9
609	1
609	2
609	3
609	4
609	5
609	6
609	7
609	8
609	10
610	1
610	2
610	4
610	5
610	6
610	8
610	9
612	1
612	4
612	5
612	6
612	7
612	8
612	10
613	1
613	7
613	8
614	1
614	3
614	4
614	5
614	6
614	7
614	8
614	10
615	1
615	2
615	4
615	7
615	8
616	1
616	2
616	4
616	6
616	7
616	8
617	1
617	2
617	4
617	8
618	1
618	2
618	3
618	4
618	5
618	6
618	8
618	10
619	1
619	2
619	3
619	4
619	5
619	6
619	8
619	10
620	1
620	2
620	3
620	4
620	5
620	6
620	8
620	10
621	1
621	2
621	4
621	8
622	1
622	22
622	23
622	3
622	25
622	4
622	26
622	5
622	6
622	8
622	32
622	10
623	1
623	2
623	4
623	5
623	8
623	10
625	1
625	2
625	4
625	7
625	8
626	1
626	22
626	23
626	3
626	25
626	4
626	26
626	5
626	28
626	6
626	7
626	8
626	32
626	9
626	10
627	1
627	2
627	3
627	4
627	5
627	6
627	7
627	8
627	9
627	10
628	1
628	2
628	3
628	4
628	5
628	6
628	7
628	8
628	9
628	10
629	1
629	3
629	4
629	5
629	6
629	7
629	8
629	10
630	1
630	4
630	7
630	8
631	1
631	2
631	3
631	4
631	5
631	6
631	7
631	8
631	9
631	10
632	1
632	2
632	3
632	4
632	5
632	6
632	7
632	8
632	9
632	10
633	2
633	3
633	4
633	5
633	6
633	8
633	9
633	10
634	1
634	22
634	23
634	8
634	32
635	1
635	22
635	23
635	25
635	4
635	5
635	6
635	7
635	8
635	32
635	9
636	1
636	2
636	4
636	7
636	8
637	1
637	22
637	2
637	23
637	25
637	4
637	26
637	5
637	6
637	7
637	8
637	32
638	1
638	22
638	2
638	23
638	25
638	26
638	5
638	28
638	6
638	7
638	8
638	32
639	1
639	2
639	4
639	7
639	8
640	1
640	22
640	2
640	23
640	3
640	25
640	4
640	5
640	28
640	6
640	7
640	8
640	32
640	9
640	10
641	1
641	2
641	4
641	5
641	7
641	8
641	10
642	1
642	2
642	4
642	7
642	8
643	1
643	2
643	3
643	4
643	5
643	6
643	7
643	8
643	9
643	10
644	1
644	2
644	3
644	4
644	5
644	6
644	7
644	8
644	9
644	10
645	1
645	2
645	3
645	4
645	5
645	6
645	7
645	8
645	9
645	10
646	1
646	2
646	3
646	4
646	6
646	7
646	8
646	9
646	10
647	1
647	2
647	4
647	8
648	1
648	3
648	4
648	5
648	6
648	7
648	8
648	10
649	1
649	22
649	23
649	3
649	25
649	4
649	26
649	5
649	28
649	6
649	7
649	8
649	32
649	10
650	1
650	3
650	4
650	5
650	6
650	7
650	8
650	10
651	1
651	22
651	2
651	23
651	25
651	26
651	5
651	28
651	6
651	7
651	32
651	9
652	1
652	2
652	3
652	4
652	5
652	6
652	8
652	9
653	1
653	3
653	4
653	5
653	6
653	7
653	8
653	10
654	1
654	2
654	4
654	7
654	8
655	1
655	22
655	23
655	25
655	4
655	26
655	5
655	28
655	6
655	7
655	8
655	32
655	10
656	1
656	22
656	2
656	23
656	3
656	25
656	4
656	26
656	5
656	28
656	6
656	7
656	8
656	32
656	9
656	10
657	1
657	22
657	2
657	23
657	3
657	25
657	4
657	6
657	8
657	32
657	9
657	10
658	2
659	2
659	4
660	1
661	1
661	2
661	4
661	5
661	7
661	8
662	1
662	2
662	3
662	4
662	5
662	6
662	7
662	8
662	9
662	10
663	1
663	2
663	3
663	4
663	5
663	6
663	7
663	8
663	9
663	10
664	2
664	9
665	1
665	22
665	23
665	25
665	26
665	5
665	28
665	6
665	8
665	32
666	1
666	4
666	7
666	8
667	1
667	4
667	8
668	1
668	3
668	4
668	5
668	6
668	7
668	8
668	10
669	1
669	2
669	3
669	4
669	5
669	6
669	7
669	8
669	9
669	10
670	1
670	2
670	3
670	4
670	5
670	6
670	7
670	8
670	9
670	10
671	1
671	22
671	2
671	23
671	25
671	4
671	5
671	8
671	9
672	1
672	22
672	23
672	25
672	8
672	32
673	1
673	2
673	4
673	7
673	8
674	1
674	2
674	3
674	4
674	8
674	32
674	9
674	10
675	22
675	23
675	3
675	25
675	4
675	26
675	6
675	8
675	32
675	10
676	1
676	4
676	7
676	8
677	1
677	2
677	4
677	7
677	8
677	10
678	1
678	2
678	3
678	4
678	6
678	7
678	8
678	9
678	10
679	1
679	22
679	23
679	26
679	5
679	28
679	6
679	7
679	10
681	1
681	22
681	23
681	25
681	4
681	26
681	6
681	8
681	32
683	1
683	3
683	4
683	5
683	6
683	7
683	8
683	10
684	1
684	2
684	5
684	6
684	7
684	8
685	1
685	2
685	4
685	5
685	6
685	8
686	1
686	2
686	3
686	4
686	5
686	6
686	7
686	8
686	9
686	10
688	1
688	2
688	3
688	4
688	5
688	6
688	7
688	8
688	9
688	10
689	1
689	22
689	2
689	23
689	3
689	25
689	4
689	26
689	5
689	28
689	6
689	7
689	8
689	32
689	9
689	10
690	1
690	5
690	6
690	7
690	8
691	1
691	22
691	23
691	3
691	25
691	26
691	5
691	28
691	6
691	7
691	8
691	32
691	10
692	1
692	2
692	3
692	4
692	5
692	6
692	7
692	8
692	10
693	1
693	2
693	3
693	4
693	5
693	6
693	7
693	8
693	9
693	10
694	1
694	2
694	3
694	4
694	5
694	6
694	7
694	8
694	10
695	1
695	2
695	4
695	6
695	8
695	10
696	1
696	2
696	3
696	4
696	5
696	6
696	7
696	8
696	9
696	10
697	1
697	2
697	4
697	6
697	8
697	10
698	1
698	2
698	3
698	4
698	5
698	6
698	7
698	8
698	9
698	10
699	1
699	2
699	3
699	4
699	5
699	6
699	7
699	8
700	1
700	2
700	3
700	4
700	5
700	6
700	7
700	8
700	10
701	1
701	22
701	2
701	23
701	25
701	4
701	26
701	5
701	6
701	8
701	32
701	9
701	10
702	1
702	22
702	2
702	23
702	25
702	8
703	1
703	2
703	4
703	5
703	6
703	8
704	1
704	2
704	8
705	1
705	22
705	2
705	23
705	3
705	25
705	4
705	26
705	5
705	28
705	6
705	7
705	8
705	32
705	9
705	10
706	2
706	4
706	9
707	1
707	22
707	23
707	3
707	25
707	4
707	26
707	5
707	6
707	8
707	32
707	9
707	10
708	1
708	2
708	3
708	4
708	5
708	6
708	8
708	10
710	1
710	4
711	1
711	2
711	3
711	4
711	5
711	6
711	8
711	10
712	1
712	2
712	4
713	1
713	2
713	3
713	4
713	5
713	6
713	7
713	8
713	9
713	10
714	1
714	22
714	23
714	25
714	4
714	5
714	28
714	6
714	7
714	8
714	32
714	10
715	1
715	2
715	3
715	4
715	5
715	6
715	7
715	8
715	9
715	10
716	1
716	2
716	3
716	8
716	10
717	1
717	22
717	23
717	25
717	4
717	8
717	32
718	1
718	22
718	2
718	23
718	25
718	4
718	5
718	6
718	8
718	32
718	9
719	2
720	1
720	2
720	3
720	4
720	5
720	6
720	7
720	8
720	10
721	1
721	2
721	3
721	4
721	5
721	6
721	7
721	8
721	9
721	10
722	4
723	1
723	3
723	5
723	6
723	7
723	8
723	10
724	1
724	2
724	4
724	7
724	8
725	1
725	22
725	23
725	3
725	25
725	4
725	26
725	5
725	6
725	7
725	8
725	32
725	10
726	1
726	2
726	4
726	8
727	1
727	4
727	6
727	8
728	1
728	2
728	4
728	8
729	2
729	9
730	1
730	3
730	5
730	6
730	7
730	8
730	10
731	1
731	2
731	3
731	4
731	6
731	8
731	9
731	10
732	1
732	6
732	7
732	8
732	10
733	1
733	2
733	4
733	7
733	8
734	1
734	2
734	3
734	4
734	5
734	6
734	7
734	8
734	10
735	1
735	2
735	3
735	4
735	5
735	6
735	7
735	8
735	10
736	1
736	22
736	2
736	23
736	3
736	25
736	26
736	5
736	28
736	6
736	7
736	8
736	32
736	9
736	10
737	1
737	2
737	4
737	8
738	1
738	2
738	4
738	7
738	8
739	1
739	22
739	2
739	23
739	3
739	25
739	4
739	28
739	8
739	32
739	9
739	10
740	1
740	2
740	3
740	4
740	7
740	8
740	9
740	10
741	1
741	2
741	4
741	7
741	8
742	1
742	2
742	4
742	7
742	8
743	1
743	2
743	3
743	4
743	5
743	6
743	7
743	8
743	9
743	10
744	1
744	2
744	3
744	4
744	5
744	6
744	7
744	8
744	9
744	10
745	1
745	22
745	2
745	23
745	3
745	25
745	4
745	26
745	28
745	6
745	8
745	32
745	9
745	10
746	1
746	2
746	3
746	8
747	2
747	4
748	1
748	2
748	4
748	7
748	8
749	1
749	2
749	3
749	4
749	5
749	6
749	7
749	8
749	10
750	1
750	2
750	3
750	4
750	5
750	6
750	7
750	8
750	9
750	10
751	1
751	2
751	3
751	4
751	5
751	6
751	8
751	9
751	10
752	1
752	22
752	2
752	23
752	3
752	25
752	4
752	26
752	7
752	8
752	32
752	9
752	10
753	1
753	22
753	23
753	3
753	25
753	4
753	26
753	28
753	6
753	8
753	32
753	9
753	10
754	1
754	4
754	5
754	7
755	1
755	2
755	4
755	7
755	8
756	1
756	2
756	3
756	4
756	5
756	6
756	8
756	10
757	1
757	2
757	3
757	4
757	6
757	7
757	8
757	9
757	10
758	1
758	2
758	4
758	7
758	8
759	1
759	22
759	23
759	25
759	26
759	6
760	1
760	22
760	23
760	3
760	25
760	4
760	26
760	5
760	28
760	6
760	7
760	8
760	32
760	10
761	1
761	2
761	3
761	4
761	5
761	6
761	7
761	8
761	9
761	10
762	1
762	2
762	3
762	4
762	5
762	6
762	7
762	8
762	9
762	10
763	1
763	22
763	23
763	25
763	4
763	26
763	28
763	6
763	8
763	32
764	1
764	22
764	2
764	23
764	3
764	25
764	4
764	26
764	5
764	28
764	6
764	8
764	32
764	10
765	1
765	22
765	23
765	25
765	4
765	26
765	5
765	8
765	32
765	9
766	1
766	2
766	3
766	4
766	5
766	6
766	7
766	8
766	10
767	1
767	2
767	3
767	4
767	5
767	6
767	7
767	8
767	9
767	10
768	8
769	1
769	22
769	23
769	3
769	25
769	28
769	6
769	7
769	32
770	1
770	4
770	8
771	1
771	2
771	4
771	6
771	8
772	1
772	22
772	23
772	25
772	4
772	26
772	5
772	28
772	6
772	7
772	8
772	32
773	1
773	2
773	4
773	7
773	8
774	1
774	4
775	1
775	22
775	2
775	23
775	3
775	25
775	4
775	26
775	5
775	28
775	6
775	7
775	8
775	32
775	9
775	10
776	1
776	2
776	3
776	5
776	6
776	8
776	10
777	1
777	2
777	3
777	4
777	5
777	6
777	7
777	8
777	9
777	10
778	1
778	3
778	5
778	6
778	7
778	8
779	1
779	22
779	2
779	23
779	25
779	5
779	6
779	7
779	8
779	32
779	10
780	1
780	4
780	8
781	1
781	2
781	4
781	7
781	8
782	1
782	2
782	4
782	7
782	8
783	1
783	5
783	7
783	8
784	1
784	2
784	4
784	7
784	8
785	1
785	22
785	2
785	23
785	3
785	25
785	4
785	26
785	5
785	28
785	6
785	7
785	8
785	32
785	9
785	10
786	1
786	2
786	3
786	4
786	5
786	6
786	7
786	8
786	9
786	10
787	1
787	3
787	4
787	5
787	6
787	7
787	8
787	10
788	1
788	2
788	4
788	7
788	8
789	1
789	2
789	3
789	4
789	5
789	6
789	7
789	8
789	9
789	10
790	1
790	22
790	2
790	23
790	25
790	4
790	26
790	6
790	8
790	32
791	1
791	2
791	3
791	4
791	5
791	6
791	7
791	8
791	9
791	10
792	1
792	2
792	4
792	7
792	8
793	1
793	5
793	6
793	7
793	8
795	1
795	22
795	2
795	23
795	3
795	25
795	4
795	26
795	5
795	28
795	6
795	7
795	8
795	32
795	9
795	10
796	1
796	2
796	3
796	4
796	5
796	6
796	7
796	8
796	9
796	10
799	1
799	2
799	3
799	4
799	5
799	6
799	7
799	8
799	9
799	10
800	1
800	22
800	2
800	23
800	3
800	25
800	4
800	26
800	5
800	28
800	6
800	7
800	8
800	32
800	9
800	10
801	1
801	22
801	2
801	23
801	3
801	25
801	4
801	26
801	5
801	6
801	7
801	8
801	32
801	9
801	10
802	1
802	22
802	23
802	25
802	4
802	26
802	5
802	6
802	8
802	32
803	1
803	3
803	4
803	7
804	1
804	3
804	4
804	7
805	1
805	2
805	3
805	4
805	5
805	6
805	7
805	8
805	9
805	10
806	1
806	22
806	2
806	23
806	28
807	2
808	1
808	2
808	4
808	5
808	8
808	9
808	10
809	1
809	2
809	4
809	7
809	8
810	1
810	22
810	23
810	3
810	25
810	4
810	5
810	6
810	7
810	8
810	32
811	1
811	4
811	5
811	6
811	7
811	8
812	1
812	2
812	8
813	1
813	7
813	8
814	1
814	2
814	3
814	4
814	6
814	7
814	8
814	9
814	10
815	1
815	2
815	3
815	4
815	5
815	6
815	7
815	8
815	9
815	10
816	1
816	2
816	4
816	7
816	8
817	1
817	2
817	23
817	4
817	26
817	5
817	6
817	7
817	8
817	32
818	1
818	2
818	4
818	5
818	6
818	8
818	10
819	2
819	3
819	4
819	5
819	8
819	9
819	10
820	1
820	2
820	3
820	4
820	5
820	6
820	7
820	8
820	9
820	10
821	1
821	2
821	3
821	4
821	5
821	6
821	7
821	8
821	9
821	10
822	1
822	4
822	8
823	1
823	2
823	3
823	4
823	5
823	6
823	7
823	8
823	9
823	10
824	1
824	2
824	3
824	4
824	6
824	7
824	8
824	10
825	1
825	2
825	3
825	4
825	5
825	6
825	7
825	8
825	9
825	10
826	1
826	22
826	23
826	3
826	25
826	28
826	6
826	8
826	32
826	9
827	1
827	4
827	8
829	1
830	1
830	2
830	4
830	7
830	8
831	1
831	2
831	4
831	7
831	8
832	1
832	2
832	3
832	4
832	6
832	7
832	8
833	1
833	2
833	7
833	8
834	1
834	2
834	3
834	4
834	7
834	8
835	1
835	22
835	2
835	23
835	25
835	4
835	8
835	32
835	9
836	1
836	22
836	2
836	23
836	25
836	4
836	5
836	6
836	7
837	1
837	22
837	2
837	23
837	25
837	5
837	28
837	7
838	1
838	22
838	23
838	25
838	4
838	5
838	8
838	32
839	1
839	2
839	3
839	4
839	5
839	6
839	7
839	8
839	9
839	10
840	1
840	22
840	23
840	3
840	25
840	26
840	5
840	6
840	8
840	32
840	9
840	10
841	1
841	4
841	8
842	1
842	22
842	2
842	23
842	3
842	25
842	4
842	26
842	5
842	28
842	6
842	7
842	8
842	32
842	9
842	10
843	1
843	2
843	3
843	4
843	5
843	6
843	8
843	10
844	1
844	3
844	4
844	6
844	8
844	10
845	1
845	2
845	3
845	4
845	5
845	6
845	7
845	8
845	9
845	10
846	1
846	2
846	3
846	4
846	5
846	6
846	7
846	8
846	9
846	10
847	1
847	2
847	4
847	7
847	8
848	1
848	2
848	3
848	4
848	5
848	6
848	7
848	8
848	9
848	10
849	1
849	7
850	1
850	4
850	8
851	1
851	22
851	2
851	23
851	3
851	25
851	4
851	26
851	5
851	28
851	6
851	7
851	8
851	32
851	9
851	10
852	1
852	2
852	7
852	8
854	1
854	2
854	3
854	4
854	5
854	6
854	7
854	8
854	9
854	10
855	1
855	2
855	3
855	4
855	5
855	6
855	7
855	8
855	9
855	10
856	1
856	2
856	4
856	5
856	6
856	8
856	10
857	1
857	3
857	4
857	5
857	6
857	8
857	10
858	1
858	2
858	3
858	4
858	5
858	6
858	8
858	10
859	1
859	3
859	4
859	5
859	8
859	10
860	1
860	22
860	2
860	23
860	3
860	25
860	4
860	26
860	5
860	28
860	6
860	8
860	32
860	9
860	10
861	1
861	3
861	4
861	5
861	6
861	7
861	8
861	10
862	1
862	2
862	4
862	8
863	1
863	4
863	7
863	8
863	10
864	1
864	22
864	23
864	25
864	4
864	26
864	5
864	6
864	32
864	10
865	1
865	2
865	3
865	4
865	5
865	6
865	7
865	8
865	9
865	10
866	1
866	2
866	3
866	4
866	5
866	6
866	7
866	8
866	10
867	1
867	2
867	3
867	4
867	5
867	6
867	7
867	8
867	9
867	10
868	1
868	2
868	3
868	4
868	6
868	7
868	8
868	9
868	10
869	1
869	2
869	3
869	4
869	5
869	6
869	7
869	8
869	9
869	10
870	1
870	2
870	4
870	8
870	10
871	1
871	2
871	4
871	8
872	1
872	22
872	2
872	23
872	25
872	4
872	28
872	6
872	8
872	32
872	9
873	1
873	2
873	3
873	4
873	5
873	6
873	8
873	9
873	10
874	1
874	22
874	2
874	23
874	3
874	25
874	4
874	26
874	5
874	28
874	6
874	8
874	32
874	9
874	10
875	1
875	22
875	23
875	25
875	28
875	6
875	7
875	32
875	10
876	1
876	2
876	4
876	7
876	8
877	1
877	2
877	3
877	4
877	5
877	6
877	7
877	8
877	9
877	10
878	1
878	2
878	3
878	4
878	5
878	6
878	7
878	8
878	9
878	10
879	1
879	2
879	3
879	4
879	5
879	6
879	7
879	8
879	9
879	10
880	1
880	22
880	2
880	23
880	25
880	4
880	5
880	7
880	8
880	32
882	1
882	22
882	2
882	23
882	3
882	25
882	4
882	26
882	5
882	28
882	6
882	7
882	8
882	32
882	9
882	10
883	1
883	22
883	23
883	25
883	4
883	5
883	6
883	7
883	8
883	32
884	1
884	2
884	3
884	4
884	5
884	6
884	7
884	8
884	9
884	10
885	1
885	2
885	3
885	4
885	5
885	6
885	7
885	8
885	9
885	10
886	1
886	2
886	3
886	5
886	6
886	7
886	8
886	10
889	1
889	2
889	5
889	7
889	9
891	1
891	2
891	7
891	8
892	1
892	2
892	8
893	1
893	4
893	6
894	2
894	4
895	1
895	2
895	4
895	7
895	8
896	1
896	2
896	3
896	4
896	6
896	8
896	10
897	1
897	2
897	3
897	4
897	7
897	8
898	1
898	2
898	8
899	1
899	2
899	3
899	4
899	5
899	6
899	7
899	8
899	9
899	10
900	1
900	2
900	4
900	7
900	8
901	1
901	2
901	3
901	4
901	5
901	6
901	7
901	8
901	10
902	1
902	3
902	4
902	6
902	8
902	10
903	1
903	2
903	4
903	7
903	8
905	1
905	22
905	23
905	25
905	26
905	5
905	28
905	6
905	8
905	32
906	1
906	2
906	7
907	1
907	2
907	4
907	7
907	8
907	9
907	10
908	1
908	22
908	2
908	23
908	3
908	25
908	4
908	26
908	5
908	6
908	8
908	32
908	10
909	1
909	2
909	3
909	4
909	5
909	6
909	8
909	10
910	1
910	22
910	2
910	23
910	3
910	25
910	4
910	26
910	5
910	28
910	6
910	7
910	8
910	32
910	9
910	10
911	1
911	3
911	4
911	5
911	6
911	7
911	8
911	10
912	1
912	22
912	23
912	3
912	25
912	4
912	26
912	5
912	28
912	6
912	7
912	8
912	32
912	10
913	1
913	22
913	2
913	23
913	25
913	5
913	6
913	7
913	8
913	32
914	1
914	22
914	23
914	25
914	4
914	7
914	32
915	1
915	22
915	2
915	23
915	3
915	25
915	4
915	5
915	7
915	8
915	32
915	9
916	1
916	3
916	4
916	5
916	6
916	8
917	1
917	4
917	8
918	1
918	2
918	3
918	4
918	5
918	6
918	7
918	8
918	10
920	1
920	2
920	5
920	6
920	7
920	8
921	1
921	22
921	2
921	23
921	3
921	25
921	4
921	5
921	28
921	7
921	8
921	32
921	9
921	10
922	1
922	3
922	4
922	6
922	8
922	10
923	1
923	22
923	23
923	25
923	4
923	26
923	8
923	32
924	1
924	2
924	3
924	4
924	5
924	6
924	8
924	10
925	1
925	2
925	3
925	4
925	5
925	6
925	8
925	10
926	1
926	2
926	3
926	4
926	5
926	6
926	8
926	10
927	1
927	2
927	3
927	4
927	5
927	6
927	7
927	8
927	9
927	10
928	1
928	2
928	3
928	4
928	5
928	6
928	7
928	8
928	9
928	10
929	1
929	4
930	1
930	2
930	3
930	4
930	6
930	8
930	9
930	10
931	2
931	4
932	1
932	2
932	4
932	8
932	9
933	1
933	2
933	3
933	4
933	5
933	6
933	7
933	8
933	9
933	10
934	1
934	22
934	2
934	23
934	25
934	4
934	5
934	28
934	7
934	8
934	32
935	1
935	2
935	4
935	7
935	8
935	32
935	9
936	1
936	2
936	3
936	4
936	5
936	6
936	8
936	9
936	10
937	1
937	2
937	3
937	4
937	5
937	6
937	7
937	8
937	9
937	10
938	1
938	2
938	3
938	4
938	5
938	6
938	7
938	8
938	9
938	10
939	1
939	2
939	3
939	4
939	5
939	6
939	7
939	8
939	9
939	10
940	1
940	4
940	7
940	8
940	10
941	1
941	22
941	2
941	23
941	25
941	4
941	26
941	28
941	6
941	8
941	32
941	9
942	1
942	22
942	2
942	23
942	3
942	25
942	4
942	26
942	5
942	28
942	6
942	7
942	8
942	32
942	9
942	10
943	1
943	22
943	2
943	23
943	3
943	25
943	4
943	26
943	5
943	28
943	6
943	7
943	8
943	32
943	9
944	1
944	22
944	2
944	23
944	3
944	25
944	4
944	26
944	6
944	7
944	8
944	32
944	9
944	10
945	1
945	2
945	4
945	7
945	8
946	2
946	9
947	1
947	22
947	23
947	25
947	4
947	5
947	7
947	8
947	32
947	9
948	22
948	2
948	23
948	3
948	25
948	6
948	8
948	32
948	9
948	10
949	1
949	2
950	2
950	3
950	5
950	6
950	8
950	10
951	1
951	2
951	4
951	8
952	1
952	22
952	23
952	25
952	5
952	7
952	8
952	10
953	1
953	2
953	4
953	7
953	8
954	1
954	2
954	3
954	4
954	5
954	6
954	7
954	8
954	10
955	1
956	1
956	2
956	3
956	4
956	5
956	6
956	7
956	8
956	9
956	10
957	1
957	22
957	2
957	23
957	3
957	25
957	4
957	26
957	5
957	28
957	6
957	7
957	8
957	32
957	9
957	10
958	1
958	2
958	3
958	4
958	5
958	6
958	7
958	8
958	10
959	1
959	2
959	3
959	4
959	5
959	6
959	7
959	8
959	9
959	10
961	8
961	32
962	1
962	2
962	3
962	4
962	6
962	8
963	1
963	2
963	3
963	4
963	5
963	6
963	7
963	8
963	9
963	10
964	1
964	2
964	4
964	6
965	1
965	2
965	3
965	4
965	5
965	6
965	7
965	8
965	9
965	10
966	1
966	2
966	3
966	4
966	5
966	6
966	7
966	8
966	9
966	10
967	1
967	2
967	4
967	7
967	8
969	1
969	3
969	4
969	6
969	8
969	10
970	1
970	22
970	23
970	3
970	25
970	4
970	6
970	7
970	8
970	32
970	10
971	1
971	22
971	2
971	23
971	3
971	25
971	4
971	26
971	5
971	28
971	6
971	8
971	32
971	9
971	10
972	1
972	22
972	2
972	3
972	26
972	7
972	8
972	32
972	9
973	1
973	2
973	3
973	4
973	6
973	7
973	8
973	9
974	1
974	3
974	4
974	6
974	8
974	10
975	1
975	22
975	2
975	25
975	5
975	6
975	8
975	32
975	9
976	1
976	2
976	3
976	4
976	6
976	7
976	8
976	9
976	10
977	1
977	2
977	3
977	4
977	5
977	6
977	7
977	8
977	9
977	10
978	1
978	22
978	2
978	23
978	3
978	25
978	26
978	5
978	28
978	6
978	8
978	32
978	9
978	10
979	1
979	22
979	2
979	23
979	3
979	25
979	4
979	26
979	5
979	28
979	6
979	7
979	8
979	32
979	9
979	10
980	1
980	2
980	4
980	8
981	1
981	22
981	23
981	25
981	4
981	5
981	7
981	8
981	32
981	9
981	10
982	1
983	1
983	22
983	23
983	3
983	25
983	4
983	26
983	28
983	6
983	8
983	32
984	1
984	22
984	23
984	3
984	25
984	4
984	5
984	28
984	6
984	8
984	32
984	10
985	1
985	22
985	23
985	3
985	25
985	4
985	26
985	5
985	6
985	7
985	8
985	32
985	10
986	1
986	2
986	3
986	8
986	10
987	1
987	2
987	3
987	4
987	5
987	6
987	7
987	8
987	9
987	10
988	2
988	3
988	4
988	5
988	6
988	8
988	9
988	10
989	1
989	2
989	3
989	4
989	5
989	6
989	7
989	8
989	9
989	10
990	1
990	2
990	3
990	4
990	5
990	6
990	7
990	8
990	9
990	10
991	1
991	2
991	4
991	8
991	10
992	2
992	3
992	4
992	6
992	10
993	1
993	5
993	6
993	7
993	8
994	1
994	2
994	4
994	7
994	8
995	1
995	2
995	3
995	5
995	6
995	8
995	10
996	1
996	2
996	4
996	7
996	8
997	22
997	2
997	23
997	3
997	4
997	8
997	32
997	9
997	10
998	1
998	2
998	4
998	7
998	8
999	1
999	22
999	23
999	3
999	25
999	28
999	8
999	32
1000	1
1000	22
1000	23
1000	3
1000	25
1000	4
1000	26
1000	5
1000	28
1000	7
1000	8
1000	32
1000	10
1001	1
1001	22
1001	2
1001	23
1001	3
1001	25
1001	4
1001	26
1001	5
1001	28
1001	6
1001	7
1001	8
1001	32
1001	9
1001	10
1002	1
1002	22
1002	2
1002	23
1002	25
1002	4
1002	26
1002	5
1002	6
1002	7
1002	8
1002	32
1002	9
1002	10
1003	1
1003	2
1003	4
1004	1
1004	22
1004	2
1004	23
1004	3
1004	25
1004	4
1004	26
1004	28
1004	6
1004	7
1004	8
1004	32
1005	1
1005	3
1005	4
1005	5
1005	6
1005	7
1005	8
1005	10
1006	1
1006	22
1006	2
1006	23
1006	3
1006	25
1006	4
1006	5
1006	7
1006	8
1006	32
1006	9
1007	1
1007	22
1007	2
1007	23
1007	25
1007	26
1007	5
1007	28
1007	6
1007	7
1007	8
1007	32
1007	9
1008	1
1008	2
1008	25
1008	8
1008	32
1009	1
1009	2
1009	4
1009	8
1009	9
1010	1
1010	2
1010	3
1010	4
1010	5
1010	6
1010	7
1010	8
1010	9
1010	10
1011	1
1011	2
1011	3
1011	4
1011	5
1011	6
1011	7
1011	8
1011	9
1011	10
1012	1
1012	2
1012	4
1012	7
1012	8
1013	1
1013	2
1013	3
1013	4
1013	5
1013	6
1013	7
1013	8
1013	9
1013	10
1014	1
1014	2
1014	7
1014	8
1015	1
1015	2
1015	3
1015	4
1015	5
1015	6
1015	7
1015	8
1015	9
1015	10
1016	1
1016	2
1016	4
1016	7
1016	8
1016	10
1017	1
1017	2
1017	3
1017	4
1017	5
1017	6
1017	7
1017	8
1017	9
1017	10
1018	1
1018	2
1018	3
1018	4
1018	5
1018	6
1018	7
1018	8
1018	10
1019	1
1019	22
1019	23
1019	25
1019	26
1019	6
1020	1
1020	3
1020	4
1020	5
1020	8
1021	1
1021	2
1021	3
1021	4
1021	5
1021	6
1021	7
1021	8
1021	9
1021	10
1022	1
1022	2
1022	4
1022	5
1022	7
1022	8
1022	9
1022	10
1023	1
1023	2
1023	4
1023	5
1023	7
1023	8
1023	9
1023	10
1024	1
1024	2
1024	4
1024	7
1024	8
1026	1
1026	2
1026	3
1026	4
1026	7
1026	8
1026	10
1028	1
1028	2
1028	4
1028	5
1028	6
1028	7
1028	8
1030	1
1030	2
1030	5
1030	6
1030	7
1030	8
1031	1
1031	3
1031	4
1031	5
1031	6
1031	8
1031	10
1032	1
1032	3
1032	4
1032	6
1032	8
1032	10
1033	1
1033	2
1033	8
1034	1
1034	2
1034	3
1034	4
1034	5
1034	6
1034	8
1034	9
1034	10
1035	1
1035	2
1035	3
1035	4
1035	5
1035	6
1035	7
1035	8
1035	9
1035	10
1037	1
1037	2
1037	5
1037	6
1037	7
1037	8
1038	1
1038	2
1038	6
1039	1
1039	2
1039	5
1039	6
1039	7
1039	8
1040	1
1040	4
1040	5
1040	6
1040	7
1040	8
1042	1
1042	2
1042	5
1042	6
1042	7
1042	8
1043	22
1043	2
1043	23
1043	25
1043	4
1043	26
1043	5
1043	6
1043	8
1043	32
1043	9
1043	10
1045	1
1045	5
1045	6
1045	7
1046	2
1046	23
1046	4
1046	5
1046	8
1047	1
1047	22
1047	2
1047	23
1047	3
1047	25
1047	4
1047	26
1047	28
1047	6
1047	8
1047	32
1047	9
1047	10
1048	1
1048	2
1048	3
1048	8
1048	10
1049	1
1049	2
1049	4
1049	5
1049	6
1049	7
1049	8
1050	1
1050	22
1050	23
1050	3
1050	25
1050	4
1050	26
1050	28
1050	6
1050	8
1050	32
1050	10
1051	1
1051	22
1051	2
1051	23
1051	25
1051	4
1051	26
1051	5
1051	28
1051	6
1051	7
1051	8
1051	32
1052	1
1052	2
1052	3
1052	4
1052	5
1052	6
1052	7
1052	8
1052	9
1052	10
\.


--
-- Data for Name: provider_fee; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.provider_fee (provider_id, fee_id) FROM stdin;
1	1
2	1
3	3
5	3
6	5
7	1
8	5
8	8
9	1
10	3
10	1
11	5
12	5
13	1
14	5
15	1
16	8
17	5
18	5
19	5
20	5
21	1
22	1
23	5
24	5
24	8
25	5
26	5
27	5
28	3
28	1
29	5
30	3
31	1
32	1
33	3
33	1
34	3
34	1
35	1
36	1
37	1
38	1
39	1
40	3
41	5
42	5
43	5
43	8
44	1
45	3
46	5
46	8
46	1
47	5
48	3
48	1
49	5
50	5
51	1
52	5
53	5
54	5
55	8
56	5
56	8
57	5
58	5
58	8
59	5
60	5
60	8
61	3
62	3
62	5
62	8
63	3
64	5
64	8
65	5
65	8
66	8
66	1
67	3
69	8
70	3
70	1
71	5
72	8
73	8
73	1
74	8
75	1
76	1
77	5
78	5
79	5
79	8
80	5
80	8
81	5
82	5
83	5
85	5
86	5
87	3
88	5
88	8
90	3
91	5
93	5
93	8
94	3
96	5
97	5
97	8
98	5
99	5
100	5
101	5
102	5
102	8
104	1
105	1
106	3
106	1
107	5
108	5
109	5
110	8
111	5
111	8
112	5
114	5
114	8
115	5
116	5
117	3
117	5
120	5
120	8
121	5
122	5
122	8
123	5
124	5
124	8
125	3
126	3
126	1
127	5
128	1
129	5
129	8
131	5
132	3
134	3
135	3
136	1
138	5
139	3
139	1
140	5
141	5
142	5
142	8
143	3
144	3
144	5
145	5
146	5
146	8
147	5
149	5
150	5
151	5
152	3
152	1
153	3
153	5
153	8
153	1
154	3
154	5
154	8
154	1
156	5
156	8
157	5
157	8
158	5
159	1
160	5
161	5
162	5
163	3
164	3
164	1
165	1
166	5
167	8
168	5
169	5
170	3
171	3
171	1
173	5
173	8
174	5
175	3
175	5
175	8
175	1
176	3
177	5
178	5
178	8
179	5
180	5
181	5
182	5
183	5
184	5
185	3
186	5
187	5
188	5
189	5
189	8
190	3
191	5
192	5
194	1
195	3
196	1
197	3
198	3
200	3
200	1
202	8
203	3
203	1
204	5
205	5
206	5
206	8
208	5
209	5
211	3
212	3
213	1
214	1
215	5
216	5
216	8
217	5
217	8
219	8
220	8
221	5
221	8
222	5
222	8
224	5
225	1
226	5
228	5
228	8
229	3
231	5
231	8
232	5
233	5
234	5
235	3
235	1
236	5
237	5
238	5
239	8
240	1
241	3
241	5
241	8
241	1
242	5
243	3
243	5
244	5
244	8
245	5
245	8
246	5
246	8
247	5
248	5
248	8
250	5
251	5
251	8
252	3
253	5
254	3
255	3
256	5
257	1
258	5
258	8
259	5
260	1
261	5
262	3
262	5
263	3
263	5
264	3
264	5
265	5
266	8
267	3
267	1
268	3
269	5
270	3
271	5
272	3
273	3
274	3
275	3
276	3
277	5
277	8
278	3
279	3
280	3
281	5
282	5
283	3
284	5
285	5
286	5
287	5
288	3
289	5
289	8
290	3
290	5
291	5
292	5
293	3
294	3
295	3
295	5
295	8
297	5
297	8
298	3
299	3
300	3
301	5
301	8
302	3
302	5
302	8
302	1
303	1
304	1
305	5
306	5
306	8
307	5
308	5
308	8
309	8
310	3
310	1
311	3
311	1
312	5
313	5
314	5
314	8
315	8
316	5
317	1
318	1
319	1
320	3
320	1
321	5
321	8
322	5
322	8
323	3
324	5
324	8
325	5
326	5
326	8
327	5
327	8
328	5
329	3
330	5
331	5
332	5
332	8
333	5
333	8
334	5
334	8
335	1
336	3
336	5
336	8
336	1
337	5
338	5
339	8
340	3
341	5
342	3
342	5
342	1
343	5
343	8
344	5
345	5
345	8
346	5
346	8
347	5
347	8
349	5
349	8
349	1
350	1
351	5
352	5
353	3
353	5
353	8
353	1
354	5
355	5
356	5
357	5
358	5
359	3
359	5
361	1
362	5
362	8
364	8
365	5
366	5
367	3
367	1
368	1
369	5
370	1
371	5
372	5
373	5
374	5
374	1
375	5
375	8
375	1
376	3
376	1
377	1
378	5
379	5
381	5
381	8
382	5
383	8
384	5
384	8
385	5
386	3
386	1
387	3
388	5
389	3
389	1
390	3
392	5
392	8
393	5
393	8
394	5
395	1
396	3
396	1
397	3
398	3
399	3
400	5
400	8
401	1
402	5
403	5
404	5
405	3
405	1
406	5
406	8
407	5
407	8
408	5
409	3
409	5
409	8
410	5
411	5
412	5
412	8
413	5
414	5
414	8
415	1
416	5
417	5
418	5
419	5
420	5
421	5
422	5
423	3
424	5
425	5
426	5
427	1
428	1
429	3
430	1
431	5
432	5
432	8
433	5
433	8
434	5
434	8
435	5
436	5
436	8
437	1
438	1
439	3
441	5
442	5
442	8
443	5
443	8
444	1
445	5
445	8
446	5
447	5
447	8
448	5
448	8
449	5
449	8
449	1
450	5
451	5
451	8
452	8
453	5
453	8
454	5
454	8
455	3
456	5
457	5
457	8
458	1
459	1
460	5
461	5
461	8
462	5
463	5
464	5
465	5
466	3
466	5
466	8
466	1
467	5
468	5
468	8
469	3
469	5
470	8
471	3
471	5
472	5
473	5
474	5
475	5
476	5
477	3
478	5
480	5
480	8
481	8
482	3
482	5
483	8
485	5
486	5
487	3
487	5
488	5
489	1
491	5
493	1
494	5
494	8
495	3
499	5
500	5
501	5
502	5
503	5
504	5
504	8
505	5
506	3
506	1
507	3
508	3
508	1
509	5
510	3
510	1
511	5
511	8
512	5
513	5
514	5
515	5
515	8
516	8
517	8
517	1
518	5
518	8
519	5
519	8
520	1
521	5
522	3
523	3
524	3
524	5
524	8
524	1
525	3
526	3
526	1
527	3
529	5
529	8
530	5
530	8
531	5
532	5
533	5
534	5
534	8
535	3
535	5
535	8
535	1
536	5
537	5
538	3
538	5
540	5
540	8
541	1
542	5
543	5
544	5
544	8
545	3
545	5
545	8
546	5
546	8
547	3
548	3
549	5
549	8
550	5
551	5
552	5
553	5
553	8
554	5
555	3
556	3
558	3
558	1
560	5
560	8
561	5
561	8
562	5
563	1
564	5
565	3
566	5
567	3
567	5
567	8
568	5
569	1
570	1
571	3
572	8
573	3
573	5
573	1
574	5
575	5
576	5
576	8
578	3
579	5
580	5
580	8
581	5
581	8
582	5
582	8
583	3
583	1
584	5
584	8
585	5
586	5
587	5
587	8
588	5
589	1
590	5
590	8
591	5
592	5
592	8
593	5
593	8
594	5
595	5
596	5
596	8
596	1
597	5
597	8
598	3
598	1
599	8
600	5
601	5
602	5
602	8
603	5
604	5
605	1
606	1
607	5
608	5
609	5
610	5
611	5
612	5
613	5
613	8
614	5
614	8
615	3
615	1
616	3
617	3
618	1
619	1
620	3
621	3
622	3
623	3
624	3
625	5
626	5
627	5
628	5
629	3
629	1
630	5
631	5
632	5
633	5
633	8
633	1
634	5
635	5
636	5
637	3
638	5
639	5
640	5
641	5
643	5
643	8
644	3
645	3
646	3
646	1
647	5
648	5
649	5
650	5
651	5
651	8
652	5
653	5
654	5
654	8
655	5
656	5
656	8
657	5
657	8
658	5
659	1
660	5
661	5
661	8
662	5
663	3
663	1
664	3
665	5
665	8
666	5
666	8
667	5
668	5
668	8
669	1
670	5
670	8
671	5
671	8
672	3
673	3
673	1
674	3
675	3
675	1
676	3
677	3
677	1
678	5
679	5
679	8
683	1
684	1
685	3
685	1
686	5
687	1
688	5
689	5
689	8
689	1
690	1
691	1
692	5
692	8
692	1
693	5
694	3
695	5
695	8
696	3
696	1
697	3
698	3
698	1
699	5
700	5
701	5
702	5
703	3
704	5
705	5
705	8
706	1
707	5
707	8
708	1
709	1
711	5
712	1
713	3
713	5
713	8
713	1
714	8
715	3
716	5
717	8
718	5
718	8
719	5
719	8
720	3
720	5
720	8
720	1
721	3
721	1
722	3
723	1
724	5
725	5
726	1
727	5
728	1
729	3
729	5
729	8
729	1
730	1
731	5
731	8
731	1
732	5
733	5
734	1
735	3
736	3
736	1
737	5
738	1
739	1
740	1
741	1
742	1
743	5
744	1
745	1
746	1
747	5
749	1
751	1
752	5
753	1
754	5
755	1
756	1
757	5
757	8
758	5
759	8
760	5
760	8
761	5
762	5
763	5
764	8
765	8
765	1
766	5
767	5
768	3
769	5
770	5
771	5
772	8
773	1
774	1
775	3
775	1
776	3
776	1
777	5
778	3
779	5
780	5
781	3
781	5
781	8
782	5
783	3
783	1
784	5
785	5
786	3
786	1
787	1
788	5
789	5
789	8
790	5
791	3
791	5
791	8
791	1
792	5
792	8
793	1
795	5
795	8
796	3
796	1
799	3
799	1
800	3
800	1
801	8
802	5
803	5
804	5
805	5
806	5
806	8
807	3
807	5
808	5
808	8
809	5
810	5
811	5
811	8
812	5
813	5
814	5
815	3
815	1
816	5
817	5
818	5
819	5
819	1
820	3
820	5
820	8
820	1
821	3
821	1
822	5
822	8
823	3
823	1
825	3
825	5
826	5
826	8
827	5
828	3
828	1
829	5
829	8
830	1
831	3
831	5
831	8
831	1
832	1
833	1
834	5
835	5
836	5
837	5
838	5
839	3
840	3
840	1
841	5
841	8
842	3
842	1
843	5
843	8
844	5
845	3
846	5
846	8
847	5
848	3
848	1
850	1
851	5
852	1
854	1
855	1
857	1
858	1
859	5
860	5
861	1
862	5
863	1
864	3
865	3
865	1
866	3
867	3
868	5
868	8
868	1
870	3
871	5
872	5
872	8
873	5
874	5
874	8
875	5
876	5
877	5
878	3
878	5
878	1
879	3
880	5
882	1
883	5
884	3
885	3
886	5
886	1
887	5
888	5
889	5
890	5
891	1
892	1
893	5
894	5
895	5
896	5
897	5
899	3
900	5
901	5
901	8
902	5
903	5
905	5
906	3
906	5
907	1
908	3
910	1
911	1
912	1
913	5
914	1
915	5
916	5
916	8
917	5
918	1
920	5
920	8
921	5
922	5
923	3
925	3
925	1
926	3
929	3
930	5
931	1
932	1
934	3
934	5
934	1
935	5
936	3
936	1
937	1
938	5
939	5
940	5
941	5
941	8
942	5
942	8
943	5
943	8
944	3
945	5
945	1
946	3
948	1
950	1
951	5
952	5
953	5
953	8
954	1
955	3
955	5
956	5
957	5
957	8
958	1
959	1
962	5
964	5
964	8
964	1
965	5
967	5
969	5
970	5
971	1
972	5
973	5
974	5
975	8
976	3
976	5
976	8
978	3
978	1
979	5
980	5
982	5
983	3
983	5
984	3
984	5
985	3
985	5
986	3
987	5
987	8
988	1
989	3
989	1
990	3
990	1
991	3
991	1
992	3
992	1
993	1
994	1
995	3
996	5
997	5
998	3
999	5
1000	5
1001	5
1001	8
1002	3
1004	3
1004	5
1005	5
1006	5
1007	3
1008	3
1008	1
1009	5
1010	3
1010	1
1011	3
1011	5
1012	1
1013	3
1014	3
1015	3
1015	5
1016	1
1017	1
1018	3
1019	8
1020	5
1021	1
1022	3
1022	1
1023	5
1024	1
1026	3
1026	1
1028	1
1030	1
1031	3
1031	1
1032	1
1033	5
1033	1
1034	3
1037	1
1038	1
1039	1
1040	1
1042	1
1043	1
1045	5
1045	8
1046	8
1047	5
1047	8
1047	1
1048	3
1048	1
1049	5
1049	1
1050	5
1050	8
1051	5
1051	8
1052	5
\.


--
-- Data for Name: provider_language; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.provider_language (provider_id, language_id) FROM stdin;
1	1
1	2
2	2
3	2
3	5
4	2
5	2
7	8
7	1
7	2
7	11
7	12
7	13
7	14
7	5
7	16
7	17
8	2
9	2
9	11
10	2
10	11
11	2
12	2
13	2
14	2
15	11
16	2
17	2
18	2
18	5
19	2
20	2
21	2
22	2
22	11
23	2
24	2
25	2
26	2
27	2
28	2
29	2
29	44
30	2
31	2
32	2
33	2
34	2
34	11
35	2
35	11
36	2
37	2
38	2
38	11
38	16
39	2
39	17
40	2
41	2
42	2
43	2
43	5
44	2
44	17
45	2
46	2
47	2
48	2
49	2
49	11
50	2
51	2
52	2
53	2
54	2
55	78
55	2
55	5
56	2
56	5
57	2
58	2
59	2
59	11
60	2
61	2
62	2
63	2
64	2
65	2
66	2
66	11
67	8
67	2
69	2
70	2
71	2
71	16
72	2
73	2
74	2
75	8
75	2
75	13
76	2
77	2
78	2
79	2
79	5
80	2
81	2
81	11
82	2
83	2
84	2
85	2
86	2
87	2
88	2
89	2
89	5
90	2
91	2
92	2
93	2
94	2
95	8
96	2
97	78
97	8
97	2
97	11
97	44
97	13
97	5
97	138
97	16
97	17
98	2
99	2
100	2
101	2
102	2
104	2
105	2
106	2
106	5
107	2
109	2
110	2
111	2
111	11
112	2
113	2
114	2
115	2
116	2
116	11
117	2
117	5
118	2
118	16
119	2
119	11
119	5
120	2
121	2
122	2
123	2
123	16
124	2
124	44
125	2
126	2
127	2
128	2
129	2
130	2
130	11
130	5
130	16
130	17
131	2
131	11
131	44
131	13
131	5
131	16
132	2
133	2
133	11
134	2
135	2
136	2
137	2
137	11
138	2
139	2
140	2
141	78
141	2
141	11
142	2
143	2
144	2
145	2
146	2
147	2
148	2
148	11
149	2
150	2
151	2
152	2
153	2
155	2
155	11
156	2
157	2
158	2
158	5
159	2
159	16
160	2
161	2
161	16
162	2
163	2
164	2
164	11
165	2
166	2
167	2
168	2
169	2
169	16
170	2
171	2
172	2
172	11
173	2
174	2
174	17
175	2
176	78
176	8
176	1
176	2
176	11
176	252
176	12
176	44
176	13
176	14
176	138
176	258
176	16
176	17
176	261
177	2
178	2
179	2
180	2
181	2
182	2
183	2
183	258
184	2
185	2
186	2
187	2
188	2
189	2
190	2
191	2
191	5
192	2
192	12
192	16
193	2
193	11
194	2
195	2
196	2
197	2
198	2
198	11
199	2
199	11
200	2
200	5
202	2
203	2
203	11
204	2
205	2
205	11
205	16
206	2
207	2
208	2
208	11
208	13
209	2
209	5
209	17
211	2
212	2
213	2
213	16
214	2
214	11
215	2
216	2
216	16
217	2
219	2
220	2
221	2
221	11
221	138
221	16
222	2
224	2
225	2
225	16
226	2
227	2
228	2
229	2
230	2
231	2
232	2
233	2
234	2
235	2
236	2
237	2
238	2
238	11
239	2
240	2
241	2
241	16
242	2
243	2
243	16
244	2
245	2
246	2
248	2
248	11
250	2
251	2
251	12
252	8
252	1
252	2
252	11
252	12
252	13
252	14
252	16
252	17
253	2
253	11
254	2
255	2
255	11
256	2
256	11
257	2
258	2
258	11
259	2
259	5
260	2
261	2
262	2
263	2
264	2
265	2
265	16
266	2
267	2
268	2
269	2
270	2
271	2
272	2
273	2
273	11
273	5
274	2
275	2
276	2
277	2
278	2
279	2
280	2
281	2
282	2
282	5
283	2
284	2
284	11
285	2
286	2
287	2
288	2
289	2
289	16
290	2
291	2
292	2
293	2
295	2
296	2
297	2
298	2
298	11
299	2
300	2
301	2
301	12
302	2
303	2
303	11
303	16
304	2
305	2
306	2
307	2
308	8
308	2
308	13
309	2
310	2
310	5
310	16
311	2
312	2
313	2
313	11
314	2
315	2
316	2
317	2
317	11
318	2
319	2
320	2
321	2
322	2
323	2
324	2
325	2
326	2
327	2
328	2
329	2
330	2
330	5
330	16
331	2
332	2
332	5
333	2
334	2
335	2
336	2
337	2
338	2
339	2
339	5
340	2
341	2
342	2
343	2
344	2
345	2
346	2
347	2
348	2
348	11
349	2
350	8
350	2
350	13
350	16
351	2
352	2
353	2
354	2
355	2
356	2
357	2
357	5
358	2
359	2
361	2
362	2
362	11
364	2
365	2
366	2
367	2
368	2
369	2
370	2
371	2
372	2
373	2
374	2
375	2
376	2
377	2
378	2
378	11
379	2
379	11
381	2
382	2
383	2
384	2
384	11
385	2
386	2
387	2
388	2
389	2
390	2
391	2
391	5
392	2
392	16
393	2
394	2
395	2
396	2
397	2
398	2
398	11
399	2
400	2
401	2
402	2
403	2
404	2
406	2
406	5
407	8
407	2
408	2
409	2
410	2
412	2
413	2
414	2
415	2
415	11
416	2
417	2
418	2
419	2
420	2
421	2
422	2
423	2
424	2
425	2
426	2
427	2
427	11
427	16
428	2
429	2
430	2
431	2
432	2
432	5
433	2
434	2
435	2
436	2
437	2
438	8
438	1
438	2
438	11
438	12
438	13
438	14
438	5
438	16
438	17
440	2
441	2
442	2
443	2
444	2
445	2
446	2
447	2
447	5
448	2
449	2
450	2
451	2
451	5
452	2
453	2
454	2
455	2
456	2
457	2
458	2
459	2
459	11
460	2
461	2
461	13
462	2
463	2
464	2
465	2
466	2
466	11
466	16
467	2
468	2
469	2
470	2
471	2
472	2
473	2
474	2
475	2
476	2
477	2
478	2
479	2
480	2
481	2
482	2
483	2
484	2
485	2
486	2
487	2
488	2
489	2
490	2
491	2
491	11
493	2
494	2
494	16
495	5
499	2
500	2
501	2
502	2
502	5
503	2
504	2
505	2
505	16
506	2
507	2
508	2
509	2
510	2
511	2
511	5
512	2
513	2
514	2
515	2
516	2
517	2
518	2
519	2
520	2
521	2
521	12
522	2
523	2
525	2
526	2
527	2
529	2
530	2
531	2
532	2
533	2
534	2
535	2
536	2
538	2
540	2
541	2
542	2
543	2
543	5
544	2
545	2
546	2
547	2
548	2
549	2
550	2
551	2
552	16
553	2
554	2
555	8
555	2
555	13
556	2
557	2
558	2
559	2
560	2
561	2
561	5
562	2
563	2
564	2
565	2
566	2
567	2
567	12
568	2
569	2
570	2
570	11
571	2
572	2
574	2
574	11
575	2
575	16
576	2
576	16
578	2
579	2
580	2
581	2
582	2
583	2
583	11
584	2
585	2
586	2
587	8
588	2
589	78
589	2
589	11
590	2
591	2
592	2
594	8
594	2
594	11
594	5
594	258
594	16
595	2
596	2
596	11
596	5
597	2
598	2
598	11
598	5
599	2
600	2
601	2
602	2
603	2
604	2
605	2
606	2
607	2
608	2
609	2
610	2
611	2
612	2
613	2
614	2
614	5
615	2
616	2
617	2
618	2
619	2
620	2
621	8
621	2
621	11
621	13
621	16
622	2
622	11
623	2
624	2
625	2
626	78
626	2
626	11
626	258
626	16
626	17
627	2
627	5
628	2
629	2
630	2
631	8
631	2
632	8
632	2
633	2
634	2
635	2
636	2
637	2
638	2
638	13
639	2
640	2
641	2
642	2
643	2
643	5
644	2
645	2
646	2
647	2
647	5
648	2
649	2
649	16
650	2
651	2
652	2
653	2
653	5
655	2
656	2
656	16
657	2
657	16
658	2
659	2
660	2
661	2
661	11
662	2
663	2
664	2
665	2
666	2
667	2
668	2
668	11
669	8
670	8
670	2
671	2
672	2
673	2
674	2
675	2
675	11
676	2
677	2
677	11
678	2
679	2
681	2
682	2
683	1
683	2
683	14
683	5
684	11
686	2
687	2
688	2
688	11
689	78
689	8
689	2
689	11
689	12
689	5
689	258
690	2
691	2
692	2
693	2
694	2
694	11
695	2
695	11
696	2
697	2
698	2
699	2
700	2
701	2
701	11
701	138
701	16
702	2
703	2
704	2
705	2
706	2
707	2
707	11
708	2
709	8
709	5
710	2
711	2
712	2
712	16
713	2
714	2
715	2
716	2
717	2
718	2
719	2
720	2
721	2
721	5
722	2
722	11
723	2
724	2
725	2
726	2
727	2
728	2
729	2
730	2
731	2
732	2
733	2
734	2
735	2
736	2
737	2
738	2
739	2
740	2
741	2
742	2
743	8
743	2
743	13
744	2
744	11
745	2
745	11
746	2
747	2
748	2
749	2
749	11
750	2
751	2
752	2
752	258
753	2
753	11
754	2
755	2
756	2
757	2
758	2
759	2
759	5
760	2
761	2
762	2
763	2
763	5
764	2
765	2
766	2
767	2
767	5
768	2
769	2
770	2
771	2
772	2
772	11
772	12
772	16
773	2
774	2
775	2
776	2
777	2
778	2
779	2
779	11
780	2
781	2
782	2
783	2
784	2
785	2
786	8
786	2
786	11
786	13
786	5
787	2
788	2
789	2
790	2
790	11
790	16
791	2
792	2
793	2
793	11
795	16
799	2
800	2
801	2
802	2
803	2
803	11
804	2
804	11
805	2
806	12
807	2
808	2
809	2
810	2
811	2
812	2
813	2
814	2
814	5
815	2
815	11
816	2
817	2
818	2
819	2
820	2
820	13
820	5
820	16
820	17
821	2
821	5
822	2
823	2
824	2
825	2
825	5
826	2
827	2
827	11
828	2
829	2
830	2
830	16
831	2
832	2
833	2
834	2
835	2
836	2
837	2
837	16
838	2
839	2
840	2
841	2
842	2
842	5
843	2
844	2
844	16
845	2
846	2
847	2
848	2
849	2
849	11
850	2
851	8
851	11
852	8
852	2
852	11
852	12
852	13
852	16
853	2
854	2
855	2
856	8
856	2
857	8
857	2
857	11
857	5
858	8
858	2
858	11
858	5
859	2
860	2
861	2
862	2
863	2
864	2
865	2
866	2
867	8
867	2
867	13
868	2
869	2
870	2
871	2
872	2
873	2
874	2
874	5
875	2
876	2
877	2
878	2
878	5
880	2
881	2
882	2
882	11
883	2
884	2
885	2
885	5
886	8
886	1
886	2
886	11
886	12
886	13
886	14
886	5
886	16
886	17
887	2
888	2
889	2
890	2
891	2
892	2
893	8
894	2
895	2
896	2
897	2
898	8
899	2
899	11
901	2
902	2
902	11
903	2
905	2
906	2
907	2
907	11
908	2
908	11
908	13
908	16
909	2
910	2
911	2
912	2
913	2
914	2
915	2
916	2
917	2
918	2
920	2
921	2
922	2
923	2
924	2
925	2
925	11
925	5
925	16
926	2
926	11
926	12
926	5
926	16
927	2
927	11
928	2
928	11
929	2
930	11
930	5
930	16
931	2
933	2
934	2
935	2
935	11
936	2
936	16
937	2
937	11
938	2
939	2
940	2
941	2
942	2
943	2
944	2
944	17
945	2
946	2
947	2
948	2
948	11
949	2
950	2
951	2
952	2
953	2
953	12
954	2
955	2
955	13
956	2
957	2
958	2
959	2
959	11
959	16
961	2
962	2
962	5
963	2
963	5
964	2
965	2
966	2
967	2
967	11
969	8
969	2
969	13
970	2
971	2
972	2
972	16
973	2
974	2
975	2
976	2
977	2
978	2
979	2
979	5
980	2
981	2
982	2
983	2
983	11
984	2
985	2
985	5
986	2
986	5
987	2
988	2
989	2
989	13
990	2
991	2
992	2
993	2
994	2
995	2
996	2
997	2
998	2
999	2
1000	2
1001	2
1002	2
1003	2
1004	2
1005	2
1005	11
1005	5
1005	16
1006	2
1007	2
1007	11
1008	2
1008	11
1009	2
1010	2
1010	11
1010	5
1011	2
1011	11
1011	5
1012	2
1013	2
1014	2
1015	2
1016	2
1017	2
1017	11
1018	2
1019	2
1020	2
1020	16
1021	2
1022	2
1023	2
1024	2
1026	2
1028	2
1029	2
1030	2
1030	11
1030	5
1031	2
1032	2
1033	2
1034	2
1035	2
1037	2
1038	2
1039	2
1040	2
1042	2
1043	78
1043	8
1043	1
1043	2
1043	11
1043	252
1043	12
1043	44
1043	13
1043	14
1043	5
1043	138
1043	258
1043	16
1043	17
1043	261
1045	2
1046	2
1046	12
1047	78
1047	8
1047	2
1047	13
1047	5
1047	261
1048	2
1048	11
1049	2
1050	2
1051	2
1052	2
\.


--
-- Data for Name: provider_referral_requirement; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.provider_referral_requirement (provider_id, referral_requirement_id) FROM stdin;
2	1
3	2
3	3
4	2
4	1
5	2
5	3
6	2
6	1
7	1
8	2
8	1
9	2
9	1
10	2
10	1
11	2
11	3
11	1
12	2
12	1
13	1
14	2
14	3
14	1
16	2
16	1
17	2
17	3
17	1
18	2
18	1
19	2
19	3
19	1
20	2
21	2
21	3
21	1
22	3
22	1
23	2
23	1
24	2
24	1
25	2
25	1
26	2
27	2
27	1
28	2
28	3
28	1
29	2
29	1
30	2
31	1
32	2
32	3
32	1
33	2
33	1
34	2
34	1
35	1
36	2
36	3
36	1
37	1
38	2
38	1
39	1
40	2
40	3
40	1
41	2
41	3
41	1
42	2
42	1
43	2
43	3
43	1
45	2
46	2
46	1
47	2
48	2
48	3
48	1
49	2
50	2
50	3
50	1
51	2
51	3
51	1
52	1
53	2
53	1
54	2
54	1
55	2
55	1
56	2
56	3
56	1
57	2
57	1
58	1
59	2
59	1
60	2
60	3
60	1
61	2
62	2
62	3
62	1
63	2
63	1
64	1
65	2
65	1
66	1
67	2
67	3
69	2
69	1
70	2
71	2
71	3
71	1
72	2
73	2
73	1
74	2
74	1
75	3
75	1
76	2
76	3
76	1
77	1
78	2
78	1
79	1
80	2
80	1
81	2
81	3
81	1
82	2
82	3
82	1
83	2
83	3
83	1
85	2
85	1
86	2
86	1
87	2
88	2
88	3
88	1
90	3
91	2
91	3
91	1
93	1
94	2
96	2
96	3
96	1
97	2
97	3
97	1
98	2
98	1
99	2
99	3
99	1
100	2
100	1
101	2
101	1
102	1
105	2
105	3
105	1
106	2
106	3
106	1
107	2
107	3
107	1
108	2
108	3
108	1
109	2
109	1
110	2
110	1
111	2
112	2
114	2
114	3
114	1
115	2
115	1
116	2
116	3
116	1
118	2
118	3
118	1
120	2
120	1
121	2
121	1
122	2
122	1
123	2
123	1
124	2
124	1
125	2
125	3
126	2
126	3
126	1
127	2
127	3
127	1
128	1
129	1
131	2
131	1
132	3
132	1
134	2
134	1
135	3
135	1
136	1
138	2
138	1
139	2
139	3
139	1
140	2
140	1
141	2
141	1
142	2
142	1
143	2
143	1
144	2
144	3
144	1
145	2
145	1
146	1
147	2
147	3
147	1
149	1
150	2
150	1
151	3
151	1
152	2
152	1
153	1
154	2
154	3
154	1
156	2
156	3
156	1
157	2
157	3
157	1
158	2
158	1
159	2
159	1
160	2
160	1
161	2
161	1
162	2
162	1
163	2
164	2
164	3
164	1
165	2
166	1
167	2
167	1
168	2
169	2
170	2
170	3
170	1
171	2
171	3
171	1
173	2
173	3
173	1
174	2
174	1
176	2
177	2
177	3
177	1
178	2
178	1
179	2
179	1
180	2
180	1
181	1
182	1
183	2
183	1
184	2
184	1
185	2
185	3
185	1
186	1
187	2
187	3
187	1
188	1
189	2
189	1
191	2
191	1
192	3
192	1
194	1
195	3
195	1
196	2
196	3
196	1
197	1
198	3
198	1
200	1
202	2
202	1
203	2
203	3
204	2
205	2
205	3
205	1
206	1
208	2
208	3
208	1
209	2
209	3
209	1
211	2
211	1
212	2
212	1
213	2
213	3
213	1
214	3
214	1
215	1
216	2
216	1
217	2
217	1
219	2
219	1
220	2
220	3
220	1
221	2
221	3
221	1
222	2
222	1
224	2
224	1
225	2
226	2
226	3
226	1
228	2
228	1
229	2
229	3
229	1
230	2
230	3
231	2
231	3
231	1
232	2
232	1
233	2
233	1
234	2
234	3
234	1
235	1
236	1
237	2
237	1
238	2
238	1
239	2
239	1
240	3
240	1
241	2
241	3
241	1
242	2
242	1
243	2
243	3
243	1
244	2
244	1
245	2
245	1
246	2
246	1
247	2
247	1
248	2
248	1
250	2
250	1
251	3
251	1
252	2
252	3
252	1
253	2
253	1
254	3
255	2
255	3
256	2
256	3
256	1
257	2
257	1
258	2
258	1
259	2
261	2
261	3
261	1
262	2
263	2
264	2
264	3
264	1
265	2
265	1
266	2
266	1
267	2
267	1
268	2
268	1
269	2
269	3
269	1
270	3
271	2
271	3
271	1
272	3
273	3
274	2
274	1
275	3
276	3
277	2
277	1
278	3
279	3
279	1
280	2
280	1
281	2
281	1
282	2
283	2
283	1
284	2
284	3
284	1
285	2
285	1
286	2
286	1
287	2
287	1
288	2
288	3
288	1
289	2
289	3
289	1
290	2
290	3
290	1
291	2
291	1
292	2
292	1
293	2
293	3
293	1
294	3
295	3
296	2
296	1
297	2
297	1
298	2
299	2
299	3
299	1
300	2
300	1
301	2
301	1
302	2
302	3
302	1
303	2
303	3
303	1
304	3
304	1
305	2
306	2
306	1
307	2
307	1
308	2
308	1
309	2
309	1
310	2
310	1
311	2
311	3
311	1
312	2
312	1
313	2
313	3
313	1
314	2
314	1
315	1
316	2
316	3
316	1
319	1
320	2
320	3
320	1
321	2
321	1
322	2
322	3
322	1
323	2
323	3
324	1
325	2
325	1
326	2
326	1
327	2
327	1
328	2
328	1
329	2
329	3
330	2
330	1
331	2
331	1
332	2
332	3
332	1
333	2
333	1
334	2
334	3
334	1
337	2
337	3
337	1
338	2
338	1
339	2
339	1
340	2
340	3
341	2
341	1
342	3
342	1
343	2
343	3
343	1
344	2
344	1
345	2
345	3
345	1
346	2
346	1
347	2
347	1
349	2
349	3
349	1
350	3
350	1
351	2
351	3
351	1
352	1
354	2
354	1
355	2
357	2
357	1
358	2
359	3
359	1
361	3
361	1
362	2
362	1
364	2
365	2
365	1
366	2
366	3
366	1
367	2
367	1
368	3
368	1
369	2
369	3
369	1
370	2
370	3
370	1
371	2
371	3
371	1
372	2
372	1
373	2
373	1
374	2
374	1
375	2
375	3
375	1
376	2
377	3
377	1
378	2
378	3
378	1
379	2
379	1
381	2
381	1
382	2
382	1
383	1
384	2
384	1
385	1
386	2
386	1
387	2
387	3
387	1
388	2
388	1
389	2
389	1
390	2
390	1
392	2
392	3
393	2
393	3
393	1
394	2
394	1
395	2
395	3
395	1
396	2
396	3
396	1
398	2
398	3
399	2
399	3
399	1
400	2
400	1
401	1
402	2
402	1
403	2
403	1
404	2
404	1
405	1
406	2
406	3
406	1
407	2
407	3
407	1
408	2
408	1
409	2
409	1
410	2
410	1
411	1
412	2
412	3
412	1
413	2
413	1
414	2
414	1
416	2
417	2
417	1
418	1
419	2
419	1
420	2
420	1
421	2
421	3
421	1
422	2
422	1
423	2
424	1
425	2
425	1
426	2
426	3
426	1
427	1
429	3
429	1
431	2
431	1
432	3
432	1
433	2
433	1
434	2
435	2
435	1
436	2
436	1
438	2
438	1
439	2
439	1
441	1
442	1
443	2
444	1
445	2
445	3
445	1
446	2
446	1
447	2
447	3
447	1
448	2
448	1
449	1
450	2
450	3
450	1
451	2
451	1
452	2
452	1
453	2
453	3
453	1
454	2
454	1
455	2
456	2
456	3
456	1
457	2
457	3
457	1
458	3
458	1
459	1
460	2
460	1
461	2
461	1
462	2
462	3
462	1
463	1
464	2
465	1
466	2
466	3
466	1
467	2
468	2
468	1
469	2
469	3
469	1
470	2
470	3
470	1
471	2
471	3
472	1
473	2
473	3
473	1
474	2
474	1
475	2
475	1
476	2
476	1
478	2
478	3
478	1
480	2
480	3
480	1
481	2
481	1
482	2
482	3
483	2
483	1
485	2
485	1
486	1
487	2
487	1
488	1
489	2
489	3
489	1
491	2
491	1
494	2
495	2
495	3
495	1
499	2
499	1
500	2
500	3
500	1
501	2
502	2
502	3
502	1
503	2
503	3
503	1
504	2
504	1
505	2
505	3
505	1
506	2
506	3
507	2
507	1
508	2
508	3
509	1
510	2
510	1
511	2
511	1
512	2
512	1
513	2
513	1
514	2
514	1
515	2
515	1
516	2
516	1
517	2
517	1
518	2
518	1
519	2
519	1
520	2
520	1
521	2
521	1
522	2
523	2
524	2
524	3
524	1
525	1
526	1
527	2
527	1
529	1
530	2
530	3
530	1
531	2
531	3
531	1
532	2
532	3
532	1
533	2
533	3
533	1
534	2
534	1
535	1
536	2
538	3
538	1
540	2
540	1
541	1
543	1
544	2
544	1
545	2
546	2
546	3
546	1
547	1
548	2
548	1
549	2
549	1
550	2
550	1
552	2
553	2
553	1
554	2
554	1
555	2
555	3
556	3
557	1
560	2
560	3
560	1
561	2
561	3
561	1
562	2
563	2
563	1
564	2
564	1
565	1
566	2
566	3
566	1
567	2
567	3
567	1
568	2
568	1
569	2
570	2
570	1
571	2
571	1
572	2
572	1
573	2
573	3
573	1
574	2
574	3
574	1
575	2
575	1
576	2
576	3
576	1
578	2
578	3
579	2
579	1
580	2
580	1
581	2
581	1
582	2
582	3
582	1
584	2
584	1
585	2
585	3
585	1
586	2
586	3
586	1
587	2
587	3
587	1
588	2
588	1
589	2
589	1
590	2
590	1
591	2
591	1
592	2
592	3
592	1
593	2
593	3
593	1
594	2
594	1
595	2
595	3
595	1
596	1
597	1
598	2
598	3
598	1
599	2
599	1
600	1
601	2
601	1
602	2
602	1
603	2
603	1
604	1
605	1
606	2
606	1
607	3
607	1
608	2
608	1
609	2
609	3
609	1
610	1
611	2
611	1
612	2
612	3
612	1
613	1
614	2
614	3
614	1
615	2
615	1
616	2
616	1
617	1
618	2
618	1
619	2
619	1
620	2
620	1
621	2
621	1
622	2
622	3
622	1
623	2
623	1
624	1
625	2
625	3
625	1
626	2
626	3
626	1
627	2
627	1
628	2
628	3
628	1
629	3
630	2
630	3
630	1
631	2
631	3
631	1
632	2
632	3
632	1
633	2
633	1
634	2
634	1
635	2
635	1
636	2
636	3
636	1
637	2
637	1
638	2
638	1
639	2
639	3
639	1
640	2
640	1
641	2
641	3
641	1
643	2
644	1
645	1
646	2
646	1
647	2
647	1
648	3
648	1
649	2
649	1
650	1
651	2
651	1
652	2
652	1
653	2
653	3
653	1
655	2
655	1
656	1
657	2
657	1
658	2
658	1
659	1
660	1
661	2
661	3
661	1
662	2
662	1
663	2
663	1
664	2
664	3
665	2
665	1
666	2
666	3
666	1
667	2
667	3
667	1
668	1
669	2
669	1
670	2
670	3
670	1
671	2
671	1
672	2
672	3
672	1
673	2
673	1
674	2
674	1
675	1
676	2
676	1
677	2
677	3
677	1
678	1
679	2
679	1
681	2
684	2
684	3
684	1
685	2
685	1
686	2
686	1
688	2
688	1
689	2
689	3
689	1
691	1
692	3
692	1
693	2
694	2
694	3
695	2
695	3
695	1
696	2
696	3
696	1
697	2
697	1
699	2
699	3
699	1
700	2
700	3
700	1
701	1
702	2
702	3
702	1
703	2
703	3
703	1
704	2
704	3
704	1
705	2
705	1
706	3
706	1
707	2
707	3
707	1
711	2
711	1
712	3
712	1
713	3
713	1
714	2
714	1
715	2
715	3
716	2
716	1
717	1
718	2
718	1
719	2
719	3
719	1
720	2
720	1
721	2
721	1
722	2
722	3
722	1
724	2
724	3
724	1
725	2
725	1
726	1
727	1
728	1
731	2
731	3
731	1
732	2
732	1
733	2
733	1
735	2
736	2
736	1
737	2
737	3
737	1
738	1
739	1
740	1
741	1
742	1
743	1
744	1
745	1
747	2
747	3
747	1
749	1
751	3
751	1
752	2
753	3
753	1
754	1
757	2
757	1
758	2
758	1
759	2
759	1
760	2
760	1
761	2
761	1
762	2
762	3
762	1
763	1
764	2
764	1
765	1
766	2
766	1
767	2
767	3
767	1
768	3
769	2
769	1
770	3
770	1
771	2
771	1
772	2
772	1
773	2
774	1
775	2
775	1
776	2
776	3
776	1
777	2
777	3
777	1
778	3
779	3
779	1
780	1
781	2
781	1
782	2
782	1
784	2
784	1
785	2
785	1
786	1
788	2
788	3
788	1
789	2
789	1
790	2
791	1
792	2
792	3
792	1
795	2
795	3
795	1
796	2
796	3
796	1
799	2
799	1
800	2
800	3
800	1
801	2
801	1
802	2
802	1
803	2
803	1
804	2
804	1
805	2
805	3
805	1
806	2
806	1
807	2
807	3
807	1
808	2
808	1
809	2
809	3
809	1
810	2
810	1
811	2
811	1
812	2
812	3
812	1
813	1
814	2
814	1
815	2
815	1
816	2
816	1
817	1
818	2
818	1
819	2
819	3
819	1
820	2
820	3
820	1
821	1
822	2
822	3
822	1
823	2
823	1
825	2
825	3
825	1
826	2
826	1
827	2
827	3
827	1
828	1
829	2
829	3
829	1
830	2
830	3
830	1
831	2
831	1
832	1
833	3
833	1
834	2
834	3
834	1
835	2
835	1
836	2
836	1
837	2
837	1
838	2
838	1
839	2
839	3
839	1
840	2
840	1
841	2
841	1
842	2
842	3
842	1
843	2
843	1
844	2
844	3
844	1
845	2
845	3
845	1
846	2
846	3
846	1
847	2
847	1
848	2
848	1
851	2
851	1
852	2
852	3
852	1
854	3
854	1
855	2
855	1
857	2
857	3
857	1
858	2
858	3
858	1
859	1
860	1
861	1
862	2
862	1
863	1
864	2
864	1
865	2
866	2
866	1
867	2
868	2
868	3
868	1
870	3
871	1
872	2
872	1
873	1
874	1
875	1
876	2
876	1
877	2
877	1
878	1
880	2
880	1
882	1
883	2
883	1
884	1
885	2
885	1
886	2
886	1
887	2
888	2
889	2
890	2
891	3
891	1
892	2
892	3
892	1
893	2
893	1
894	2
894	3
894	1
895	2
895	1
896	2
896	3
896	1
897	2
897	3
897	1
899	2
899	1
900	2
901	2
902	2
902	3
902	1
903	2
903	1
905	1
906	2
907	3
907	1
908	2
908	1
910	2
910	1
912	2
912	3
912	1
913	2
914	1
915	2
915	1
916	2
916	1
917	2
917	1
918	1
920	2
920	3
920	1
921	1
922	2
922	1
923	2
925	2
925	1
926	2
926	1
929	2
929	1
930	1
931	2
931	1
934	2
934	1
935	2
935	1
936	2
936	3
936	1
937	1
938	2
938	3
938	1
939	2
939	1
940	2
940	1
941	2
941	1
942	2
942	1
943	2
943	1
944	2
944	3
945	2
945	3
945	1
946	2
947	2
947	1
948	1
950	1
951	2
951	1
952	2
952	1
953	2
953	1
954	1
955	2
956	2
956	1
957	2
957	1
958	1
959	2
959	1
961	2
961	3
961	1
962	2
962	1
964	1
965	2
965	3
965	1
967	2
967	1
969	2
969	1
970	2
970	1
971	2
971	1
972	2
972	1
973	1
974	2
974	3
974	1
975	2
975	1
976	2
976	1
978	2
978	1
979	2
979	1
980	2
980	1
981	2
982	2
983	2
983	3
983	1
984	2
984	3
984	1
985	2
985	1
986	1
987	2
987	3
987	1
988	1
989	1
991	1
992	1
993	1
994	1
996	1
997	2
997	3
997	1
998	1
999	2
1000	1
1001	2
1001	1
1002	2
1002	1
1004	2
1005	2
1006	1
1007	2
1007	3
1007	1
1008	2
1008	1
1009	2
1009	1
1010	2
1010	1
1012	3
1012	1
1014	2
1014	1
1015	1
1016	2
1016	1
1017	2
1017	3
1017	1
1018	2
1018	1
1019	1
1020	2
1020	1
1021	2
1021	1
1022	2
1023	2
1023	1
1024	1
1026	2
1026	1
1028	1
1029	2
1029	3
1029	1
1031	2
1031	1
1032	1
1033	2
1033	1
1034	2
1037	2
1037	1
1039	1
1040	2
1040	1
1042	1
1043	1
1045	2
1045	1
1046	2
1046	1
1047	2
1047	1
1049	1
1050	2
1050	1
1051	2
1051	1
1052	2
1052	3
1052	1
\.


--
-- Data for Name: provider_revision; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.provider_revision (provider_revision_id, provider_id, discord_user_id, "timestamp", revision_index, source, slug, name, address, assessments_provided, description, email, hours_of_operation, phone, fsa, satellite_locations, fee_info, submitted_by, accessibility_available, website) FROM stdin;
\.


--
-- Data for Name: provider_revision_expertise; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.provider_revision_expertise (provider_revision_id, characteristic_id) FROM stdin;
\.


--
-- Data for Name: provider_revision_fee; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.provider_revision_fee (provider_revision_id, fee_id) FROM stdin;
\.


--
-- Data for Name: provider_revision_language; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.provider_revision_language (provider_revision_id, language_id) FROM stdin;
\.


--
-- Data for Name: provider_revision_referral_requirement; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.provider_revision_referral_requirement (provider_revision_id, referral_requirement_id) FROM stdin;
\.


--
-- Data for Name: provider_revision_service; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.provider_revision_service (provider_revision_id, service_id) FROM stdin;
\.


--
-- Data for Name: provider_revision_training; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.provider_revision_training (provider_revision_id, training_id) FROM stdin;
\.


--
-- Data for Name: provider_service; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.provider_service (provider_id, service_id) FROM stdin;
1	1
2	1
3	3
3	4
4	5
5	6
5	7
7	8
8	9
9	1
10	1
11	12
11	13
11	14
12	13
12	16
12	5
13	18
13	19
14	14
15	1
16	12
16	13
17	18
17	13
17	5
17	9
18	18
18	8
18	9
19	13
19	32
20	33
21	34
22	1
22	7
22	37
22	9
22	19
22	40
23	5
24	42
25	9
27	9
27	19
28	1
29	9
30	48
30	7
31	1
32	1
33	18
33	8
33	54
33	19
34	1
35	1
37	1
38	1
39	1
40	7
40	37
41	9
42	19
43	1
43	7
43	19
45	68
45	7
46	9
47	5
48	1
48	9
48	19
48	40
49	18
49	16
49	78
49	32
49	80
49	7
49	14
49	5
50	19
52	85
53	42
53	85
54	8
54	9
55	18
55	91
55	9
55	19
56	9
57	9
58	9
59	42
59	4
60	5
61	68
61	7
62	16
62	1
62	104
62	68
62	32
62	7
62	8
62	9
62	19
63	7
63	54
64	113
66	19
67	68
67	7
69	9
70	1
70	7
70	9
70	19
71	19
72	32
73	18
73	1
74	19
75	1
76	1
76	9
76	19
78	9
78	19
79	9
80	18
80	9
80	19
81	91
82	16
85	8
85	113
86	13
86	32
86	143
87	48
87	7
87	54
90	18
90	78
90	8
91	16
91	5
92	13
92	16
92	5
93	9
93	19
94	12
94	68
94	7
95	68
95	7
96	9
97	18
97	91
97	9
97	19
98	9
99	91
102	113
104	1
105	1
106	12
106	68
106	7
106	54
106	19
107	5
108	5
110	18
110	9
110	19
111	182
111	183
112	183
113	16
113	186
113	7
113	8
113	91
113	9
114	9
115	1
116	19
117	7
118	5
119	7
120	9
120	19
121	19
122	19
123	18
123	91
123	9
124	19
125	7
125	4
126	1
126	9
126	19
127	91
127	9
128	1
130	1
130	9
130	19
131	13
131	16
131	5
132	1
132	9
133	1
134	9
135	13
135	1
135	7
135	8
135	54
135	9
136	1
136	9
137	7
137	8
137	54
137	19
138	18
138	19
139	12
139	8
139	54
140	18
140	32
141	183
142	19
143	18
143	68
143	7
143	8
143	9
144	7
145	9
146	9
146	19
147	9
147	19
149	7
149	37
149	91
149	9
150	19
151	91
152	12
152	1
152	68
152	7
152	8
152	54
152	9
152	19
153	12
153	1
153	104
153	68
153	7
153	9
154	1
155	85
156	1
156	9
157	91
157	9
158	12
158	91
158	9
158	19
159	1
159	9
160	19
161	19
162	19
163	12
163	54
164	12
164	1
164	68
164	7
164	33
164	8
164	54
164	9
164	19
165	68
165	7
166	85
167	9
168	9
169	9
170	42
170	7
171	12
171	7
171	4
172	68
172	7
173	13
173	32
173	7
174	18
174	9
174	19
175	1
175	7
175	37
175	9
175	19
175	40
176	1
176	7
176	4
177	5
178	18
178	19
179	9
180	9
181	54
182	143
183	12
183	91
183	9
183	19
184	9
185	7
185	4
186	16
187	9
189	9
189	19
190	68
190	7
192	78
193	1
194	186
195	12
195	1
195	78
195	355
195	33
195	54
195	19
197	32
197	19
198	18
198	186
200	18
200	186
202	18
202	9
202	19
203	48
203	68
203	355
203	7
203	33
203	8
203	54
203	375
203	91
204	78
205	14
206	5
206	113
207	13
207	7
207	5
208	7
208	5
209	7
211	48
211	7
211	54
212	48
212	68
212	7
212	54
213	1
214	1
214	9
214	19
215	9
216	19
217	1
217	9
219	34
220	9
221	9
222	9
222	19
224	19
225	1
226	9
227	9
228	9
229	12
229	68
229	7
229	33
229	54
229	19
230	7
230	4
231	9
231	19
232	5
233	9
234	13
234	14
235	12
235	8
235	54
236	19
237	9
238	1
239	9
240	7
240	37
240	54
240	9
240	19
240	40
241	12
241	68
241	7
241	37
241	8
242	9
243	5
244	9
245	19
246	9
246	19
247	9
248	9
248	19
250	9
250	19
251	1
252	1
252	33
252	8
253	18
253	42
253	14
253	9
254	6
254	7
255	68
255	7
256	9
257	468
257	34
259	5
260	1
261	91
261	9
262	42
263	42
264	476
264	7
265	91
265	19
266	32
267	68
267	7
268	68
268	7
269	18
269	91
270	7
271	91
272	7
272	37
274	68
274	7
275	6
276	4
277	13
277	1
277	32
278	7
278	4
279	3
279	7
280	7
281	32
282	32
283	68
283	7
284	91
285	18
285	32
286	32
287	91
288	68
288	7
289	13
289	32
289	7
290	18
290	7
290	4
291	16
291	14
292	16
293	68
293	7
294	7
294	4
295	7
295	4
295	529
296	12
296	91
297	32
298	7
298	4
299	6
299	42
299	7
300	48
300	1
300	68
300	541
300	7
300	8
300	54
300	19
300	4
301	7
302	13
302	16
302	68
302	7
302	8
303	1
304	1
305	113
307	9
307	19
308	13
310	12
310	1
310	68
310	7
310	54
311	12
311	1
311	104
311	68
311	7
311	8
311	54
311	9
311	19
312	19
313	91
314	18
314	91
315	9
316	9
317	1
317	9
318	1
318	9
318	19
319	1
319	19
320	1
320	7
321	33
322	32
322	113
323	6
323	7
324	1
324	40
325	9
325	19
326	19
327	19
328	9
328	19
329	6
329	7
330	9
331	5
332	19
333	19
334	9
336	1
336	7
336	37
336	9
336	19
337	9
338	19
339	18
339	9
340	18
340	7
341	5
342	1
343	9
344	9
345	9
346	1
346	9
346	19
348	1
348	9
348	19
349	1
349	40
350	1
350	9
350	19
352	19
353	1
353	40
354	42
354	183
356	13
356	16
356	32
356	5
357	19
358	5
359	9
361	1
361	9
361	19
362	1
362	113
364	19
365	19
367	12
367	1
367	68
367	7
367	33
367	8
367	19
368	1
369	9
370	1
370	9
371	9
372	9
373	9
374	182
374	669
374	670
375	13
375	32
375	7
375	91
375	9
376	12
376	1
376	7
376	33
376	8
376	54
376	375
376	19
377	1
377	40
379	19
382	9
382	19
383	19
384	13
384	32
385	9
386	12
386	1
386	68
386	7
386	8
386	54
386	9
386	19
387	12
387	68
387	7
388	7
389	12
389	1
389	68
389	7
389	8
389	9
389	19
390	186
391	1
391	78
391	186
392	13
393	9
393	19
394	9
394	19
395	7
395	54
396	12
396	54
397	48
397	68
397	7
397	8
397	54
398	7
398	4
399	7
400	9
401	1
402	9
404	9
405	1
405	7
406	9
407	9
408	5
409	9
409	19
410	9
410	19
411	32
412	143
413	42
413	9
414	19
415	68
415	7
415	37
415	8
415	19
416	3
416	13
416	16
416	759
416	104
416	80
416	355
416	7
416	14
416	37
416	375
416	91
417	768
417	143
418	113
419	18
419	9
420	19
421	9
422	9
422	19
423	7
423	4
424	9
425	5
426	9
428	1
429	68
429	7
429	8
429	54
430	1
431	19
432	13
432	16
432	32
432	5
432	91
432	143
433	9
433	40
434	9
435	19
436	12
436	9
439	7
439	54
440	68
440	7
441	19
442	9
443	183
444	1
445	9
446	9
447	1
447	68
447	7
447	91
447	9
447	19
448	9
450	14
451	9
452	9
453	42
454	9
455	48
455	68
455	7
456	19
457	9
458	1
458	40
459	9
460	9
461	9
463	9
464	9
465	42
465	54
466	1
466	91
466	9
466	19
467	5
468	9
470	19
471	7
472	19
473	5
474	19
475	9
476	9
477	68
477	7
478	91
479	91
480	91
480	9
481	19
482	7
482	4
483	34
484	91
485	19
486	9
487	9
488	9
489	1
489	9
489	19
490	9
491	9
491	19
494	18
494	9
495	68
495	7
499	19
500	9
501	13
502	13
502	16
502	5
503	32
504	5
505	9
506	54
506	19
507	48
507	68
507	7
508	19
509	9
510	12
510	1
510	68
510	7
510	8
510	9
510	19
511	9
512	91
513	9
514	19
515	9
516	18
516	1
516	9
516	19
517	1
517	9
517	19
518	9
519	9
520	9
520	19
521	42
521	19
521	4
522	48
522	68
522	7
523	68
523	7
524	68
524	7
524	8
524	54
525	68
525	7
526	12
526	68
526	7
527	68
527	186
527	7
527	8
527	54
527	9
527	19
529	1
529	78
529	186
529	113
530	91
530	9
531	91
532	91
533	9
533	19
534	9
535	8
536	16
536	7
538	78
538	541
538	5
538	8
538	54
538	91
538	19
540	9
540	19
541	1
542	1
543	78
543	42
545	9
546	9
546	19
547	68
547	7
548	68
548	42
548	7
549	9
550	42
550	9
551	9
553	7
553	9
553	19
553	143
554	9
554	19
556	18
556	6
556	355
556	7
556	33
556	8
557	355
558	12
558	1
558	68
558	7
558	8
558	54
558	9
558	19
559	1
559	68
559	7
559	8
559	54
559	9
559	19
560	91
561	9
561	19
562	9
564	12
564	13
564	16
564	5
565	68
565	7
566	32
566	7
567	5
569	48
569	68
569	7
569	37
569	8
569	54
569	91
569	9
569	19
570	9
570	19
571	186
572	9
574	9
574	19
575	9
575	19
576	19
578	3
578	7
578	4
580	1
580	42
580	9
581	9
583	7
583	37
583	91
583	9
583	19
583	40
584	13
584	32
585	13
585	5
586	13
586	5
587	5
588	13
588	16
589	34
590	91
591	1060
592	9
592	19
593	9
593	19
594	18
594	91
594	9
595	91
595	9
596	19
597	7
599	9
600	9
601	85
602	1
603	9
604	1
605	1
607	5
608	19
610	9
611	9
612	9
612	19
613	68
613	7
614	14
616	68
616	7
617	186
618	186
618	7
619	186
619	7
620	186
621	186
622	18
622	186
623	186
624	1
624	186
625	19
626	18
626	78
626	8
627	1
628	5
629	1
629	68
629	7
629	8
629	9
630	9
631	16
631	7
632	16
632	7
633	1
633	9
633	19
634	12
634	91
635	9
636	5
637	68
637	7
638	18
638	14
638	5
640	91
641	9
641	19
642	9
643	104
643	7
644	1
644	7
644	54
645	1
645	7
645	54
646	48
646	7
646	54
647	91
647	9
648	9
649	19
649	4
650	9
651	18
651	9
652	32
653	9
654	9
655	19
656	18
656	9
656	19
657	18
657	9
657	19
658	7
658	91
659	9
659	19
660	13
660	32
660	54
660	9
661	16
661	7
662	9
662	19
663	12
663	1
663	68
663	541
663	7
663	8
663	54
663	9
663	19
664	7
664	37
665	9
666	9
666	19
667	91
668	9
669	1
670	9
670	19
671	18
671	19
672	3
672	9
672	19
673	355
673	33
673	8
673	54
674	48
674	1
674	54
674	19
675	186
676	7
676	54
677	12
677	68
677	7
677	33
677	8
677	54
679	42
679	375
681	183
682	113
684	1
685	68
685	7
685	8
685	19
686	16
686	5
686	9
687	1
688	13
689	18
689	1
689	541
689	14
689	91
689	9
689	19
690	1
691	18
691	355
691	8
691	54
691	19
692	1
692	19
694	7
695	19
696	3
696	68
696	7
696	8
696	54
696	19
696	4
697	186
697	7
698	18
698	1
698	68
698	7
698	8
698	54
698	19
699	91
700	91
701	91
701	19
702	18
702	32
702	355
702	14
702	375
702	9
703	186
703	7
704	9
705	18
705	9
706	1
706	19
707	19
709	1
711	9
712	3
712	186
712	7
713	355
714	42
715	7
715	4
716	1
717	19
718	19
719	91
720	12
720	13
720	1
720	104
720	68
720	32
720	7
720	37
720	8
720	54
720	9
720	19
721	12
721	68
721	7
722	18
722	68
722	33
722	8
722	19
723	1
724	9
725	183
726	1
726	40
727	9
728	1
728	40
729	1
729	68
729	7
729	37
729	91
729	9
729	19
730	1
730	9
730	19
731	9
731	19
734	1
735	48
735	9
736	12
736	8
737	9
738	9
739	34
741	1
742	1
743	19
744	1
745	34
746	1
746	68
746	7
746	8
746	54
746	9
747	9
748	1
750	19
752	183
753	34
754	9
755	1
756	1
756	40
757	9
757	19
758	16
758	5
759	9
760	18
760	13
760	32
761	9
762	91
763	19
764	9
765	1
765	42
765	9
766	13
767	68
767	7
767	113
768	48
768	68
768	7
769	33
770	32
771	9
771	19
772	9
774	1
775	12
775	1
775	759
775	104
775	7
775	33
775	8
775	54
775	19
776	1
776	7
776	8
776	91
776	9
776	19
776	40
777	5
778	6
778	7
779	85
780	113
781	9
781	19
783	1
783	7
783	91
783	9
783	19
783	40
784	143
785	18
785	16
785	33
785	5
786	12
786	1
786	104
786	68
786	7
786	8
786	54
786	9
786	19
790	9
791	9
792	13
793	1
793	7
793	19
795	32
795	9
796	12
796	1
796	68
796	7
796	33
796	8
796	54
799	1
799	68
799	7
799	8
799	54
799	9
799	19
800	18
800	1
800	42
801	19
802	18
802	9
802	19
803	9
804	9
805	5
806	19
807	7
807	9
808	9
810	19
811	9
813	1
814	9
815	12
815	1
815	68
815	7
815	8
815	54
815	9
815	19
817	85
818	19
819	1
820	1
820	104
820	68
820	7
820	8
820	54
820	9
820	19
821	1
821	68
821	541
821	7
821	8
821	54
821	91
821	9
821	19
822	91
822	9
823	12
823	1
823	68
823	7
823	8
823	54
823	9
823	19
824	1
825	7
826	9
827	91
827	9
828	186
828	7
829	91
830	1
831	7
832	9
833	1
834	9
834	19
835	9
836	78
836	5
837	18
837	32
837	14
837	5
838	18
838	9
838	19
839	68
839	7
839	8
839	54
839	19
840	18
840	68
840	7
840	54
840	19
840	4
841	19
842	355
843	91
843	9
843	19
845	68
845	7
846	13
846	1
846	9
847	9
847	19
848	12
848	1
848	68
848	7
848	8
848	54
848	9
848	19
849	541
849	7
849	37
849	8
849	91
849	9
850	1
850	7
851	18
851	1
851	78
851	8
851	54
851	4
852	12
852	68
852	7
852	33
852	54
853	1
853	68
853	7
853	8
853	54
853	19
854	12
854	1
854	68
854	7
854	8
854	54
854	9
854	19
855	12
855	7
855	54
856	186
857	12
857	186
858	12
858	7
858	54
859	113
860	113
861	1
862	9
864	18
864	186
865	48
865	1
865	68
865	7
866	48
866	16
866	104
866	68
866	7
866	37
866	8
866	54
866	91
866	19
867	3
867	7
867	4
868	1
868	9
868	40
869	183
870	7
870	9
871	9
872	19
873	91
874	32
875	32
875	9
876	5
877	1060
878	355
879	48
879	68
879	7
880	32
882	48
882	355
882	33
882	8
882	54
882	19
883	9
884	7
884	54
885	48
885	68
885	7
886	541
886	7
886	37
886	8
886	19
886	40
889	7
889	54
891	1
891	40
892	1
893	91
893	9
895	9
896	9
898	7
898	54
899	48
899	7
899	54
900	1
901	9
901	19
902	91
903	9
905	9
905	19
906	1
906	78
906	541
906	7
906	37
906	8
906	91
906	9
906	40
907	1
907	19
908	18
908	186
909	1
909	78
909	186
909	7
910	1
910	1707
910	1708
910	34
911	1
912	54
913	183
915	9
916	113
917	91
918	1
920	9
921	18
921	355
922	9
922	19
923	48
923	68
923	7
924	186
925	186
926	186
927	91
928	91
929	42
930	113
931	9
932	1
934	355
935	85
936	68
936	7
936	8
936	54
936	9
936	19
937	1
938	7
938	14
939	18
939	7
939	14
941	18
941	19
942	18
942	19
943	18
943	9
944	68
944	7
946	7
947	182
948	34
950	1
950	19
951	9
951	19
952	19
953	759
956	13
956	32
956	5
956	143
957	18
957	5
958	1
959	1
961	7
961	4
962	91
962	9
963	91
963	9
964	32
964	541
964	7
964	5
964	91
964	9
965	13
965	16
965	32
965	7
965	5
966	13
966	16
966	32
966	5
967	13
967	32
967	5
969	13
969	32
969	113
970	9
971	12
971	1
971	42
971	19
972	1805
973	9
974	12
974	91
974	19
975	1805
976	5
976	8
977	5
977	8
978	18
978	68
978	7
978	37
978	8
979	18
979	5
980	91
981	18
981	13
981	16
981	14
981	5
982	9
982	19
983	18
983	6
983	7
983	33
983	8
983	4
983	768
984	48
984	13
984	6
984	32
984	355
984	7
984	14
984	33
984	8
984	375
984	19
984	529
985	42
985	468
986	68
986	7
986	8
987	91
987	9
987	19
988	1
988	68
988	7
988	8
988	54
988	9
988	19
989	18
989	68
989	7
990	1
990	68
990	7
991	7
991	54
992	54
993	1
993	40
994	1
995	68
995	7
995	37
995	8
995	91
995	9
995	19
996	19
997	9
998	7
998	54
999	5
1000	19
1001	19
1002	48
1002	68
1002	355
1002	7
1002	33
1002	8
1002	54
1002	19
1003	13
1003	16
1003	541
1003	7
1003	37
1003	5
1003	91
1004	18
1004	16
1004	32
1004	541
1004	7
1004	33
1004	9
1005	7
1005	4
1006	85
1007	18
1007	68
1007	7
1008	48
1008	54
1009	9
1009	19
1010	16
1010	68
1010	7
1010	8
1010	54
1010	9
1010	19
1011	13
1011	32
1011	355
1011	54
1012	1
1014	68
1014	7
1015	78
1015	355
1016	12
1016	54
1017	1
1017	78
1017	9
1018	91
1019	91
1020	91
1020	9
1021	12
1021	1
1021	68
1021	7
1021	8
1021	54
1021	91
1022	12
1022	7
1022	54
1023	9
1023	19
1024	1
1026	48
1026	1
1026	68
1026	7
1026	8
1026	54
1026	9
1026	19
1028	12
1028	1
1028	40
1029	18
1029	1
1029	355
1029	14
1029	37
1029	33
1029	54
1029	9
1029	19
1030	12
1030	1
1030	9
1030	19
1031	186
1032	1
1032	91
1032	19
1033	12
1033	1
1033	9
1033	19
1034	3
1034	7
1034	37
1034	9
1034	19
1035	7
1035	54
1037	12
1037	1
1037	9
1037	19
1037	40
1038	12
1038	1
1038	9
1038	19
1039	12
1039	1
1040	1
1040	9
1042	18
1042	1
1042	40
1043	12
1043	1
1043	9
1043	19
1044	16
1044	7
1045	18
1045	9
1046	18
1046	9
1047	8
1047	91
1047	9
1047	19
1048	12
1048	1
1048	104
1048	7
1048	54
1048	9
1048	19
1048	40
1049	12
1049	1
1049	9
1049	19
1049	40
1050	9
1051	78
1051	14
1052	9
\.


--
-- Data for Name: provider_training; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.provider_training (provider_id, training_id) FROM stdin;
3	1
21	1
24	1
33	1
33	5
33	6
33	7
33	8
33	9
42	1
42	8
42	12
69	1
72	5
72	6
72	8
74	1
74	18
74	5
74	8
123	1
123	18
123	5
123	8
123	25
125	1
139	1
139	18
139	5
139	6
139	7
139	8
139	9
139	25
139	12
143	1
160	1
161	1
163	1
163	25
163	12
164	25
164	12
176	1
181	1
181	25
185	1
185	25
185	12
200	1
204	1
224	1
224	5
224	8
224	9
224	12
229	1
229	25
229	12
236	1
236	18
236	5
236	12
242	1
242	18
242	5
242	6
254	12
266	1
266	5
266	6
266	8
269	1
275	12
296	1
296	12
297	1
297	6
297	8
298	1
298	18
298	25
315	1
315	5
326	1
326	18
326	6
327	1
327	18
327	5
340	1
379	1
379	5
379	25
379	12
382	1
387	1
387	6
387	25
387	12
396	1
396	18
396	5
396	6
396	8
396	25
396	12
402	1
402	5
402	6
402	8
404	1
404	18
404	12
414	1
414	5
414	6
431	1
431	6
431	25
435	1
435	12
436	18
442	18
442	6
453	1
454	1
454	18
454	5
454	6
454	8
474	1
474	8
481	1
485	1
486	1
486	18
495	1
495	25
499	1
509	1
509	18
509	5
509	6
514	1
514	18
514	5
518	1
518	18
518	5
556	1
556	5
557	1
557	5
557	25
579	12
594	1
594	6
599	1
603	1
603	18
603	5
603	6
608	1
608	8
634	18
637	25
637	12
640	1
640	6
672	1
674	1
674	25
674	12
679	5
679	8
705	1
705	18
705	6
705	25
705	12
717	1
736	1
736	8
769	1
769	18
769	5
769	6
769	7
769	8
772	1
772	18
775	5
775	6
801	1
840	1
840	18
840	5
840	6
840	7
840	8
874	1
874	25
880	1
882	1
882	25
882	12
912	1
912	5
912	6
912	7
912	8
941	12
944	1
944	18
944	5
944	6
944	25
944	12
952	1
970	1
970	8
978	25
984	1
984	8
997	6
997	8
1001	1
1002	12
1007	1
1007	25
1008	1
1008	5
1008	8
1008	9
1008	25
1008	12
\.


--
-- Data for Name: referral_requirement; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.referral_requirement (id, referral_requirement_kind) FROM stdin;
1	Self Referral
2	Appointment Required
3	Referral from doctor
\.


--
-- Data for Name: review; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.review (provider_id, discord_user_id, text, score) FROM stdin;
\.


--
-- Data for Name: rho_training; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.rho_training (id, training_kind) FROM stdin;
1	Foundations for all health care providers working with trans, non-binary, and gender non-conforming adult clients (19+)
5	Introduction to LGBT2SQ and health needs
6	Introduction to LGBT2SQ emotional and mental health
7	LGBT seniors and health needs
8	Removing the barriers: making your organization LGBT2SQ-positive
9	Transition in the workplace
12	Transition-related Surgeries: planning, referral, and care (5.5 Mainpro-M1 credits)
18	Foundations for trans-positive counselling
25	Transition-Related Hormone Therapy in Primary Care (5.0 Mainpro-M1 credits)
\.


--
-- Data for Name: service; Type: TABLE DATA; Schema: public; Owner: transontario
--

COPY public.service (id, service_kind) FROM stdin;
1	Community Services or groups
3	Hospital Department
4	Specialized (Other)
5	Registered Massage Therapist
6	Endocrinologist
7	Physician
8	Registered Nurse
9	Registered Psychotherapist
12	Community Health Centre
13	Acupuncturist
14	Physiotherapist
16	Chiropractor
18	Team of Service Providers
19	Registered Social Worker
32	Naturopath
33	Registered Dietitian
34	Peer support worker
37	Psychiatrist
40	Residential Programs
42	Individual
48	Family Health Team
54	Registered Nurse Practitioner
68	Family Physician
78	Home Care
80	Orthopaedist
85	Speech Language Pathologist
91	Registered Psychologist
104	Dentist
113	Doula
143	Homeopath
182	Cosmetician
183	Electrolysis
186	Midwife
355	Pharmacist
375	Registered Nutritionist
468	Binder, Gaffe and/or Prosthetics Supplier
476	ENT
529	Urologist
541	Occupational Therapist
669	Makeup Artist
670	Tattoo Artist
759	Dental Hygienist
768	Fertility Services
1060	Osteopath
1707	Lawyer
1708	Notary
1805	Vocal Coach
\.


--
-- Name: characteristic_id_seq; Type: SEQUENCE SET; Schema: public; Owner: transontario
--

SELECT pg_catalog.setval('public.characteristic_id_seq', 8198, true);


--
-- Name: fee_id_seq; Type: SEQUENCE SET; Schema: public; Owner: transontario
--

SELECT pg_catalog.setval('public.fee_id_seq', 1513, true);


--
-- Name: language_id_seq; Type: SEQUENCE SET; Schema: public; Owner: transontario
--

SELECT pg_catalog.setval('public.language_id_seq', 1397, true);


--
-- Name: provider_id_seq; Type: SEQUENCE SET; Schema: public; Owner: transontario
--

SELECT pg_catalog.setval('public.provider_id_seq', 1052, true);


--
-- Name: provider_revision_provider_revision_id_seq; Type: SEQUENCE SET; Schema: public; Owner: transontario
--

SELECT pg_catalog.setval('public.provider_revision_provider_revision_id_seq', 1, false);


--
-- Name: referral_requirement_id_seq; Type: SEQUENCE SET; Schema: public; Owner: transontario
--

SELECT pg_catalog.setval('public.referral_requirement_id_seq', 1834, true);


--
-- Name: rho_training_id_seq; Type: SEQUENCE SET; Schema: public; Owner: transontario
--

SELECT pg_catalog.setval('public.rho_training_id_seq', 237, true);


--
-- Name: service_id_seq; Type: SEQUENCE SET; Schema: public; Owner: transontario
--

SELECT pg_catalog.setval('public.service_id_seq', 2045, true);


--
-- Name: characteristic characteristic_person_kind_key; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.characteristic
    ADD CONSTRAINT characteristic_person_kind_key UNIQUE (person_kind);


--
-- Name: characteristic characteristic_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.characteristic
    ADD CONSTRAINT characteristic_pkey PRIMARY KEY (id);


--
-- Name: discord_user discord_user_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.discord_user
    ADD CONSTRAINT discord_user_pkey PRIMARY KEY (id);


--
-- Name: fee fee_fee_kind_key; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.fee
    ADD CONSTRAINT fee_fee_kind_key UNIQUE (fee_kind);


--
-- Name: fee fee_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.fee
    ADD CONSTRAINT fee_pkey PRIMARY KEY (id);


--
-- Name: fsa fsa_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.fsa
    ADD CONSTRAINT fsa_pkey PRIMARY KEY (fsa);


--
-- Name: language language_language_name_key; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.language
    ADD CONSTRAINT language_language_name_key UNIQUE (language_name);


--
-- Name: language language_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.language
    ADD CONSTRAINT language_pkey PRIMARY KEY (id);


--
-- Name: provider_expertise provider_expertise_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_expertise
    ADD CONSTRAINT provider_expertise_pkey PRIMARY KEY (provider_id, characteristic_id);


--
-- Name: provider_fee provider_fee_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_fee
    ADD CONSTRAINT provider_fee_pkey PRIMARY KEY (provider_id, fee_id);


--
-- Name: provider_language provider_language_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_language
    ADD CONSTRAINT provider_language_pkey PRIMARY KEY (provider_id, language_id);


--
-- Name: provider provider_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider
    ADD CONSTRAINT provider_pkey PRIMARY KEY (id);


--
-- Name: provider_referral_requirement provider_referral_requirement_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_referral_requirement
    ADD CONSTRAINT provider_referral_requirement_pkey PRIMARY KEY (provider_id, referral_requirement_id);


--
-- Name: provider_revision_expertise provider_revision_expertise_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision_expertise
    ADD CONSTRAINT provider_revision_expertise_pkey PRIMARY KEY (provider_revision_id, characteristic_id);


--
-- Name: provider_revision_fee provider_revision_fee_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision_fee
    ADD CONSTRAINT provider_revision_fee_pkey PRIMARY KEY (provider_revision_id, fee_id);


--
-- Name: provider_revision_language provider_revision_language_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision_language
    ADD CONSTRAINT provider_revision_language_pkey PRIMARY KEY (provider_revision_id, language_id);


--
-- Name: provider_revision provider_revision_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision
    ADD CONSTRAINT provider_revision_pkey PRIMARY KEY (provider_revision_id);


--
-- Name: provider_revision provider_revision_provider_id_revision_index_key; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision
    ADD CONSTRAINT provider_revision_provider_id_revision_index_key UNIQUE (provider_id, revision_index);


--
-- Name: provider_revision_referral_requirement provider_revision_referral_requirement_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision_referral_requirement
    ADD CONSTRAINT provider_revision_referral_requirement_pkey PRIMARY KEY (provider_revision_id, referral_requirement_id);


--
-- Name: provider_revision_service provider_revision_service_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision_service
    ADD CONSTRAINT provider_revision_service_pkey PRIMARY KEY (provider_revision_id, service_id);


--
-- Name: provider_revision_training provider_revision_training_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision_training
    ADD CONSTRAINT provider_revision_training_pkey PRIMARY KEY (provider_revision_id, training_id);


--
-- Name: provider_service provider_service_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_service
    ADD CONSTRAINT provider_service_pkey PRIMARY KEY (provider_id, service_id);


--
-- Name: provider provider_slug_key; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider
    ADD CONSTRAINT provider_slug_key UNIQUE (slug);


--
-- Name: provider_training provider_training_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_training
    ADD CONSTRAINT provider_training_pkey PRIMARY KEY (provider_id, training_id);


--
-- Name: referral_requirement referral_requirement_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.referral_requirement
    ADD CONSTRAINT referral_requirement_pkey PRIMARY KEY (id);


--
-- Name: referral_requirement referral_requirement_referral_requirement_kind_key; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.referral_requirement
    ADD CONSTRAINT referral_requirement_referral_requirement_kind_key UNIQUE (referral_requirement_kind);


--
-- Name: review review_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.review
    ADD CONSTRAINT review_pkey PRIMARY KEY (provider_id, discord_user_id);


--
-- Name: rho_training rho_training_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.rho_training
    ADD CONSTRAINT rho_training_pkey PRIMARY KEY (id);


--
-- Name: rho_training rho_training_training_kind_key; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.rho_training
    ADD CONSTRAINT rho_training_training_kind_key UNIQUE (training_kind);


--
-- Name: service service_pkey; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.service
    ADD CONSTRAINT service_pkey PRIMARY KEY (id);


--
-- Name: service service_service_kind_key; Type: CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.service
    ADD CONSTRAINT service_service_kind_key UNIQUE (service_kind);


--
-- Name: auth auth; Type: TRIGGER; Schema: api; Owner: transontario
--

CREATE TRIGGER auth INSTEAD OF INSERT OR DELETE OR UPDATE ON api.auth FOR EACH ROW EXECUTE FUNCTION public.do_auth();


--
-- Name: reviews do_post_review; Type: TRIGGER; Schema: api; Owner: transontario
--

CREATE TRIGGER do_post_review INSTEAD OF INSERT OR DELETE OR UPDATE ON api.reviews FOR EACH ROW EXECUTE FUNCTION public.post_review();


--
-- Name: providers do_update_provider; Type: TRIGGER; Schema: api; Owner: transontario
--

CREATE TRIGGER do_update_provider INSTEAD OF INSERT OR UPDATE ON api.providers FOR EACH ROW EXECUTE FUNCTION public.update_provider();


--
-- Name: provider_expertise provider_expertise_characteristic_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_expertise
    ADD CONSTRAINT provider_expertise_characteristic_id_fkey FOREIGN KEY (characteristic_id) REFERENCES public.characteristic(id);


--
-- Name: provider_expertise provider_expertise_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_expertise
    ADD CONSTRAINT provider_expertise_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.provider(id);


--
-- Name: provider_fee provider_fee_fee_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_fee
    ADD CONSTRAINT provider_fee_fee_id_fkey FOREIGN KEY (fee_id) REFERENCES public.fee(id);


--
-- Name: provider_fee provider_fee_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_fee
    ADD CONSTRAINT provider_fee_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.provider(id);


--
-- Name: provider_language provider_language_language_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_language
    ADD CONSTRAINT provider_language_language_id_fkey FOREIGN KEY (language_id) REFERENCES public.language(id);


--
-- Name: provider_language provider_language_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_language
    ADD CONSTRAINT provider_language_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.provider(id);


--
-- Name: provider_referral_requirement provider_referral_requirement_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_referral_requirement
    ADD CONSTRAINT provider_referral_requirement_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.provider(id);


--
-- Name: provider_referral_requirement provider_referral_requirement_referral_requirement_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_referral_requirement
    ADD CONSTRAINT provider_referral_requirement_referral_requirement_id_fkey FOREIGN KEY (referral_requirement_id) REFERENCES public.referral_requirement(id);


--
-- Name: provider_revision provider_revision_discord_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision
    ADD CONSTRAINT provider_revision_discord_user_id_fkey FOREIGN KEY (discord_user_id) REFERENCES public.discord_user(id);


--
-- Name: provider_revision_expertise provider_revision_expertise_characteristic_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision_expertise
    ADD CONSTRAINT provider_revision_expertise_characteristic_id_fkey FOREIGN KEY (characteristic_id) REFERENCES public.characteristic(id);


--
-- Name: provider_revision_expertise provider_revision_expertise_provider_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision_expertise
    ADD CONSTRAINT provider_revision_expertise_provider_revision_id_fkey FOREIGN KEY (provider_revision_id) REFERENCES public.provider_revision(provider_revision_id);


--
-- Name: provider_revision_fee provider_revision_fee_fee_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision_fee
    ADD CONSTRAINT provider_revision_fee_fee_id_fkey FOREIGN KEY (fee_id) REFERENCES public.fee(id);


--
-- Name: provider_revision_fee provider_revision_fee_provider_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision_fee
    ADD CONSTRAINT provider_revision_fee_provider_revision_id_fkey FOREIGN KEY (provider_revision_id) REFERENCES public.provider_revision(provider_revision_id);


--
-- Name: provider_revision_language provider_revision_language_language_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision_language
    ADD CONSTRAINT provider_revision_language_language_id_fkey FOREIGN KEY (language_id) REFERENCES public.language(id);


--
-- Name: provider_revision_language provider_revision_language_provider_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision_language
    ADD CONSTRAINT provider_revision_language_provider_revision_id_fkey FOREIGN KEY (provider_revision_id) REFERENCES public.provider_revision(provider_revision_id);


--
-- Name: provider_revision provider_revision_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision
    ADD CONSTRAINT provider_revision_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.provider(id);


--
-- Name: provider_revision_referral_requirement provider_revision_referral_require_referral_requirement_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision_referral_requirement
    ADD CONSTRAINT provider_revision_referral_require_referral_requirement_id_fkey FOREIGN KEY (referral_requirement_id) REFERENCES public.referral_requirement(id);


--
-- Name: provider_revision_referral_requirement provider_revision_referral_requiremen_provider_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision_referral_requirement
    ADD CONSTRAINT provider_revision_referral_requiremen_provider_revision_id_fkey FOREIGN KEY (provider_revision_id) REFERENCES public.provider_revision(provider_revision_id);


--
-- Name: provider_revision_service provider_revision_service_provider_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision_service
    ADD CONSTRAINT provider_revision_service_provider_revision_id_fkey FOREIGN KEY (provider_revision_id) REFERENCES public.provider_revision(provider_revision_id);


--
-- Name: provider_revision_service provider_revision_service_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision_service
    ADD CONSTRAINT provider_revision_service_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.service(id);


--
-- Name: provider_revision_training provider_revision_training_provider_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision_training
    ADD CONSTRAINT provider_revision_training_provider_revision_id_fkey FOREIGN KEY (provider_revision_id) REFERENCES public.provider_revision(provider_revision_id);


--
-- Name: provider_revision_training provider_revision_training_training_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_revision_training
    ADD CONSTRAINT provider_revision_training_training_id_fkey FOREIGN KEY (training_id) REFERENCES public.rho_training(id);


--
-- Name: provider_service provider_service_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_service
    ADD CONSTRAINT provider_service_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.provider(id);


--
-- Name: provider_service provider_service_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_service
    ADD CONSTRAINT provider_service_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.service(id);


--
-- Name: provider_training provider_training_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_training
    ADD CONSTRAINT provider_training_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.provider(id);


--
-- Name: provider_training provider_training_training_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.provider_training
    ADD CONSTRAINT provider_training_training_id_fkey FOREIGN KEY (training_id) REFERENCES public.rho_training(id);


--
-- Name: review review_discord_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.review
    ADD CONSTRAINT review_discord_user_id_fkey FOREIGN KEY (discord_user_id) REFERENCES public.discord_user(id);


--
-- Name: review review_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: transontario
--

ALTER TABLE ONLY public.review
    ADD CONSTRAINT review_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.provider(id);


--
-- Name: review; Type: ROW SECURITY; Schema: public; Owner: transontario
--

ALTER TABLE public.review ENABLE ROW LEVEL SECURITY;

--
-- Name: review review_policy; Type: POLICY; Schema: public; Owner: transontario
--

CREATE POLICY review_policy ON public.review USING (true) WITH CHECK ((((current_setting('request.jwt.claims'::text, true))::json ->> 'id'::text) = discord_user_id));


--
-- Name: review review_policy_delete; Type: POLICY; Schema: public; Owner: transontario
--

CREATE POLICY review_policy_delete ON public.review AS RESTRICTIVE FOR DELETE USING ((((current_setting('request.jwt.claims'::text, true))::json ->> 'id'::text) = discord_user_id));


--
-- Name: review review_policy_update; Type: POLICY; Schema: public; Owner: transontario
--

CREATE POLICY review_policy_update ON public.review AS RESTRICTIVE FOR UPDATE USING ((((current_setting('request.jwt.claims'::text, true))::json ->> 'id'::text) = discord_user_id));


--
-- Name: SCHEMA api; Type: ACL; Schema: -; Owner: transontario
--

GRANT USAGE ON SCHEMA api TO editor;
GRANT USAGE ON SCHEMA api TO web_anon;


--
-- Name: TABLE auth; Type: ACL; Schema: api; Owner: transontario
--

GRANT SELECT,INSERT ON TABLE api.auth TO web_anon;


--
-- Name: TABLE characteristic; Type: ACL; Schema: public; Owner: transontario
--

GRANT SELECT ON TABLE public.characteristic TO editor;


--
-- Name: TABLE characteristics; Type: ACL; Schema: api; Owner: transontario
--

GRANT SELECT ON TABLE api.characteristics TO web_anon;
GRANT SELECT ON TABLE api.characteristics TO editor;


--
-- Name: TABLE discord_application; Type: ACL; Schema: api; Owner: transontario
--

GRANT SELECT ON TABLE api.discord_application TO web_anon;


--
-- Name: TABLE fee; Type: ACL; Schema: public; Owner: transontario
--

GRANT SELECT ON TABLE public.fee TO editor;


--
-- Name: TABLE fees; Type: ACL; Schema: api; Owner: transontario
--

GRANT SELECT ON TABLE api.fees TO web_anon;
GRANT SELECT ON TABLE api.fees TO editor;


--
-- Name: TABLE language; Type: ACL; Schema: public; Owner: transontario
--

GRANT SELECT ON TABLE public.language TO editor;


--
-- Name: TABLE languages; Type: ACL; Schema: api; Owner: transontario
--

GRANT SELECT ON TABLE api.languages TO web_anon;
GRANT SELECT ON TABLE api.languages TO editor;


--
-- Name: TABLE discord_user; Type: ACL; Schema: public; Owner: transontario
--

GRANT SELECT ON TABLE public.discord_user TO editor;
GRANT SELECT,INSERT,UPDATE ON TABLE public.discord_user TO web_anon;


--
-- Name: TABLE me; Type: ACL; Schema: api; Owner: transontario
--

GRANT SELECT ON TABLE api.me TO editor;


--
-- Name: TABLE provider; Type: ACL; Schema: public; Owner: transontario
--

GRANT ALL ON TABLE public.provider TO editor;


--
-- Name: TABLE provider_expertise; Type: ACL; Schema: public; Owner: transontario
--

GRANT ALL ON TABLE public.provider_expertise TO editor;


--
-- Name: TABLE provider_fee; Type: ACL; Schema: public; Owner: transontario
--

GRANT ALL ON TABLE public.provider_fee TO editor;


--
-- Name: TABLE provider_language; Type: ACL; Schema: public; Owner: transontario
--

GRANT ALL ON TABLE public.provider_language TO editor;


--
-- Name: TABLE provider_referral_requirement; Type: ACL; Schema: public; Owner: transontario
--

GRANT ALL ON TABLE public.provider_referral_requirement TO editor;


--
-- Name: TABLE provider_service; Type: ACL; Schema: public; Owner: transontario
--

GRANT ALL ON TABLE public.provider_service TO editor;


--
-- Name: TABLE provider_training; Type: ACL; Schema: public; Owner: transontario
--

GRANT ALL ON TABLE public.provider_training TO editor;


--
-- Name: TABLE referral_requirement; Type: ACL; Schema: public; Owner: transontario
--

GRANT SELECT ON TABLE public.referral_requirement TO editor;


--
-- Name: TABLE review; Type: ACL; Schema: public; Owner: transontario
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.review TO editor;


--
-- Name: TABLE rho_training; Type: ACL; Schema: public; Owner: transontario
--

GRANT SELECT ON TABLE public.rho_training TO editor;


--
-- Name: TABLE service; Type: ACL; Schema: public; Owner: transontario
--

GRANT SELECT ON TABLE public.service TO editor;


--
-- Name: TABLE providers; Type: ACL; Schema: api; Owner: transontario
--

GRANT SELECT ON TABLE api.providers TO web_anon;
GRANT SELECT,INSERT,UPDATE ON TABLE api.providers TO editor;


--
-- Name: TABLE referral_requirements; Type: ACL; Schema: api; Owner: transontario
--

GRANT SELECT ON TABLE api.referral_requirements TO web_anon;
GRANT SELECT ON TABLE api.referral_requirements TO editor;


--
-- Name: TABLE regions; Type: ACL; Schema: api; Owner: transontario
--

GRANT SELECT ON TABLE api.regions TO web_anon;
GRANT SELECT ON TABLE api.regions TO editor;


--
-- Name: TABLE reviews; Type: ACL; Schema: api; Owner: transontario
--

GRANT SELECT ON TABLE api.reviews TO web_anon;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE api.reviews TO editor;


--
-- Name: TABLE services; Type: ACL; Schema: api; Owner: transontario
--

GRANT SELECT ON TABLE api.services TO web_anon;
GRANT SELECT ON TABLE api.services TO editor;


--
-- Name: TABLE training; Type: ACL; Schema: api; Owner: transontario
--

GRANT SELECT ON TABLE api.training TO web_anon;
GRANT SELECT ON TABLE api.training TO editor;


--
-- Name: TABLE provider_revision; Type: ACL; Schema: public; Owner: transontario
--

GRANT SELECT,INSERT ON TABLE public.provider_revision TO editor;


--
-- Name: TABLE provider_revision_expertise; Type: ACL; Schema: public; Owner: transontario
--

GRANT SELECT,INSERT ON TABLE public.provider_revision_expertise TO editor;


--
-- Name: TABLE provider_revision_fee; Type: ACL; Schema: public; Owner: transontario
--

GRANT SELECT,INSERT ON TABLE public.provider_revision_fee TO editor;


--
-- Name: TABLE provider_revision_language; Type: ACL; Schema: public; Owner: transontario
--

GRANT SELECT,INSERT ON TABLE public.provider_revision_language TO editor;


--
-- Name: SEQUENCE provider_revision_provider_revision_id_seq; Type: ACL; Schema: public; Owner: transontario
--

GRANT ALL ON SEQUENCE public.provider_revision_provider_revision_id_seq TO editor;


--
-- Name: TABLE provider_revision_referral_requirement; Type: ACL; Schema: public; Owner: transontario
--

GRANT SELECT,INSERT ON TABLE public.provider_revision_referral_requirement TO editor;


--
-- Name: TABLE provider_revision_service; Type: ACL; Schema: public; Owner: transontario
--

GRANT SELECT,INSERT ON TABLE public.provider_revision_service TO editor;


--
-- Name: TABLE provider_revision_training; Type: ACL; Schema: public; Owner: transontario
--

GRANT SELECT,INSERT ON TABLE public.provider_revision_training TO editor;


--
-- PostgreSQL database dump complete
--

--
-- PostgreSQL database cluster dump complete
--

