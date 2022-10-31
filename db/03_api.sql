DROP SCHEMA IF EXISTS api CASCADE;
CREATE SCHEMA api;

CREATE ROLE editor nologin;
GRANT editor TO authenticator;
GRANT USAGE ON SCHEMA api TO editor;

CREATE ROLE web_anon nologin;
GRANT USAGE ON SCHEMA api TO web_anon;

CREATE VIEW api.languages AS SELECT language_name AS language FROM language;
GRANT SELECT ON api.languages TO web_anon;
GRANT SELECT ON api.languages TO editor;

CREATE VIEW api.characteristics AS SELECT person_kind AS characteristic FROM characteristic;
GRANT SELECT ON api.characteristics TO web_anon;
GRANT SELECT ON api.characteristics TO editor;

CREATE VIEW api.training AS SELECT training_kind FROM rho_training;
GRANT SELECT ON api.training TO web_anon;
GRANT SELECT ON api.training TO editor;

CREATE VIEW api.fees AS SELECT fee_kind AS fee FROM fee;
GRANT SELECT ON api.fees TO web_anon;
GRANT SELECT ON api.fees TO editor;

CREATE VIEW api.services AS SELECT service_kind AS service FROM service;
GRANT SELECT ON api.services TO web_anon;
GRANT SELECT ON api.services TO editor;

CREATE VIEW api.regions AS SELECT DISTINCT region FROM fsa;
GRANT SELECT ON api.regions TO web_anon;
GRANT SELECT ON api.regions TO editor;

CREATE VIEW api.reviews AS SELECT provider_id, text, score, username, discriminator, avatar FROM review LEFT JOIN discord_user ON review.discord_user_id = discord_user.id;
GRANT SELECT ON api.reviews TO web_anon;
GRANT SELECT ON api.reviews TO editor;

ALTER TABLE review ENABLE ROW LEVEL SECURITY;

CREATE POLICY review_policy ON review AS PERMISSIVE
  USING (true)
  WITH CHECK (current_setting('request.jwt.claims', true)::json->>'id' = discord_user_id);

CREATE POLICY review_policy_update ON review AS RESTRICTIVE FOR UPDATE
  USING (current_setting('request.jwt.claims', true)::json->>'id' = discord_user_id);

CREATE POLICY review_policy_delete ON review AS RESTRICTIVE FOR DELETE
  USING (current_setting('request.jwt.claims', true)::json->>'id' = discord_user_id);
  
CREATE VIEW api.providers AS
  SELECT
    slug,
    source,
    name,
    address,
    assessments_provided,
    description,
    email,
    hours_of_operation,
    phone,
    satellite_locations,
    fee_info,
    submitted_by,
    accessibility_available,
    website,
    region,
    languages,
    specializes_in,
    training,
    referral_requirements,
    fees,
    services,
    review_count
  FROM provider
  LEFT JOIN fsa ON provider.fsa = fsa.fsa
  LEFT JOIN (
    SELECT provider.id, array_agg(language_name) filter (where language is not null) AS languages
    FROM provider
    LEFT JOIN provider_language ON provider_language.provider_id = provider.id
    LEFT JOIN language ON language.id = provider_language.language_id
    GROUP BY 1
  ) q1 ON provider.id = q1.id
  LEFT JOIN (
    SELECT provider.id, array_agg(person_kind) filter (where characteristic is not null) AS specializes_in
    FROM provider
    LEFT JOIN provider_expertise ON provider_expertise.provider_id = provider.id
    LEFT JOIN characteristic ON characteristic.id = provider_expertise.characteristic_id
    GROUP BY 1
  ) q2 ON provider.id = q2.id
  LEFT JOIN (
    SELECT provider.id, array_agg(training_kind) filter (where rho_training is not null) AS training
    FROM provider
    LEFT JOIN provider_training ON provider_training.provider_id = provider.id
    LEFT JOIN rho_training ON rho_training.id = provider_training.training_id
    GROUP BY 1
  ) q3 ON provider.id = q3.id
  LEFT JOIN (
    SELECT provider.id, array_agg(referral_requirement_kind) filter (where referral_requirement is not null) AS referral_requirements
    FROM provider
    LEFT JOIN provider_referral_requirement ON provider_referral_requirement.provider_id = provider.id
    LEFT JOIN referral_requirement ON referral_requirement.id = provider_referral_requirement.referral_requirement_id
    GROUP BY 1
  ) q4 ON provider.id = q4.id
  LEFT JOIN (
    SELECT provider.id, array_agg(fee_kind) filter (where fee is not null) AS fees
    FROM provider
    LEFT JOIN provider_fee ON provider_fee.provider_id = provider.id
    LEFT JOIN fee ON fee.id = provider_fee.fee_id
    GROUP BY 1
  ) q5 ON provider.id = q5.id
  LEFT JOIN (
    SELECT provider.id, array_agg(service_kind) filter (where service is not null) AS services
    FROM provider
    LEFT JOIN provider_service ON provider_service.provider_id = provider.id
    LEFT JOIN service ON service.id = provider_service.service_id
    GROUP BY 1
  ) q6 ON provider.id = q6.id
  LEFT JOIN (
    SELECT provider.id, count(review) AS review_count
    FROM provider
    LEFT JOIN review ON review.provider_id = provider.id
    GROUP BY 1
  ) q7 on provider.id = q7.id
  ORDER BY review_count DESC
;
GRANT SELECT ON api.providers TO web_anon;
GRANT SELECT ON api.providers TO editor;

CREATE OR REPLACE FUNCTION post_review() RETURNS TRIGGER AS $$
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
$$ LANGUAGE plpgsql;

CREATE TRIGGER do_post_review
INSTEAD OF INSERT OR UPDATE OR DELETE ON api.reviews
    FOR EACH ROW EXECUTE FUNCTION post_review();

GRANT INSERT ON api.reviews TO editor;
GRANT UPDATE ON api.reviews TO editor;
GRANT DELETE ON api.reviews TO editor;
GRANT SELECT ON review TO editor;
GRANT INSERT ON review TO editor;
GRANT UPDATE ON review TO editor;
GRANT DELETE ON review TO editor;

GRANT SELECT ON discord_user TO editor;

CREATE VIEW api.me AS SELECT username, discriminator, avatar FROM discord_user WHERE discord_user.id = current_setting('request.jwt.claims', true)::json->>'id';

;
GRANT SELECT ON api.me TO editor;
