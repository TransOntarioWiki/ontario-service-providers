DROP TABLE provider_revision CASCADE;
CREATE TABLE IF NOT EXISTS provider_revision(
	provider_revision_id SERIAL PRIMARY KEY,
	provider_id INTEGER NOT NULL,
	discord_user_id TEXT,
	timestamp TIMESTAMP WITH TIME ZONE,
	revision_index INTEGER,
	source TEXT,
	slug TEXT NOT NULL,
	name TEXT,
	address TEXT,
	assessments_provided TEXT,
	description TEXT,
	email TEXT,
	hours_of_operation TEXT,
	phone TEXT,
	fsa TEXT,
	satellite_locations TEXT,
	fee_info TEXT,
	submitted_by TEXT,
	accessibility_available INTEGER,
	website TEXT,
	UNIQUE(provider_id, revision_index),
	FOREIGN KEY(provider_id) REFERENCES provider(id),
	FOREIGN KEY(discord_user_id) REFERENCES discord_user(id)
);

DROP TABLE provider_revision_expertise CASCADE;
CREATE TABLE IF NOT EXISTS provider_revision_expertise(
	provider_revision_id INTEGER NOT NULL,
	characteristic_id INTEGER NOT NULL,
	FOREIGN KEY(provider_revision_id) REFERENCES provider_revision(provider_revision_id),
	FOREIGN KEY(characteristic_id) REFERENCES characteristic(id),
	PRIMARY KEY(provider_revision_id, characteristic_id)
);

DROP TABLE provider_revision_training CASCADE;
CREATE TABLE IF NOT EXISTS provider_revision_training(
	provider_revision_id INTEGER NOT NULL,
	training_id INTEGER NOT NULL,
	FOREIGN KEY(provider_revision_id) REFERENCES provider_revision(provider_revision_id),
	FOREIGN KEY(training_id) REFERENCES rho_training(id),
	PRIMARY KEY(provider_revision_id, training_id)
);

DROP TABLE provider_revision_referral_requirement CASCADE;
CREATE TABLE IF NOT EXISTS provider_revision_referral_requirement(
	provider_revision_id INTEGER NOT NULL,
	referral_requirement_id INTEGER NOT NULL,
	FOREIGN KEY(provider_revision_id) REFERENCES provider_revision(provider_revision_id),
	FOREIGN KEY(referral_requirement_id) REFERENCES referral_requirement(id),
	PRIMARY KEY(provider_revision_id, referral_requirement_id)
);

DROP TABLE provider_revision_language CASCADE;
CREATE TABLE IF NOT EXISTS provider_revision_language(
	provider_revision_id INTEGER NOT NULL,
	language_id INTEGER NOT NULL,
	FOREIGN KEY(provider_revision_id) REFERENCES provider_revision(provider_revision_id),
	FOREIGN KEY(language_id) REFERENCES language(id),
	PRIMARY KEY(provider_revision_id, language_id)
);

DROP TABLE provider_revision_fee CASCADE;
CREATE TABLE IF NOT EXISTS provider_revision_fee(
	provider_revision_id INTEGER NOT NULL,
	fee_id INTEGER NOT NULL,
	FOREIGN KEY(provider_revision_id) REFERENCES provider_revision(provider_revision_id),
	FOREIGN KEY(fee_id) REFERENCES fee(id),
	PRIMARY KEY(provider_revision_id, fee_id)
);

DROP TABLE provider_revision_service CASCADE;
CREATE TABLE IF NOT EXISTS provider_revision_service(
	provider_revision_id INTEGER NOT NULL,
	service_id INTEGER NOT NULL,
	FOREIGN KEY(provider_revision_id) REFERENCES provider_revision(provider_revision_id),
	FOREIGN KEY(service_id) REFERENCES service(id),
	PRIMARY KEY(provider_revision_id, service_id)
);

CREATE OR REPLACE FUNCTION update_provider() RETURNS TRIGGER AS $$
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
$$ LANGUAGE plpgsql;

CREATE TRIGGER do_update_provider
INSTEAD OF UPDATE OR INSERT ON api.providers
	FOR EACH ROW EXECUTE PROCEDURE update_provider();

GRANT UPDATE ON api.providers TO editor;
GRANT INSERT ON api.providers TO editor;

GRANT SELECT ON provider_revision TO editor;
GRANT INSERT ON provider_revision TO editor;
GRANT ALL ON provider_revision_provider_revision_id_seq TO editor;

GRANT ALL ON provider TO editor;
GRANT ALL ON provider_expertise TO editor;
GRANT ALL ON provider_training TO editor;
GRANT ALL ON provider_referral_requirement TO editor;
GRANT ALL ON provider_language TO editor;
GRANT ALL ON provider_fee TO editor;
GRANT ALL ON provider_service TO editor;

GRANT INSERT ON provider_revision_expertise TO editor;
GRANT SELECT ON provider_revision_expertise TO editor;
GRANT INSERT ON provider_revision_training TO editor;
GRANT SELECT ON provider_revision_training TO editor;
GRANT INSERT ON provider_revision_referral_requirement TO editor;
GRANT SELECT ON provider_revision_referral_requirement TO editor;
GRANT INSERT ON provider_revision_language TO editor;
GRANT SELECT ON provider_revision_language TO editor;
GRANT INSERT ON provider_revision_fee TO editor;
GRANT SELECT ON provider_revision_fee TO editor;
GRANT INSERT ON provider_revision_service TO editor;
GRANT SELECT ON provider_revision_service TO editor;

GRANT SELECT ON characteristic TO editor;
GRANT SELECT ON rho_training TO editor;
GRANT SELECT ON referral_requirement TO editor;
GRANT SELECT ON language TO editor;
GRANT SELECT ON fee TO editor;
GRANT SELECT ON service TO editor;
