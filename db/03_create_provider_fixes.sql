CREATE OR REPLACE FUNCTION public.update_provider() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE _provider_id INTEGER; _provider_revision_id INTEGER;
BEGIN
	INSERT INTO provider(
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
		CASE WHEN (TG_OP = 'UPDATE') THEN
		  OLD.source  -- cannot be changed
		ELSE 
		  'user'
		END,
		CASE WHEN (TG_OP = 'UPDATE') THEN
		  OLD.slug  -- cannot be changed
		ELSE 
		  NEW.slug 
		END,
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
	) ON CONFLICT(slug) DO UPDATE SET 
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
		website = NEW.website
        RETURNING provider.id INTO _provider_id;

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
		_provider_id,
	        (current_setting('request.jwt.claims', true)::json->>'id'),
		now(),
		COALESCE((select revision_index + 1 from provider_revision where provider_id = _provider_id order by revision_index desc limit 1), 1),
		CASE WHEN (TG_OP = 'UPDATE') THEN
		  OLD.source  -- cannot be changed
		ELSE 
		  'user'
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

	INSERT INTO provider_revision_expertise(
		provider_revision_id,
		characteristic_id
	) SELECT
		_provider_revision_id,
		characteristic.id
	FROM UNNEST(NEW.specializes_in) AS characteristic_name
	LEFT JOIN characteristic ON characteristic.person_kind = characteristic_name;

	DELETE FROM provider_expertise WHERE provider_id = _provider_id;
	INSERT INTO provider_expertise(
		provider_id,
		characteristic_id
	) SELECT
		_provider_id,
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

	DELETE FROM provider_training WHERE provider_id = _provider_id;
	INSERT INTO provider_training(
		provider_id,
		training_id
	) SELECT
		_provider_id,
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

	DELETE FROM provider_referral_requirement WHERE provider_id = _provider_id;
	INSERT INTO provider_referral_requirement(
		provider_id,
		referral_requirement_id
	) SELECT
		_provider_id,
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

	DELETE FROM provider_language WHERE provider_id = _provider_id;
	INSERT INTO provider_language(
		provider_id,
		language_id
	) SELECT
		_provider_id,
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

	DELETE FROM provider_fee WHERE provider_id = _provider_id;
	INSERT INTO provider_fee(
		provider_id,
		fee_id
	) SELECT
		_provider_id,
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

	DELETE FROM provider_service WHERE provider_id = _provider_id;
	INSERT INTO provider_service(
		provider_id,
		service_id
	) SELECT
		_provider_id,
		service_id
	FROM provider_revision_service WHERE provider_revision_service.provider_revision_id = _provider_revision_id;

	RETURN NEW;
END;
$$;


GRANT ALL ON SEQUENCE public.provider_id_seq TO editor;
