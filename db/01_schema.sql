DROP TABLE discord_user CASCADE;
DROP TABLE characteristic CASCADE;
DROP TABLE rho_training CASCADE;
DROP TABLE referral_requirement CASCADE;
DROP TABLE language CASCADE;
DROP TABLE fee CASCADE;
DROP TABLE service CASCADE;
DROP TABLE provider CASCADE;
DROP TABLE provider_expertise CASCADE;
DROP TABLE provider_referral_requirement CASCADE;
DROP TABLE provider_language CASCADE;
DROP TABLE provider_training CASCADE;
DROP TABLE provider_fee CASCADE;
DROP TABLE provider_service CASCADE;
DROP TABLE review CASCADE;
DROP TABLE fsa CASCADE;

CREATE TABLE IF NOT EXISTS discord_user(
	id TEXT PRIMARY KEY NOT NULL,
	username TEXT NOT NULL,
	discriminator TEXT NOT NULL,
	avatar TEXT
);

CREATE TABLE IF NOT EXISTS characteristic(
	id SERIAL PRIMARY KEY,
	person_kind TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS rho_training(
	id SERIAL PRIMARY KEY,
	training_kind TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS referral_requirement(
	id SERIAL PRIMARY KEY,
	referral_requirement_kind TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS language(
	id SERIAL PRIMARY KEY,
	language_name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS fee(
	id SERIAL PRIMARY KEY,
	fee_kind TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS service(
	id SERIAL PRIMARY KEY,
	service_kind TEXT NOT NULL UNIQUE
);
	
CREATE TABLE IF NOT EXISTS provider(
	id SERIAL PRIMARY KEY,
	source TEXT NOT NULL DEFAULT 'rho',
	slug TEXT NOT NULL UNIQUE,
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
	website TEXT
);

CREATE TABLE IF NOT EXISTS provider_expertise(
	provider_id INTEGER NOT NULL,
	characteristic_id INTEGER NOT NULL,
	FOREIGN KEY(provider_id) REFERENCES provider(id),
	FOREIGN KEY(characteristic_id) REFERENCES characteristic(id),
	PRIMARY KEY(provider_id, characteristic_id)
);

CREATE TABLE IF NOT EXISTS provider_training(
	provider_id INTEGER NOT NULL,
	training_id INTEGER NOT NULL,
	FOREIGN KEY(provider_id) REFERENCES provider(id),
	FOREIGN KEY(training_id) REFERENCES rho_training(id),
	PRIMARY KEY(provider_id, training_id)
);

CREATE TABLE IF NOT EXISTS provider_referral_requirement(
	provider_id INTEGER NOT NULL,
	referral_requirement_id INTEGER NOT NULL,
	FOREIGN KEY(provider_id) REFERENCES provider(id),
	FOREIGN KEY(referral_requirement_id) REFERENCES referral_requirement(id),
	PRIMARY KEY(provider_id, referral_requirement_id)
);

CREATE TABLE IF NOT EXISTS provider_language(
	provider_id INTEGER NOT NULL,
	language_id INTEGER NOT NULL,
	FOREIGN KEY(provider_id) REFERENCES provider(id),
	FOREIGN KEY(language_id) REFERENCES language(id),
	PRIMARY KEY(provider_id, language_id)
);

CREATE TABLE IF NOT EXISTS provider_fee(
	provider_id INTEGER NOT NULL,
	fee_id INTEGER NOT NULL,
	FOREIGN KEY(provider_id) REFERENCES provider(id),
	FOREIGN KEY(fee_id) REFERENCES fee(id),
	PRIMARY KEY(provider_id, fee_id)
);

CREATE TABLE IF NOT EXISTS provider_service(
	provider_id INTEGER NOT NULL,
	service_id INTEGER NOT NULL,
	FOREIGN KEY(provider_id) REFERENCES provider(id),
	FOREIGN KEY(service_id) REFERENCES service(id),
	PRIMARY KEY(provider_id, service_id)
);

CREATE TABLE IF NOT EXISTS review(
	provider_id INTEGER NOT NULL,
	discord_user_id TEXT,
	text TEXT NOT NULL,
	score INTEGER NOT NULL,
	FOREIGN KEY(provider_id) REFERENCES provider(id),
	FOREIGN KEY(discord_user_id) REFERENCES discord_user(id),
	PRIMARY KEY(provider_id, discord_user_id)
);

CREATE TABLE IF NOT EXISTS fsa(
	fsa TEXT PRIMARY KEY NOT NULL,
	region TEXT NOT NULL
);

INSERT INTO fsa VALUES('K1A', 'ottawa');
INSERT INTO fsa VALUES('K2A', 'ottawa');
INSERT INTO fsa VALUES('K4A', 'ottawa');
INSERT INTO fsa VALUES('K6A', 'ottawa');
INSERT INTO fsa VALUES('K7A', 'ottawa');
INSERT INTO fsa VALUES('K8A', 'ottawa');
INSERT INTO fsa VALUES('K9A', 'kingston');
INSERT INTO fsa VALUES('K1B', 'ottawa');
INSERT INTO fsa VALUES('K2B', 'ottawa');
INSERT INTO fsa VALUES('K4B', 'ottawa');
INSERT INTO fsa VALUES('K8B', 'ottawa');
INSERT INTO fsa VALUES('K1C', 'ottawa');
INSERT INTO fsa VALUES('K2C', 'ottawa');
INSERT INTO fsa VALUES('K4C', 'ottawa');
INSERT INTO fsa VALUES('K7C', 'ottawa');
INSERT INTO fsa VALUES('K1E', 'ottawa');
INSERT INTO fsa VALUES('K2E', 'ottawa');
INSERT INTO fsa VALUES('K1G', 'ottawa');
INSERT INTO fsa VALUES('K2G', 'ottawa');
INSERT INTO fsa VALUES('K7G', 'kingston');
INSERT INTO fsa VALUES('K1H', 'ottawa');
INSERT INTO fsa VALUES('K2H', 'ottawa');
INSERT INTO fsa VALUES('K6H', 'ottawa');
INSERT INTO fsa VALUES('K7H', 'ottawa');
INSERT INTO fsa VALUES('K8H', 'ottawa');
INSERT INTO fsa VALUES('K9H', 'durham');
INSERT INTO fsa VALUES('K1J', 'ottawa');
INSERT INTO fsa VALUES('K2J', 'ottawa');
INSERT INTO fsa VALUES('K6J', 'ottawa');
INSERT INTO fsa VALUES('K9J', 'durham');
INSERT INTO fsa VALUES('K1K', 'ottawa');
INSERT INTO fsa VALUES('K2K', 'ottawa');
INSERT INTO fsa VALUES('K4K', 'ottawa');
INSERT INTO fsa VALUES('K6K', 'ottawa');
INSERT INTO fsa VALUES('K7K', 'kingston');
INSERT INTO fsa VALUES('K9K', 'durham');
INSERT INTO fsa VALUES('K1L', 'ottawa');
INSERT INTO fsa VALUES('K2L', 'ottawa');
INSERT INTO fsa VALUES('K7L', 'kingston');
INSERT INTO fsa VALUES('K9L', 'durham');
INSERT INTO fsa VALUES('K1M', 'ottawa');
INSERT INTO fsa VALUES('K2M', 'ottawa');
INSERT INTO fsa VALUES('K4M', 'ottawa');
INSERT INTO fsa VALUES('K7M', 'kingston');
INSERT INTO fsa VALUES('K1N', 'ottawa');
INSERT INTO fsa VALUES('K7N', 'kingston');
INSERT INTO fsa VALUES('K8N', 'kingston');
INSERT INTO fsa VALUES('K1P', 'ottawa');
INSERT INTO fsa VALUES('K2P', 'ottawa');
INSERT INTO fsa VALUES('K4P', 'ottawa');
INSERT INTO fsa VALUES('K7P', 'kingston');
INSERT INTO fsa VALUES('K8P', 'kingston');
INSERT INTO fsa VALUES('K1R', 'ottawa');
INSERT INTO fsa VALUES('K2R', 'ottawa');
INSERT INTO fsa VALUES('K4R', 'ottawa');
INSERT INTO fsa VALUES('K7R', 'kingston');
INSERT INTO fsa VALUES('K8R', 'kingston');
INSERT INTO fsa VALUES('K1S', 'ottawa');
INSERT INTO fsa VALUES('K2S', 'ottawa');
INSERT INTO fsa VALUES('K7S', 'ottawa');
INSERT INTO fsa VALUES('K1T', 'ottawa');
INSERT INTO fsa VALUES('K2T', 'ottawa');
INSERT INTO fsa VALUES('K6T', 'kingston');
INSERT INTO fsa VALUES('K1V', 'ottawa');
INSERT INTO fsa VALUES('K2V', 'ottawa');
INSERT INTO fsa VALUES('K6V', 'kingston');
INSERT INTO fsa VALUES('K7V', 'ottawa');
INSERT INTO fsa VALUES('K8V', 'kingston');
INSERT INTO fsa VALUES('K9V', 'durham');
INSERT INTO fsa VALUES('K1W', 'ottawa');
INSERT INTO fsa VALUES('K2W', 'ottawa');
INSERT INTO fsa VALUES('K1X', 'ottawa');
INSERT INTO fsa VALUES('K1Y', 'ottawa');
INSERT INTO fsa VALUES('K1Z', 'ottawa');
INSERT INTO fsa VALUES('L1A', 'durham');
INSERT INTO fsa VALUES('L2A', 'niagara');
INSERT INTO fsa VALUES('L4A', 'york');
INSERT INTO fsa VALUES('L5A', 'peel');
INSERT INTO fsa VALUES('L6A', 'york');
INSERT INTO fsa VALUES('L7A', 'peel');
INSERT INTO fsa VALUES('L9A', 'hamilton');
INSERT INTO fsa VALUES('L1B', 'durham');
INSERT INTO fsa VALUES('L3B', 'niagara');
INSERT INTO fsa VALUES('L4B', 'york');
INSERT INTO fsa VALUES('L5B', 'peel');
INSERT INTO fsa VALUES('L6B', 'york');
INSERT INTO fsa VALUES('L7B', 'york');
INSERT INTO fsa VALUES('L8B', 'hamilton');
INSERT INTO fsa VALUES('L9B', 'hamilton');
INSERT INTO fsa VALUES('L1C', 'durham');
INSERT INTO fsa VALUES('L3C', 'niagara');
INSERT INTO fsa VALUES('L4C', 'york');
INSERT INTO fsa VALUES('L5C', 'peel');
INSERT INTO fsa VALUES('L6C', 'york');
INSERT INTO fsa VALUES('L7C', 'peel');
INSERT INTO fsa VALUES('L9C', 'hamilton');
INSERT INTO fsa VALUES('L1E', 'durham');
INSERT INTO fsa VALUES('L2E', 'niagara');
INSERT INTO fsa VALUES('L4E', 'york');
INSERT INTO fsa VALUES('L5E', 'peel');
INSERT INTO fsa VALUES('L6E', 'york');
INSERT INTO fsa VALUES('L7E', 'peel');
INSERT INTO fsa VALUES('L8E', 'hamilton');
INSERT INTO fsa VALUES('L9E', 'hamilton');
INSERT INTO fsa VALUES('L1G', 'durham');
INSERT INTO fsa VALUES('L2G', 'niagara');
INSERT INTO fsa VALUES('L4G', 'york');
INSERT INTO fsa VALUES('L5G', 'peel');
INSERT INTO fsa VALUES('L6G', 'york');
INSERT INTO fsa VALUES('L7G', 'peel');
INSERT INTO fsa VALUES('L8G', 'hamilton');
INSERT INTO fsa VALUES('L9G', 'hamilton');
INSERT INTO fsa VALUES('L1H', 'durham');
INSERT INTO fsa VALUES('L2H', 'niagara');
INSERT INTO fsa VALUES('L4H', 'york');
INSERT INTO fsa VALUES('L5H', 'peel');
INSERT INTO fsa VALUES('L6H', 'hamilton');
INSERT INTO fsa VALUES('L8H', 'hamilton');
INSERT INTO fsa VALUES('L9H', 'hamilton');
INSERT INTO fsa VALUES('L1J', 'durham');
INSERT INTO fsa VALUES('L2J', 'niagara');
INSERT INTO fsa VALUES('L3J', 'niagara');
INSERT INTO fsa VALUES('L4J', 'york');
INSERT INTO fsa VALUES('L5J', 'peel');
INSERT INTO fsa VALUES('L6J', 'hamilton');
INSERT INTO fsa VALUES('L7J', 'peel');
INSERT INTO fsa VALUES('L8J', 'hamilton');
INSERT INTO fsa VALUES('L9J', 'barrie');
INSERT INTO fsa VALUES('L1K', 'durham');
INSERT INTO fsa VALUES('L3K', 'niagara');
INSERT INTO fsa VALUES('L4K', 'york');
INSERT INTO fsa VALUES('L5K', 'peel');
INSERT INTO fsa VALUES('L6K', 'hamilton');
INSERT INTO fsa VALUES('L7K', 'peel');
INSERT INTO fsa VALUES('L8K', 'hamilton');
INSERT INTO fsa VALUES('L9K', 'hamilton');
INSERT INTO fsa VALUES('L1L', 'durham');
INSERT INTO fsa VALUES('L3L', 'york');
INSERT INTO fsa VALUES('L4L', 'york');
INSERT INTO fsa VALUES('L5L', 'peel');
INSERT INTO fsa VALUES('L6L', 'hamilton');
INSERT INTO fsa VALUES('L7L', 'hamilton');
INSERT INTO fsa VALUES('L8L', 'hamilton');
INSERT INTO fsa VALUES('L9L', 'durham');
INSERT INTO fsa VALUES('L1M', 'durham');
INSERT INTO fsa VALUES('L2M', 'niagara');
INSERT INTO fsa VALUES('L3M', 'hamilton');
INSERT INTO fsa VALUES('L4M', 'barrie');
INSERT INTO fsa VALUES('L5M', 'peel');
INSERT INTO fsa VALUES('L6M', 'hamilton');
INSERT INTO fsa VALUES('L7M', 'hamilton');
INSERT INTO fsa VALUES('L8M', 'hamilton');
INSERT INTO fsa VALUES('L9M', 'barrie');
INSERT INTO fsa VALUES('L1N', 'durham');
INSERT INTO fsa VALUES('L2N', 'niagara');
INSERT INTO fsa VALUES('L4N', 'barrie');
INSERT INTO fsa VALUES('L5N', 'peel');
INSERT INTO fsa VALUES('L7N', 'hamilton');
INSERT INTO fsa VALUES('L8N', 'hamilton');
INSERT INTO fsa VALUES('L9N', 'york');
INSERT INTO fsa VALUES('L1P', 'durham');
INSERT INTO fsa VALUES('L2P', 'niagara');
INSERT INTO fsa VALUES('L3P', 'york');
INSERT INTO fsa VALUES('L4P', 'barrie');
INSERT INTO fsa VALUES('L5P', 'peel');
INSERT INTO fsa VALUES('L6P', 'peel');
INSERT INTO fsa VALUES('L7P', 'hamilton');
INSERT INTO fsa VALUES('L8P', 'hamilton');
INSERT INTO fsa VALUES('L9P', 'durham');
INSERT INTO fsa VALUES('L1R', 'durham');
INSERT INTO fsa VALUES('L2R', 'niagara');
INSERT INTO fsa VALUES('L3R', 'york');
INSERT INTO fsa VALUES('L4R', 'barrie');
INSERT INTO fsa VALUES('L5R', 'peel');
INSERT INTO fsa VALUES('L6R', 'peel');
INSERT INTO fsa VALUES('L7R', 'hamilton');
INSERT INTO fsa VALUES('L8R', 'hamilton');
INSERT INTO fsa VALUES('L9R', 'barrie');
INSERT INTO fsa VALUES('L1S', 'durham');
INSERT INTO fsa VALUES('L2S', 'niagara');
INSERT INTO fsa VALUES('L3S', 'york');
INSERT INTO fsa VALUES('L4S', 'york');
INSERT INTO fsa VALUES('L5S', 'peel');
INSERT INTO fsa VALUES('L6S', 'peel');
INSERT INTO fsa VALUES('L7S', 'hamilton');
INSERT INTO fsa VALUES('L8S', 'hamilton');
INSERT INTO fsa VALUES('L9S', 'barrie');
INSERT INTO fsa VALUES('L1T', 'durham');
INSERT INTO fsa VALUES('L2T', 'niagara');
INSERT INTO fsa VALUES('L3T', 'york');
INSERT INTO fsa VALUES('L4T', 'peel');
INSERT INTO fsa VALUES('L5T', 'peel');
INSERT INTO fsa VALUES('L6T', 'peel');
INSERT INTO fsa VALUES('L7T', 'hamilton');
INSERT INTO fsa VALUES('L8T', 'hamilton');
INSERT INTO fsa VALUES('L9T', 'hamilton');
INSERT INTO fsa VALUES('L1V', 'durham');
INSERT INTO fsa VALUES('L2V', 'niagara');
INSERT INTO fsa VALUES('L3V', 'barrie');
INSERT INTO fsa VALUES('L4V', 'peel');
INSERT INTO fsa VALUES('L5V', 'peel');
INSERT INTO fsa VALUES('L6V', 'peel');
INSERT INTO fsa VALUES('L8V', 'hamilton');
INSERT INTO fsa VALUES('L9V', 'peel');
INSERT INTO fsa VALUES('L1W', 'durham');
INSERT INTO fsa VALUES('L2W', 'niagara');
INSERT INTO fsa VALUES('L4W', 'peel');
INSERT INTO fsa VALUES('L5W', 'peel');
INSERT INTO fsa VALUES('L6W', 'peel');
INSERT INTO fsa VALUES('L8W', 'hamilton');
INSERT INTO fsa VALUES('L9W', 'peel');
INSERT INTO fsa VALUES('L1X', 'durham');
INSERT INTO fsa VALUES('L3X', 'york');
INSERT INTO fsa VALUES('L4X', 'peel');
INSERT INTO fsa VALUES('L6X', 'peel');
INSERT INTO fsa VALUES('L9X', 'barrie');
INSERT INTO fsa VALUES('L1Y', 'durham');
INSERT INTO fsa VALUES('L3Y', 'york');
INSERT INTO fsa VALUES('L4Y', 'peel');
INSERT INTO fsa VALUES('L6Y', 'peel');
INSERT INTO fsa VALUES('L9Y', 'barrie');
INSERT INTO fsa VALUES('L1Z', 'durham');
INSERT INTO fsa VALUES('L3Z', 'york');
INSERT INTO fsa VALUES('L4Z', 'peel');
INSERT INTO fsa VALUES('L6Z', 'peel');
INSERT INTO fsa VALUES('L9Z', 'barrie');
INSERT INTO fsa VALUES('M3A', 'toronto');
INSERT INTO fsa VALUES('M4A', 'toronto');
INSERT INTO fsa VALUES('M5A', 'toronto');
INSERT INTO fsa VALUES('M6A', 'toronto');
INSERT INTO fsa VALUES('M7A', 'toronto');
INSERT INTO fsa VALUES('M9A', 'toronto');
INSERT INTO fsa VALUES('M1B', 'toronto');
INSERT INTO fsa VALUES('M3B', 'toronto');
INSERT INTO fsa VALUES('M4B', 'toronto');
INSERT INTO fsa VALUES('M5B', 'toronto');
INSERT INTO fsa VALUES('M6B', 'toronto');
INSERT INTO fsa VALUES('M9B', 'toronto');
INSERT INTO fsa VALUES('M1C', 'toronto');
INSERT INTO fsa VALUES('M3C', 'toronto');
INSERT INTO fsa VALUES('M4C', 'toronto');
INSERT INTO fsa VALUES('M5C', 'toronto');
INSERT INTO fsa VALUES('M6C', 'toronto');
INSERT INTO fsa VALUES('M9C', 'toronto');
INSERT INTO fsa VALUES('M1E', 'toronto');
INSERT INTO fsa VALUES('M4E', 'toronto');
INSERT INTO fsa VALUES('M5E', 'toronto');
INSERT INTO fsa VALUES('M6E', 'toronto');
INSERT INTO fsa VALUES('M1G', 'toronto');
INSERT INTO fsa VALUES('M4G', 'toronto');
INSERT INTO fsa VALUES('M5G', 'toronto');
INSERT INTO fsa VALUES('M6G', 'toronto');
INSERT INTO fsa VALUES('M1H', 'toronto');
INSERT INTO fsa VALUES('M2H', 'toronto');
INSERT INTO fsa VALUES('M3H', 'toronto');
INSERT INTO fsa VALUES('M4H', 'toronto');
INSERT INTO fsa VALUES('M5H', 'toronto');
INSERT INTO fsa VALUES('M6H', 'toronto');
INSERT INTO fsa VALUES('M1J', 'toronto');
INSERT INTO fsa VALUES('M2J', 'toronto');
INSERT INTO fsa VALUES('M3J', 'toronto');
INSERT INTO fsa VALUES('M4J', 'toronto');
INSERT INTO fsa VALUES('M5J', 'toronto');
INSERT INTO fsa VALUES('M6J', 'toronto');
INSERT INTO fsa VALUES('M1K', 'toronto');
INSERT INTO fsa VALUES('M2K', 'toronto');
INSERT INTO fsa VALUES('M3K', 'toronto');
INSERT INTO fsa VALUES('M4K', 'toronto');
INSERT INTO fsa VALUES('M5K', 'toronto');
INSERT INTO fsa VALUES('M6K', 'toronto');
INSERT INTO fsa VALUES('M1L', 'toronto');
INSERT INTO fsa VALUES('M2L', 'toronto');
INSERT INTO fsa VALUES('M3L', 'toronto');
INSERT INTO fsa VALUES('M4L', 'toronto');
INSERT INTO fsa VALUES('M5L', 'toronto');
INSERT INTO fsa VALUES('M6L', 'toronto');
INSERT INTO fsa VALUES('M9L', 'toronto');
INSERT INTO fsa VALUES('M1M', 'toronto');
INSERT INTO fsa VALUES('M2M', 'toronto');
INSERT INTO fsa VALUES('M3M', 'toronto');
INSERT INTO fsa VALUES('M4M', 'toronto');
INSERT INTO fsa VALUES('M5M', 'toronto');
INSERT INTO fsa VALUES('M6M', 'toronto');
INSERT INTO fsa VALUES('M9M', 'toronto');
INSERT INTO fsa VALUES('M1N', 'toronto');
INSERT INTO fsa VALUES('M2N', 'toronto');
INSERT INTO fsa VALUES('M3N', 'toronto');
INSERT INTO fsa VALUES('M4N', 'toronto');
INSERT INTO fsa VALUES('M5N', 'toronto');
INSERT INTO fsa VALUES('M6N', 'toronto');
INSERT INTO fsa VALUES('M9N', 'toronto');
INSERT INTO fsa VALUES('M1P', 'toronto');
INSERT INTO fsa VALUES('M2P', 'toronto');
INSERT INTO fsa VALUES('M4P', 'toronto');
INSERT INTO fsa VALUES('M5P', 'toronto');
INSERT INTO fsa VALUES('M6P', 'toronto');
INSERT INTO fsa VALUES('M9P', 'toronto');
INSERT INTO fsa VALUES('M1R', 'toronto');
INSERT INTO fsa VALUES('M2R', 'toronto');
INSERT INTO fsa VALUES('M4R', 'toronto');
INSERT INTO fsa VALUES('M5R', 'toronto');
INSERT INTO fsa VALUES('M6R', 'toronto');
INSERT INTO fsa VALUES('M7R', 'toronto');
INSERT INTO fsa VALUES('M9R', 'toronto');
INSERT INTO fsa VALUES('M1S', 'toronto');
INSERT INTO fsa VALUES('M4S', 'toronto');
INSERT INTO fsa VALUES('M5S', 'toronto');
INSERT INTO fsa VALUES('M6S', 'toronto');
INSERT INTO fsa VALUES('M1T', 'toronto');
INSERT INTO fsa VALUES('M4T', 'toronto');
INSERT INTO fsa VALUES('M5T', 'toronto');
INSERT INTO fsa VALUES('M1V', 'toronto');
INSERT INTO fsa VALUES('M4V', 'toronto');
INSERT INTO fsa VALUES('M5V', 'toronto');
INSERT INTO fsa VALUES('M8V', 'toronto');
INSERT INTO fsa VALUES('M9V', 'toronto');
INSERT INTO fsa VALUES('M1W', 'toronto');
INSERT INTO fsa VALUES('M4W', 'toronto');
INSERT INTO fsa VALUES('M5W', 'toronto');
INSERT INTO fsa VALUES('M8W', 'toronto');
INSERT INTO fsa VALUES('M9W', 'toronto');
INSERT INTO fsa VALUES('M1X', 'toronto');
INSERT INTO fsa VALUES('M4X', 'toronto');
INSERT INTO fsa VALUES('M5X', 'toronto');
INSERT INTO fsa VALUES('M8X', 'toronto');
INSERT INTO fsa VALUES('M4Y', 'toronto');
INSERT INTO fsa VALUES('M7Y', 'toronto');
INSERT INTO fsa VALUES('M8Y', 'toronto');
INSERT INTO fsa VALUES('M8Z', 'toronto');
INSERT INTO fsa VALUES('N1A', 'kw');
INSERT INTO fsa VALUES('N2A', 'kw');
INSERT INTO fsa VALUES('N3A', 'kw');
INSERT INTO fsa VALUES('N5A', 'kw');
INSERT INTO fsa VALUES('N6A', 'london');
INSERT INTO fsa VALUES('N7A', 'kw');
INSERT INTO fsa VALUES('N8A', 'windsor');
INSERT INTO fsa VALUES('N9A', 'windsor');
INSERT INTO fsa VALUES('N2B', 'kw');
INSERT INTO fsa VALUES('N3B', 'kw');
INSERT INTO fsa VALUES('N4B', 'london');
INSERT INTO fsa VALUES('N6B', 'london');
INSERT INTO fsa VALUES('N9B', 'windsor');
INSERT INTO fsa VALUES('N1C', 'kw');
INSERT INTO fsa VALUES('N2C', 'kw');
INSERT INTO fsa VALUES('N3C', 'kw');
INSERT INTO fsa VALUES('N5C', 'london');
INSERT INTO fsa VALUES('N6C', 'london');
INSERT INTO fsa VALUES('N9C', 'windsor');
INSERT INTO fsa VALUES('N1E', 'kw');
INSERT INTO fsa VALUES('N2E', 'kw');
INSERT INTO fsa VALUES('N3E', 'kw');
INSERT INTO fsa VALUES('N6E', 'london');
INSERT INTO fsa VALUES('N9E', 'windsor');
INSERT INTO fsa VALUES('N1G', 'kw');
INSERT INTO fsa VALUES('N2G', 'kw');
INSERT INTO fsa VALUES('N4G', 'london');
INSERT INTO fsa VALUES('N6G', 'london');
INSERT INTO fsa VALUES('N7G', 'london');
INSERT INTO fsa VALUES('N9G', 'windsor');
INSERT INTO fsa VALUES('N1H', 'kw');
INSERT INTO fsa VALUES('N2H', 'kw');
INSERT INTO fsa VALUES('N3H', 'kw');
INSERT INTO fsa VALUES('N5H', 'london');
INSERT INTO fsa VALUES('N6H', 'london');
INSERT INTO fsa VALUES('N8H', 'windsor');
INSERT INTO fsa VALUES('N9H', 'windsor');
INSERT INTO fsa VALUES('N2J', 'kw');
INSERT INTO fsa VALUES('N6J', 'london');
INSERT INTO fsa VALUES('N9J', 'windsor');
INSERT INTO fsa VALUES('N1K', 'kw');
INSERT INTO fsa VALUES('N2K', 'kw');
INSERT INTO fsa VALUES('N4K', 'barrie');
INSERT INTO fsa VALUES('N6K', 'london');
INSERT INTO fsa VALUES('N9K', 'windsor');
INSERT INTO fsa VALUES('N1L', 'kw');
INSERT INTO fsa VALUES('N2L', 'kw');
INSERT INTO fsa VALUES('N3L', 'kw');
INSERT INTO fsa VALUES('N4L', 'barrie');
INSERT INTO fsa VALUES('N5L', 'london');
INSERT INTO fsa VALUES('N6L', 'london');
INSERT INTO fsa VALUES('N7L', 'windsor');
INSERT INTO fsa VALUES('N1M', 'kw');
INSERT INTO fsa VALUES('N2M', 'kw');
INSERT INTO fsa VALUES('N6M', 'london');
INSERT INTO fsa VALUES('N7M', 'windsor');
INSERT INTO fsa VALUES('N8M', 'windsor');
INSERT INTO fsa VALUES('N2N', 'kw');
INSERT INTO fsa VALUES('N4N', 'barrie');
INSERT INTO fsa VALUES('N6N', 'london');
INSERT INTO fsa VALUES('N8N', 'windsor');
INSERT INTO fsa VALUES('N1P', 'kw');
INSERT INTO fsa VALUES('N2P', 'kw');
INSERT INTO fsa VALUES('N3P', 'hamilton');
INSERT INTO fsa VALUES('N5P', 'london');
INSERT INTO fsa VALUES('N6P', 'london');
INSERT INTO fsa VALUES('N8P', 'windsor');
INSERT INTO fsa VALUES('N1R', 'kw');
INSERT INTO fsa VALUES('N2R', 'kw');
INSERT INTO fsa VALUES('N3R', 'kw');
INSERT INTO fsa VALUES('N5R', 'london');
INSERT INTO fsa VALUES('N8R', 'windsor');
INSERT INTO fsa VALUES('N1S', 'kw');
INSERT INTO fsa VALUES('N3S', 'kw');
INSERT INTO fsa VALUES('N4S', 'kw');
INSERT INTO fsa VALUES('N7S', 'sarnia');
INSERT INTO fsa VALUES('N8S', 'windsor');
INSERT INTO fsa VALUES('N1T', 'kw');
INSERT INTO fsa VALUES('N2T', 'kw');
INSERT INTO fsa VALUES('N3T', 'kw');
INSERT INTO fsa VALUES('N4T', 'kw');
INSERT INTO fsa VALUES('N7T', 'sarnia');
INSERT INTO fsa VALUES('N8T', 'windsor');
INSERT INTO fsa VALUES('N2V', 'kw');
INSERT INTO fsa VALUES('N3V', 'kw');
INSERT INTO fsa VALUES('N4V', 'kw');
INSERT INTO fsa VALUES('N5V', 'london');
INSERT INTO fsa VALUES('N7V', 'sarnia');
INSERT INTO fsa VALUES('N8V', 'windsor');
INSERT INTO fsa VALUES('N9V', 'windsor');
INSERT INTO fsa VALUES('N3W', 'hamilton');
INSERT INTO fsa VALUES('N4W', 'kw');
INSERT INTO fsa VALUES('N5W', 'london');
INSERT INTO fsa VALUES('N7W', 'sarnia');
INSERT INTO fsa VALUES('N8W', 'windsor');
INSERT INTO fsa VALUES('N4X', 'kw');
INSERT INTO fsa VALUES('N5X', 'london');
INSERT INTO fsa VALUES('N7X', 'sarnia');
INSERT INTO fsa VALUES('N8X', 'windsor');
INSERT INTO fsa VALUES('N3Y', 'hamilton');
INSERT INTO fsa VALUES('N5Y', 'london');
INSERT INTO fsa VALUES('N8Y', 'windsor');
INSERT INTO fsa VALUES('N9Y', 'windsor');
INSERT INTO fsa VALUES('N2Z', 'windsor');
INSERT INTO fsa VALUES('N4Z', 'kw');
INSERT INTO fsa VALUES('N5Z', 'london');
INSERT INTO fsa VALUES('P1A', 'sudbury');
INSERT INTO fsa VALUES('P2A', 'sudbury');
INSERT INTO fsa VALUES('P3A', 'sudbury');
INSERT INTO fsa VALUES('P5A', 'sudbury');
INSERT INTO fsa VALUES('P6A', 'sudbury');
INSERT INTO fsa VALUES('P7A', 'thunder-bay');
INSERT INTO fsa VALUES('P9A', 'thunder-bay');
INSERT INTO fsa VALUES('P1B', 'sudbury');
INSERT INTO fsa VALUES('P2B', 'sudbury');
INSERT INTO fsa VALUES('P3B', 'sudbury');
INSERT INTO fsa VALUES('P6B', 'sudbury');
INSERT INTO fsa VALUES('P7B', 'thunder-bay');
INSERT INTO fsa VALUES('P1C', 'sudbury');
INSERT INTO fsa VALUES('P3C', 'sudbury');
INSERT INTO fsa VALUES('P6C', 'sudbury');
INSERT INTO fsa VALUES('P7C', 'thunder-bay');
INSERT INTO fsa VALUES('P3E', 'sudbury');
INSERT INTO fsa VALUES('P5E', 'sudbury');
INSERT INTO fsa VALUES('P7E', 'thunder-bay');
INSERT INTO fsa VALUES('P3G', 'sudbury');
INSERT INTO fsa VALUES('P7G', 'thunder-bay');
INSERT INTO fsa VALUES('P1H', 'sudbury');
INSERT INTO fsa VALUES('P7J', 'thunder-bay');
INSERT INTO fsa VALUES('P7K', 'thunder-bay');
INSERT INTO fsa VALUES('P1L', 'sudbury');
INSERT INTO fsa VALUES('P3L', 'sudbury');
INSERT INTO fsa VALUES('P7L', 'thunder-bay');
INSERT INTO fsa VALUES('P2N', 'sudbury');
INSERT INTO fsa VALUES('P3N', 'sudbury');
INSERT INTO fsa VALUES('P4N', 'sudbury');
INSERT INTO fsa VALUES('P5N', 'thunder-bay');
INSERT INTO fsa VALUES('P8N', 'thunder-bay');
INSERT INTO fsa VALUES('P9N', 'thunder-bay');
INSERT INTO fsa VALUES('P1P', 'sudbury');
INSERT INTO fsa VALUES('P3P', 'sudbury');
INSERT INTO fsa VALUES('P4P', 'sudbury');
INSERT INTO fsa VALUES('P4R', 'sudbury');
INSERT INTO fsa VALUES('P8T', 'thunder-bay');
INSERT INTO fsa VALUES('P3Y', 'sudbury');

