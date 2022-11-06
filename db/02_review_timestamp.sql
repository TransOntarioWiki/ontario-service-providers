ALTER TABLE public.review ADD COLUMN timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;

CREATE OR REPLACE VIEW api.reviews AS
 SELECT review.provider_id,
    review.text,
    review.score,
    discord_user.username,
    discord_user.discriminator,
    discord_user.avatar,
    discord_user.id AS discord_user_id,
    timestamp
   FROM (public.review
     LEFT JOIN public.discord_user ON ((review.discord_user_id = discord_user.id)));

CREATE OR REPLACE FUNCTION public.post_review() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    BEGIN
        IF (TG_OP = 'DELETE') THEN
            DELETE FROM review WHERE provider_id = OLD.provider_id and discord_user_id = (SELECT id FROM discord_user WHERE discord_user.username = OLD.username AND discord_user.discriminator = OLD.discriminator);
            IF NOT FOUND THEN RETURN NULL; END IF;
            RETURN OLD;
        ELSIF (TG_OP = 'UPDATE') THEN
            UPDATE review SET text = NEW.text, score = NEW.score, timestamp = now() WHERE provider_id = OLD.provider_id AND discord_user_id = (SELECT id FROM discord_user WHERE discord_user.username = OLD.username AND discord_user.discriminator = OLD.discriminator);
            IF NOT FOUND THEN RETURN NULL; END IF;
            RETURN NEW;
        ELSIF (TG_OP = 'INSERT') THEN
            INSERT INTO review VALUES(
	      NEW.provider_id, 
	      (current_setting('request.jwt.claims', true)::json->>'id'),
	      NEW.text,
	      NEW.score, now());
            RETURN NEW;
        END IF;
    END;
$$;
