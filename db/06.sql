CREATE OR REPLACE VIEW api.providers AS
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
    review_count,
    provider.id AS id,
    provider.fsa
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


CREATE VIEW api.referral_requirements AS SELECT referral_requirement_kind AS requirement FROM referral_requirement;
GRANT SELECT ON api.referral_requirements TO web_anon;
GRANT SELECT ON api.referral_requirements TO editor;
