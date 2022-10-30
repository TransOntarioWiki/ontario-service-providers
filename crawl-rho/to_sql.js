const rho = require("./rho.json");
const fs = require("fs");

function field(str) {
  if (str == null) return "NULL";
  return `'${str.replace(/'/g, "''")}'`;
}

let sql;

for (const [slug, entry] of Object.entries(rho)) {
  let extra_service_fees;
  if (entry.service_fees?.includes("Service fee ")) {
    const parts = entry.service_fees.split("Service fee ");
    entry.service_fees = parts[0].trim();
    entry.service_fees += "\nFee for Service";
    extra_service_fees = parts[1].trim();
  } else if (entry.service_fees?.includes("Sliding scale range - $/Hour")) {
    const parts = entry.service_fees.split("Sliding scale range - $/Hour");
    entry.service_fees = parts[0].trim();
    entry.service_fees += "\nFee for Service With Sliding Scale";
    extra_service_fees = `Sliding scale range - $/Hour${parts[1]}`;
  }

  sql += `INSERT INTO provider(slug, name, address, assessments_provided, description, email, hours_of_operation, phone, fsa, satellite_locations, fee_info, submitted_by, accessibility_available, website) VALUES(${[
    slug,
    entry.name,
    entry.address,
    entry.assessments_provided,
    entry.description,
    entry.email,
    entry.hours_of_operation,
    entry.phone,
    entry.postal_code?.split(" ")[0],
    entry.satellite_locations,
    extra_service_fees,
    entry.submitted_by,
    entry.accessibility_available,
    entry.website,
  ]
    .map(field)
    .join(",")}) ON CONFLICT (slug) DO UPDATE SET name=${field(
    entry.name
  )}, address=${field(entry.address)}, assessments_provided=${field(
    entry.assessments_provided
  )}, description=${field(entry.description)}, email=${field(
    entry.email
  )}, hours_of_operation=${field(entry.hours_of_operation)}, phone=${field(
    entry.phone
  )}, fsa=${field(
    entry.postal_code?.split(" ")[0]
  )}, satellite_locations=${field(entry.satellite_locations)}, fee_info=${field(
    extra_service_fees
  )}, submitted_by=${field(
    entry.submitted_by
  )}, accessibility_available=${field(
    entry.accessibility_available
  )}, website=${field(entry.website)};`;

  if (entry.experience_with) {
    for (const characteristic of entry.experience_with.split("\n")) {
      sql += `INSERT INTO characteristic(person_kind) VALUES(${field(
        characteristic
      )}) ON CONFLICT DO NOTHING;`;
      sql += `INSERT INTO provider_expertise(provider_id, characteristic_id) VALUES(
          (SELECT id FROM provider WHERE slug = ${field(slug)}),
          (SELECT id FROM characteristic WHERE person_kind = ${field(
            characteristic
          )})
        ) ON CONFLICT DO NOTHING;`;
    }
  }

  if (entry.service_available_in) {
    for (const language of entry.service_available_in.split("\n")) {
      sql += `INSERT INTO language(language_name) VALUES(${field(
        language
      )}) ON CONFLICT DO NOTHING;`;
      sql += `INSERT INTO provider_language(provider_id, language_id) VALUES(
          (SELECT id FROM provider WHERE slug = ${field(slug)}),
          (SELECT id FROM language WHERE language_name = ${field(language)})
        ) ON CONFLICT DO NOTHING;`;
    }
  }

  if (entry.rho_training_completion) {
    for (const training_kind of entry.rho_training_completion.split("\n")) {
      sql += `INSERT INTO rho_training(training_kind) VALUES(${field(
        training_kind
      )}) ON CONFLICT DO NOTHING;`;
      sql += `INSERT INTO provider_training(provider_id, training_id) VALUES(
          (SELECT id FROM provider WHERE slug = ${field(slug)}),
          (SELECT id FROM rho_training WHERE training_kind = ${field(
            training_kind
          )})
        ) ON CONFLICT DO NOTHING;`;
    }
  }

  if (entry.how_to_access_services) {
    for (const referral_requirement_kind_raw of entry.how_to_access_services.split(
      "\n"
    )) {
      const referral_requirement_kind =
        referral_requirement_kind_raw === "Referral From Doctor"
          ? "Referral from doctor"
          : referral_requirement_kind_raw;
      sql += `INSERT INTO referral_requirement(referral_requirement_kind) VALUES(${field(
        referral_requirement_kind
      )}) ON CONFLICT DO NOTHING;`;
      sql += `INSERT INTO provider_referral_requirement(provider_id, referral_requirement_id) VALUES(
          (SELECT id FROM provider WHERE slug = ${field(slug)}),
          (SELECT id FROM referral_requirement WHERE referral_requirement_kind = ${field(
            referral_requirement_kind
          )})
        ) ON CONFLICT DO NOTHING;`;
    }
  }

  if (entry.services) {
    for (const service_kind of entry.services.split("\n")) {
      sql += `INSERT INTO service(service_kind) VALUES(${field(
        service_kind
      )}) ON CONFLICT DO NOTHING;`;
      sql += `INSERT INTO provider_service(provider_id, service_id) VALUES(
          (SELECT id FROM provider WHERE slug = ${field(slug)}),
          (SELECT id FROM service WHERE service_kind = ${field(service_kind)})
        ) ON CONFLICT DO NOTHING;`;
    }
  }

  if (entry.service_fees) {
    for (const fee_kind_raw of entry.service_fees.split("\n")) {
      if (!fee_kind_raw) {
        continue;
      }
      const fee_kind =
        fee_kind_raw === "Fee for service with sliding scale"
          ? "Fee for Service With Sliding Scale"
          : fee_kind_raw;

      sql += `INSERT INTO fee(fee_kind) VALUES(${field(
        fee_kind
      )}) ON CONFLICT DO NOTHING;`;
      sql += `INSERT INTO provider_fee(provider_id, fee_id) VALUES(
          (SELECT id FROM provider WHERE slug = ${field(slug)}),
          (SELECT id FROM fee WHERE fee_kind = ${field(fee_kind)})
        ) ON CONFLICT DO NOTHING;`;
    }
  }
}

fs.writeFileSync("./rho.sql", sql);
