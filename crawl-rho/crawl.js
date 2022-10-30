const { parse } = require("node-html-parser");
const fs = require("fs");

function theFuture(timeout) {
  return new Promise((resolve) => setTimeout(resolve, timeout));
}

function toSnakeCase(str) {
  return str
    .replace(/:$/, "")
    .replace(/([a-z])([A-Z])/g, "$1_$2")
    .replace(/[\s-]+/g, "_")
    .toLowerCase();
}

function retry(fn, retries = 5, timeout = 500) {
  return new Promise((resolve, reject) => {
    function attempt() {
      fn()
        .then(resolve)
        .catch((err) => {
          if (retries === 0) {
            reject(err);
          } else {
            retries -= 1;
            setTimeout(attempt, timeout);
          }
        });
    }
    attempt();
  });
}

async function getProviders() {
  const providers = [];
  for (let i = 1; ; i += 1) {
    console.debug("Crawling result page", i);
    const res = await fetch(
      "https://www.rainbowhealthontario.ca/wp-admin/admin-ajax.php",
      {
        credentials: "include",
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:107.0) Gecko/20100101 Firefox/107.0",
          Accept: "*/*",
          "Accept-Language": "en-CA,en-US;q=0.8,en-GB;q=0.5,en;q=0.3",
          "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
          "X-Requested-With": "XMLHttpRequest",
          "Sec-Fetch-Dest": "empty",
          "Sec-Fetch-Mode": "cors",
          "Sec-Fetch-Site": "same-origin",
          "Sec-GPC": "1",
        },
        referrer:
          "https://www.rainbowhealthontario.ca/service-provider-directory/",
        body: `post_type=service_provider&action=rho_ajax_fetch_listings&keywords=&order=asc&orderby=post_name&paged=${i}&exact_search=off&viewtype=list&distance=-1&rho_primary_assessment=off&rho_secondary_assessment=off&rho_training_completion=off&rho_accessibility_features=off`,
        method: "POST",
        mode: "cors",
      }
    );

    if (res.status !== 200) {
      console.warn(res);
      throw new Error("Unexpected status");
    }

    const body = await res.text();
    if (body.includes("No service providers found")) {
      break;
    }
    const matches = body.matchAll(
      /<a class="view-full link" href="https:\/\/www.rainbowhealthontario.ca\/service-provider-directory\/(.*)\/" aria-label="(.*)">Details<\/a>/g
    );
    for (const match of matches) {
      providers.push(match[1]);
    }

    await theFuture(500 + 500 * Math.random());
  }

  return providers;
}

async function getProvider(provider) {
  const res = await fetch(
    `https://www.rainbowhealthontario.ca/service-provider-directory/${provider}/`,
    {
      credentials: "include",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:107.0) Gecko/20100101 Firefox/107.0",
        Accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-CA,en-US;q=0.8,en-GB;q=0.5,en;q=0.3",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Sec-GPC": "1",
      },
      referrer:
        "https://www.rainbowhealthontario.ca/service-provider-directory/",
      method: "GET",
      mode: "cors",
    }
  );

  if (res.status !== 200) {
    console.warn(res);
    throw new Error("Unexpected status");
  }

  const body = await res.text();
  const root = parse(body);
  const fields = {};
  for (const item of root.querySelectorAll(".sidebar-section")) {
    const header = item.querySelector(".sidebar-header");
    if (header) {
      const items = [];
      for (
        let element = header.nextElementSibling;
        element;
        element = element.nextElementSibling
      ) {
        if (element.classNames.includes("address")) {
          const address = [];
          for (const child of element.childNodes) {
            if (child.nodeType === 3 /* text */) {
              address.push(child.textContent.trim());
            }
          }
          fields["address"] = address.join("\n");
        } else if (element.tagName.toLowerCase() === "ul") {
          for (const li of element.querySelectorAll("li")) {
            const label = li.querySelector(".label");
            const value = li.querySelector(".value");
            if (label && value) {
              fields[toSnakeCase(label.textContent.trim())] =
                value.textContent.trim();
            } else {
              items.push(li.textContent.trim());
            }
          }
        } else {
          items.push(element.textContent.trim().replace(/\s+/g, " "));
        }
      }

      if (items.length > 0) {
        fields[toSnakeCase(toSnakeCase(header.textContent.trim()))] =
          items.join("\n");
      } else {
        fields[toSnakeCase(toSnakeCase(header.textContent.trim()))] = "true";
      }
    }
  }

  for (const classField of ["submitted-by", "description", "services"]) {
    const container = root.querySelector(`.${classField}`);
    if (container) {
      const containerLines = [];
      for (const child of container.childNodes) {
        const thisTag = child.tagName?.toLowerCase();
        if (thisTag === "p" || thisTag === "li" || thisTag === "blockquote") {
          tag = thisTag;
          containerLines.push(child.textContent.trim());
        }
      }
      fields[toSnakeCase(classField)] = containerLines.join("\n");
    }
  }

  const title = root.querySelector(".title-header")?.textContent.trim();
  fields["name"] = title;

  const postalCodeMatch = fields.address?.match(/([A-Z]\d[A-Z]) ?(\d[A-Z]\d)/);
  const postalCode = postalCodeMatch?.[2]
    ? `${postalCodeMatch?.[1]} ${postalCodeMatch?.[2]}`
    : null;
  fields["postal_code"] = postalCode;

  return fields;
}

async function main() {
  const providers = await getProviders();
  const data = {};
  for (const [i, provider] of providers.entries()) {
    data[provider] = await retry(() => getProvider(provider));
    console.debug(
      `Crawling entry ${i + 1}/${providers.length}`,
      provider,
      data[provider]
    );
    await theFuture(500 + 500 * Math.random());
  }

  fs.writeFileSync("rho.json", JSON.stringify(data, null, 2));
}

main();
