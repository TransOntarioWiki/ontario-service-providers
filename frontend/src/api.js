const baseUrl =
  process.env.NODE_ENV === "production"
    ? "https://api.transontario.wiki/"
    : "http://localhost:3000/";

// Use in POST requests later
// eslint-disable-next-line no-unused-vars
let bearer;

const fetchServices = () =>
  fetch(`${baseUrl}services`)
    .then((res) => res.json())
    .then((response) => {
      return response.map((x) => ({ id: x.service, name: x.service }));
    });

const fetchProviders = async ({ pageParam = 0, queryKey: [, params] }) => {
  const response = await fetch(
    `${baseUrl}providers?` +
      new URLSearchParams({
        ...params,
        offset: pageParam,
        limit: 50,
      }),
    {
      headers: {
        Prefer: "count=exact",
      },
    }
  );
  const data = await response.json();

  const totalResults = Number(
    response.headers.get("content-range").split("/")[1]
  );
  const nextStart = pageParam + 50;

  return { data, nextPage: totalResults > nextStart ? nextStart : null };
};

const initiateLogin = async () => {
  const response = await fetch(`${baseUrl}discord_application`);
  const [{ client_id, redirect_uri }] = await response.json();

  const state = Math.random();

  localStorage.setItem("dc_state", state);

  window.location = `https://discord.com/oauth2/authorize?client_id=${client_id}&scope=guilds.members.read%20identify&redirect_uri=${encodeURIComponent(
    redirect_uri
  )}&state=${state}&response_type=code`;
};

let loginPromise;

const handleLogin = async () => {
  if (loginPromise) {
    // Can be called multiple times.
    return await loginPromise;
  }

  loginPromise = (async () => {
    localStorage.removeItem("auth");

    try {
      const searchParams = new URLSearchParams(window.location.search);
      const state = searchParams.get("state");
      if (state === localStorage.getItem("dc_state")) {
        const code = searchParams.get("code");
        const response = await fetch(`${baseUrl}auth`, {
          method: "POST",
          body: JSON.stringify({ code }),
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            Prefer: "return=representation",
          },
        });
        if (response.status >= 400) {
          console.warn(await response.text());
          return false;
        }
        const json = await response.json();
        if (!json?.[0]?.code) {
          console.warn("missing code");
          return false;
        }
        bearer = json?.[0]?.code;
        localStorage.setItem("auth", bearer);
        return true;
      }
    } catch (err) {
      console.warn(err);
      return false;
    }
  })();

  return await loginPromise;
};

bearer = localStorage.getItem("auth");

const isLoggedIn = () => Boolean(bearer);

export {
  isLoggedIn,
  handleLogin,
  initiateLogin,
  fetchServices,
  fetchProviders,
};
