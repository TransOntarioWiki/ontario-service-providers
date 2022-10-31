const baseUrl = "http://localhost:3000/";

// Use in POST requests later
// eslint-disable-next-line no-unused-vars
let bearer;

const fetchServices = () => fetch(`${baseUrl}services`).then(res => res.json()).then(
  response => {
    return response.map(x => ({ id: x.service, name: x.service }));
  });

const fetchProviders = async ({ pageParam = 0, queryKey: [,params] }) => {
  const response = await fetch(`${baseUrl}providers?` + new URLSearchParams({
    ...Object.fromEntries(Object.entries(params).map(([key, value]) => [key, `eq.${value}`])),
    offset: pageParam,
    limit: 50,
  }), {
    headers: {
      Prefer: "count=exact",
    }
  });
  const data = await response.json();

  const totalResults = Number(
    response.headers.get("content-range").split("/")[1]);
  const nextStart = pageParam + 50;

  return { data, nextPage: totalResults > nextStart ? nextStart : null };
};

const initiateLogin = async () => {
  const response = await fetch(`${baseUrl}discord_application`);
  const [{ client_id, redirect_uri }] = await response.json();

  const state = Math.random();

  localStorage.setItem("dc_state", state);

  window.location = `https://discord.com/oauth2/authorize?client_id=${client_id}&scope=guilds.members.read%20identify&redirect_uri=${encodeURIComponent(redirect_uri)}&state=${state}&response_type=code`;
};

const handleLogin = async () => {
  const searchParams = new URLSearchParams(window.location.search);
  const state = searchParams.get("state");
  if (state === localStorage.getItem("dc_state")) {
    const code = searchParams.get("code");
    bearer = await fetch(`${baseUrl}auth`, {
      method: "POST",
      body: JSON.stringify({ code }),
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        Prefer: "return=representation",
      },
    });
    console.log("Successfully logged in!")
    localStorage.setItem("auth", bearer);
  }
};

const init = () => {
  bearer = localStorage.getItem("auth");
};
const isLoggedIn = () => Boolean(bearer);

export { init, isLoggedIn, handleLogin, initiateLogin, fetchServices, fetchProviders };
