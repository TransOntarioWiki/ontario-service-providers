const baseUrl = "http://localhost:3000/";

const fetchServices = () => fetch(`${baseUrl}service`).then(res => res.json()).then(
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

  console.log(response);
  const totalResults = Number(
    response.headers.get("content-range").split("/")[1]);
  const nextStart = pageParam + 50;

  return { data, nextPage: totalResults > nextStart ? nextStart : null };
};

export { fetchServices, fetchProviders };
