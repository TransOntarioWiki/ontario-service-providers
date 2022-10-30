const baseUrl = "http://localhost:3000/";

const fetchServices = () => fetch(`${baseUrl}service`).then(res => res.json()).then(
  response => {
    return response.map(x => ({ id: x.service, name: x.service }));
  });

const fetchProviders = async ({ pageParam = 0, params, headers }) => {
  const response = await fetch(`${baseUrl}providers?` + new URLSearchParams({
    ...params,
    offset: pageParam,
    limit: 50,
  }));
  const data = await response.json()
  return { data, nextPage: response.status === 206 ? pageParam + 50 : null };
};

export { fetchServices, fetchProviders };
