import { QueryClient, useQuery, useInfiniteQuery } from "react-query";

const baseUrl =
  process.env.NODE_ENV === "production" ||
  process.env.REACT_APP_BUILDER === "ashley"
    ? "https://api.transontario.wiki/"
    : "http://localhost:3000/";

let bearer;
export const queryClient = new QueryClient();

export const fetchServices = () =>
  fetch(`${baseUrl}services`)
    .then((res) => res.json())
    .then((response) => {
      return response.map((x) => ({ id: x.service, name: x.service }));
    });

export const useServices = () => {
  return useQuery(["services"], fetchServices, {
    refetchOnMount: false,
    refetchOnWindowFocus: false,
  });
};

const fetchMe = async () => {
  if (!bearer) {
    return null;
  }

  const res = await fetch(`${baseUrl}me`, {
    headers: { Authorization: `Bearer ${bearer}` },
  });
  if (res.status !== 200) {
    initiateLogout();
    return null;
  }
  const json = await res.json();
  return json?.[0];
};

export const useMe = () => {
  return useQuery(["me"], fetchMe);
};

export const postReview = async (provider_id, text, score) => {
  if (!bearer) {
    return null;
  }

  await fetch(`${baseUrl}reviews`, {
    method: "POST",
    body: JSON.stringify({ provider_id, text, score }),
    headers: {
      Authorization: `Bearer ${bearer}`,
      Accept: "application/json",
      "Content-Type": "application/json",
      Prefer: "return=representation",
    },
  });

  queryClient.invalidateQueries(["reviews", provider_id]);
};

export const putReview = async (provider_id, discord_user_id, text, score) => {
  if (!bearer) {
    return null;
  }

  await fetch(
    `${baseUrl}reviews?` +
      new URLSearchParams({
        provider_id: `eq.${provider_id}`,
        discord_user_id: `eq.${discord_user_id}`,
      }),
    {
      method: "PATCH",
      body: JSON.stringify({ provider_id, text, score }),
      headers: {
        Authorization: `Bearer ${bearer}`,
        Accept: "application/json",
        "Content-Type": "application/json",
        Prefer: "return=representation",
      },
    }
  );

  queryClient.invalidateQueries(["reviews", provider_id]);
};

export const fetchReviews = async ({
  queryKey: [, providerId],
  pageParam = 0,
}) => {
  if (!providerId) {
    return null;
  }

  const response = await fetch(
    `${baseUrl}reviews?` +
      new URLSearchParams({
        provider_id: `eq.${providerId}`,
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

export function useReviews(providerId) {
  return useInfiniteQuery(["reviews", providerId], fetchReviews, {
    getNextPageParam: (lastPage) => {
      return lastPage?.nextPage;
    },
    refetchOnMount: false,
    refetchOnWindowFocus: false,
  });
}

export const fetchProviders = async ({
  pageParam = 0,
  queryKey: [, params],
}) => {
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

export const patchProviders = async (data) => {
  if (!bearer) {
    return null;
  }

  const response = await fetch(
    `${baseUrl}providers?` +
      new URLSearchParams({
        id: `eq.${data.id}`,
      }),
    {
      method: "PATCH",
      body: JSON.stringify(data),
      headers: {
        Authorization: `Bearer ${bearer}`,
        Accept: "application/json",
        "Content-Type": "application/json",
        Prefer: "return=representation",
      },
    }
  );

  queryClient.invalidateQueries(["providers"]);

  return response;
};

export const createProvider = async (data) => {
  if (!bearer) {
    return null;
  }

  const response = await fetch(`${baseUrl}providers`, {
    method: "POST",
    body: JSON.stringify(data),
    headers: {
      Authorization: `Bearer ${bearer}`,
      Accept: "application/json",
      "Content-Type": "application/json",
      Prefer: "return=representation",
    },
  });

  queryClient.invalidateQueries(["providers"]);

  return response;
};

export const fetchProvider = async ({ queryKey: [, providerSlug] }) => {
  if (!providerSlug) {
    return null;
  }

  const response = await fetch(
    `${baseUrl}providers?` +
      new URLSearchParams({
        slug: `eq.${providerSlug}`,
      })
  );
  const data = await response.json();

  return data?.[0];
};

export const useProvider = (providerSlug) => {
  return useQuery(["provider", providerSlug], fetchProvider);
};

export const fetchReferralRequirements = async () => {
  const response = await fetch(`${baseUrl}referral_requirements`);
  return await response.json();
};

export const useReferralRequirements = () => {
  return useQuery(["referral_requirements"], fetchReferralRequirements);
};

export const fetchLanguages = async () => {
  const response = await fetch(`${baseUrl}languages`);
  return await response.json();
};

export const useLanguages = () => {
  return useQuery(["languages"], fetchLanguages);
};

export const fetchFees = async () => {
  const response = await fetch(`${baseUrl}fees`);
  return await response.json();
};

export const useFees = () => {
  return useQuery(["fees"], fetchFees);
};

export const fetchCharacteristics = async () => {
  const response = await fetch(`${baseUrl}characteristics`);
  return await response.json();
};

export const useCharacteristics = () => {
  return useQuery(["characteristics"], fetchCharacteristics);
};

export const initiateLogin = async () => {
  const response = await fetch(`${baseUrl}discord_application`);
  const [{ client_id, redirect_uri }] = await response.json();

  const state = Math.random();

  localStorage.setItem("dc_state", state);

  window.location = `https://discord.com/oauth2/authorize?client_id=${client_id}&scope=guilds.members.read%20identify&redirect_uri=${encodeURIComponent(
    redirect_uri
  )}&state=${state}&response_type=code`;
};

export const initiateLogout = async () => {
  bearer = null;
  localStorage.bearer = null;
  queryClient.invalidateQueries();
};

let loginPromise;

export const handleLogin = async () => {
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
        if (!json?.[0]?.bearer) {
          console.warn("missing cbearerode");
          return false;
        }
        bearer = json?.[0]?.bearer;
        localStorage.setItem("auth", bearer);
        queryClient.invalidateQueries();
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

export const isLoggedIn = () => Boolean(bearer);
