import { useMemo } from "react";
import { useInfiniteQuery } from "react-query";
import { useNavigate } from "react-router-dom";

import regions from "./regions";
import { fetchProviders } from "./api";

const ProvidersList = ({ filters }) => {
  const navigate = useNavigate();
  const { fetchNextPage, hasNextPage, data, isLoading } = useInfiniteQuery(
    ["providers", filters],
    fetchProviders,
    {
      refetchOnMount: false,
      refetchOnWindowFocus: false,
      getNextPageParam: (lastPage) => {
        return lastPage?.nextPage;
      },
    }
  );

  const providers = useMemo(() => {
    if (!isLoading && data && data.pages) {
      return data.pages.map((page) => page?.data || []).flat();
    }
    return [];
  }, [isLoading, data]);

  const filteredServiceProviders = useMemo(() => {
    if (!providers) {
      return [];
    }
    return (
      providers.filter((provider) => {
        let include = true;
        if (filters.region) {
          include =
            include &&
            (provider.region === filters.region.split(".")[1] ||
              (provider.region == null && filters.region === "is.null"));
        } else if (filters.services) {
          include =
            include &&
            provider.services.find(
              (s) => s === filters.services.match(/cs.{([A-Za-z -]+)}/)[1]
            );
        }
        return include;
      }) || []
    );
  }, [providers, filters]);

  if (isLoading) {
    return <div />;
  }

  return (
    <div className="mt-4">
      {filteredServiceProviders.length ? (
        <>
          {filteredServiceProviders.map((provider) => (
            <div
              key={provider.slug}
              onClick={() => navigate(`provider/${provider.slug}`)}
              className="cursor-pointer py-2 border-b border-black"
            >
              <div className="font-bold">{provider.name}</div>
              <div>Region: {regions[provider.region]}</div>
              <div className="mt-2">{provider.description}</div>
            </div>
          ))}
          {hasNextPage && (
            <div className="flex justify-center">
              <button
                onClick={fetchNextPage}
                className="bg-blue-500 hover:bg-blue-700 rounded-md text-white py-1 px-2 mt-2"
              >
                View More Providers
              </button>
            </div>
          )}
        </>
      ) : (
        <div className="text-xl text-center">No Service Providers Found</div>
      )}
    </div>
  );
};

export default ProvidersList;
