import { useMemo, useState, useEffect } from "react";
import axios from "axios";

import ProviderOverlay from "./ProviderOverlay";

const limit = 50;

const ProvidersList = ({ filters }) => {
  const [providers, setProviders] = useState([{ id: 1, name: "Testing" }]);
  const [offset, setOffset] = useState(0);
  const [totalProviders, setTotalProviders] = useState(1);
  const [focusedProviderId, setFocusedProvider] = useState(null);

  const fetchNext = () => {
    axios.get("providers/", { offset, limit }).then(response => {
      setProviders(prev => [...prev, ...response.data]);
      setOffset(prev => prev + limit);
      // TODO
      setTotalProviders(1000);
    }).catch(() => {});
  };

  useEffect(() => {
    fetchNext();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filteredServiceProviders = useMemo(() => {
    // TODO once I know API shape
    return providers.filter(provider => {
      if (!filters) {
        return true;
      }
      return true;
    });
  }, [providers, filters]);

  const focusedProvider = useMemo(() => {
    return providers.find(prov => prov.id === focusedProviderId);
  }, [providers, focusedProviderId]);

  return (
    <div className="mt-4">
      {filteredServiceProviders.length ? filteredServiceProviders.map(provider => (
        <>
          <div
            onClick={() => setFocusedProvider(provider.id)}
            className="cursor-pointer my-2"
          >
            <div>{provider.name}</div>
            <div>{provider.location}</div>
          </div>
          {offset < totalProviders && (
            <button
              onClick={fetchNext}
              className="bg-blue-500 hover:bg-blue-700 rounded-md text-white py-1 px-2 mt-2"
            >
              View More Providers
            </button>
          )}
        </>
      )) : (
        <div className="text-xl text-center">No Service Providers Found</div>
      )}
      <ProviderOverlay
        provider={focusedProvider}
        onClose={() => setFocusedProvider(null)}
      />
    </div>
  );
};

export default ProvidersList;
