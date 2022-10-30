import { useMemo, useState, useEffect } from "react";
import axios from "axios";

const ProvidersList = ({ filters }) => {
  const [providers, setProviders] = useState([]);

  useEffect(() => {
    axios.get("providers/").then(response => {
      setProviders(response.data);
    }).catch(() => {});
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

  return (
    <div className="mt-4">
      {filteredServiceProviders.length ? filteredServiceProviders.map(provider => (
        <div>Service!</div>
      )) : (
        <div className="text-xl text-center">No Service Providers Found</div>
      )}
    </div>
  );
};

export default ProvidersList;
