import React from "react";
import { useSearchParams } from "react-router-dom";

import SearchForm from "./SearchForm";
import ServiceProvidersList from "./ServicesList";
import PageChrome from "./PageChrome";

function Services() {
  const [searchParams] = useSearchParams();

  const filters = React.useMemo(() => {
    const _filters = {};
    searchParams.forEach((value, key) => {
      _filters[key] = value;
    });
    return _filters;
  }, [searchParams]);

  console.log(filters);

  return (
    <PageChrome>
      <div className="p-4 flex flex-col items-center w-full h-full relative flex-grow max-w-6xl mx-auto">
        <SearchForm />
        <ServiceProvidersList filters={filters} />
      </div>
    </PageChrome>
  );
}

export default Services;
