import React from "react";

import SearchForm from "./SearchForm";
import ServiceProvidersList from "./ServicesList";
import PageChrome from "./PageChrome";

function Services() {
  const [filters, handleSearch] = React.useState({});

  return (
    <PageChrome>
      <div className="p-4 flex flex-col items-center w-full h-full relative flex-grow max-w-6xl mx-auto">
        <SearchForm onSearch={handleSearch} />
        <ServiceProvidersList filters={filters} />
      </div>
    </PageChrome>
  );
}

export default Services;
