import React from "react";

import { isLoggedIn, initiateLogin } from "./api";
import SearchForm from "./SearchForm";
import ServiceProvidersList from "./ServicesList";
import PageChrome from "./PageChrome";

function Services() {
  const [filters, handleSearch] = React.useState({});

  return (
    <PageChrome>
      <div className="p-8 flex flex-col items-center w-full h-full relative flex-grow">
        <h1 className="text-3xl mb-8">TransOntario Wiki</h1>
        <SearchForm onSearch={handleSearch} />
        <ServiceProvidersList filters={filters} />
        {!isLoggedIn() && (
          <button
            onClick={initiateLogin}
            className="absolute top-2 right-2 bg-pink-500 hover:bg-pink-600 text-white py-1 px-2 rounded"
          >
            Login to add Review
          </button>
        )}
      </div>
    </PageChrome>
  );
}

export default Services;
