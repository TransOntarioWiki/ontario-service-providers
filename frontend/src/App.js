import "./App.css"
import React from "react";

import SearchForm from "./SearchForm";
import ServiceProvidersList from "./ServicesList";

function App() {
  const [filters, handleSearch] = React.useState({});

  return (
    <div className="p-8 flex flex-col items-center w-full">
      <h1 className="text-3xl mb-8">TransOntario Wiki</h1>
      <SearchForm onSearch={handleSearch} />
      <ServiceProvidersList filters={filters} />
    </div>
  );
}

export default App;
