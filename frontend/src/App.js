import "./App.css"
import React from "react";
import axios from "axios";

import SearchForm from "./SearchForm";
import ServiceProvidersList from "./ServicesList";


function App() {
  const [filters, handleSearch] = React.useState({});

  React.useEffect(() => {
    axios.defaults.baseURL = "http://localhost:3000";
  }, []);

  return (
    <div className="p-8 flex flex-col items-center w-full">
      <h1 className="text-3xl mb-8">TransOntario Wiki</h1>
      <SearchForm onSearch={handleSearch} />
      <ServiceProvidersList filters={filters} />
    </div>
  );
}

export default App;
