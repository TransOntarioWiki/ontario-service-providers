import "./App.css"
import React from "react";
import { QueryClient, QueryClientProvider } from "react-query";

import SearchForm from "./SearchForm";
import ServiceProvidersList from "./ServicesList";

const queryClient = new QueryClient();

function App() {
  const [filters, handleSearch] = React.useState({});

  return (
    <QueryClientProvider client={queryClient}>
    <div className="p-8 flex flex-col items-center w-full h-full">
      <h1 className="text-3xl mb-8">TransOntario Wiki</h1>
      <SearchForm onSearch={handleSearch} />
      <ServiceProvidersList filters={filters} />
    </div>
    </QueryClientProvider>
  );
}

export default App;
