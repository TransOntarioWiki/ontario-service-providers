import "./App.css";
import React from "react";
import { QueryClient, QueryClientProvider } from "react-query";

import { init, isLoggedIn, initiateLogin, handleLogin } from "./api";
import SearchForm from "./SearchForm";
import ServiceProvidersList from "./ServicesList";
import TrustHeader from "./TrustHeader";
import Footer from "./Footer";

const queryClient = new QueryClient();

function App() {
  const [prepped, setPrepped] = React.useState(false);
  const [filters, handleSearch] = React.useState({});

  React.useEffect(() => {
    init();
    // eslint-disable-next-line no-restricted-globals
    if (!isLoggedIn() && location.pathname === "/oauth") {
      handleLogin().then(() => setPrepped(true));
    } else {
      setPrepped(true);
    }
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      <TrustHeader />
      <div className="p-8 flex flex-col items-center w-full h-full relative">
        <h1 className="text-3xl mb-8">TransOntario Wiki</h1>
        <SearchForm onSearch={handleSearch} />
        <ServiceProvidersList filters={filters} />
        {(!prepped || !isLoggedIn()) && (
          <button
            onClick={initiateLogin}
            className="absolute top-2 right-2 bg-pink-500 hover:bg-pink-600 text-white py-1 px-2 rounded"
          >
            Login to add Review
          </button>
        )}
      </div>
      <Footer />
    </QueryClientProvider>
  );
}

export default App;
