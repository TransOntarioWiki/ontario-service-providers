import React from "react";
import { Link } from "react-router-dom";

import PageChrome from "./PageChrome";

function Privacy() {
  return (
    <PageChrome>
      <div className="p-4 flex flex-col w-full h-full relative flex-grow max-w-6xl mx-auto">
        <h1 className="text-3xl mb-8">Not Found</h1>
        <p className="mb-1">The requested page could not be found</p>
        <Link to="/" className="text-blue-900 underline">
          Go back to the home page
        </Link>
      </div>
    </PageChrome>
  );
}

export default Privacy;
