import React from "react";
import PageChrome from "./PageChrome";

function Privacy() {
  return (
    <PageChrome>
      <div className="p-4 flex flex-col w-full h-full relative flex-grow max-w-6xl mx-auto">
        <h1 className="text-3xl mb-8">Terms of Service</h1>
        <p className="mb-1">
          To contribute reviews or content to this site, you must be
          transgender, non-binary, or any gender minority. You must also live in
          Ontario.
        </p>
        <p className="mb-1">
          You agree that any contributions can be published under the{" "}
          <a
            href="https://creativecommons.org/licenses/by-sa/3.0/"
            className="text-blue-900 underline"
          >
            CC BY-SA 3.0
          </a>{" "}
          license.
        </p>
        <p className="mb-1">
          TransOntario Wiki has no affiliation with Rainbow Health Ontario or
          Sherbourne Health.
        </p>
      </div>
    </PageChrome>
  );
}

export default Privacy;
