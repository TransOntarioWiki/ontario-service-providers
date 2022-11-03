import React from "react";
import PageChrome from "./PageChrome";

function Privacy() {
  return (
    <PageChrome>
      <div className="p-4 flex flex-col w-full h-full relative flex-grow max-w-6xl mx-auto">
        <h1 className="text-3xl mb-8">Privacy Policy</h1>
        <p className="mb-1">
          You need to log in to contribute. When you log in, we collect your
          Discord ID, username, discriminator (the numbers that are part of your
          username), avatar URL, and whether you have the "level three" role on
          the TransOntario Discord. This information will be published and may
          be accessed by anyone. Anything you contribute to the site will also
          be publically accessible and tied to that identity. We collect this
          information to run the site.
        </p>
        <p className="mb-1">
          We store request logs, which may include your IP address, the URL you
          accessed, and information about your browser for 30 days. We do this
          to help us debug issues and prevent abuse.
        </p>
        <p className="mb-1">
          If you would like your information to be removed or have other
          questions about this policy, please reach out to emilyskidsister#6688
          on Discord.
        </p>
      </div>
    </PageChrome>
  );
}

export default Privacy;
