import { useNavigate } from "react-router-dom";

import React, { useState, useRef } from "react";
import PageChrome from "./PageChrome";
import { handleLogin } from "./api";

function OAuth() {
  const [error, setError] = useState(null);
  const loginState = useRef("not-started");
  const navigate = useNavigate();

  React.useEffect(() => {
    if (loginState.current !== "not-started") {
      return;
    }

    loginState.current = "in-progress";

    async function login() {
      const ok = await handleLogin();
      if (loginState.current === "not-started") {
        return;
      }
      loginState.current = "not-started";
      if (ok) {
        navigate("/", { replace: true });
      } else {
        setError(true);
      }
    }

    login();

    return () => {
      loginState.current = "not-started";
    };
  }, [navigate]);

  return (
    <PageChrome>
      <div className="p-8 flex flex-col items-center w-full h-full relative flex-grow">
        {error ? (
          <>
            <h1 className="text-3xl mb-8">Sorry, we could not log you in.</h1>
            <p>
              You must be an active (level 3) member of the{" "}
              <a
                href="https://discord.gg/transontario"
                className="underline text-blue-900"
              >
                TransOntario discord
              </a>{" "}
              to contribute.
            </p>
            <p>
              If you are, please contact emilyskidsister#6688 on Discord for
              assistance.
            </p>
          </>
        ) : (
          <h1 className="text-3xl mb-8">Logging you in&hellip;</h1>
        )}
      </div>
    </PageChrome>
  );
}

export default OAuth;
