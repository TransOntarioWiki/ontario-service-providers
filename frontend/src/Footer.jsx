import React from "react";

export default function Footer() {
  return (
    <div className="w-full text-center bg-slate-100 p-2 border-slate-900 border-t-2">
      <p>
        <b>Contact:</b> emilyskidsister#6688 or bashlyss#7777 on Discord
      </p>
      <p>
        <a
          href="https://github.com/TransOntarioWiki/ontario-service-providers"
          className="underline text-blue-900 hover:text-blue-300"
        >
          GitHub
        </a>{" "}
        |{" "}
        <a href="/tos" className="underline text-blue-900 hover:text-blue-300">
          Terms of Service
        </a>{" "}
        |{" "}
        <a
          href="/privacy"
          className="underline text-blue-900 hover:text-blue-300"
        >
          Privacy Policy
        </a>
      </p>
    </div>
  );
}
