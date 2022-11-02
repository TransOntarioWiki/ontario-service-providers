import React from "react";
import TrustHeader from "./TrustHeader";
import Footer from "./Footer";

function PageChrome(props) {
  return (
    <div className="min-h-screen flex flex-col">
      <TrustHeader />
      {props.children}
      <Footer />
    </div>
  );
}

export default PageChrome;
