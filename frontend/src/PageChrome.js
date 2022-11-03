import React from "react";
import TrustHeader from "./TrustHeader";
import NavHeader from "./NavHeader";
import Footer from "./Footer";

function PageChrome(props) {
  return (
    <div className="min-h-screen flex flex-col">
      <TrustHeader />
      <NavHeader />
      {props.children}
      <Footer />
    </div>
  );
}

export default PageChrome;
