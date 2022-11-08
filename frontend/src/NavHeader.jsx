import React, { useRef, useState, useEffect } from "react";
import { initiateLogin, useMe, initiateLogout } from "./api";
import { Link } from "react-router-dom";
import Avatar from "./Avatar";

function NavHeader() {
  const me = useMe();
  const [userMenuOpen, setUserMenuOpen] = useState(false);

  const userMenuRef = useRef(null);

  const handleClickOutside = (event) => {
    if (userMenuRef.current && !userMenuRef.current.contains(event.target)) {
      setUserMenuOpen(false);
    }
  };

  useEffect(() => {
    document.addEventListener("click", handleClickOutside, true);
    return () => {
      document.removeEventListener("click", handleClickOutside, true);
    };
  }, []);

  return (
    <div className="w-full py-3 border-black border-b">
      <nav className="max-w-6xl px-4 mx-auto flex items-center">
        <h1 className="text-2xl text-black font-bold hover:text-sky-600">
          <Link to="/">TransOntario Wiki</Link>
        </h1>
        <div className="flex-grow" />
        {me.status === "success" && !me.data ? (
          <button onClick={initiateLogin} className="text-sky-600 font-bold">
            Login
          </button>
        ) : null}
        {me.status === "success" && me.data ? (
          <Link className="text-sky-600 font-bold mr-8" to="/create-provider">
            Add Provider
          </Link>
        ) : null}
        {me.status === "success" && me.data ? (
          <div className="relative" ref={userMenuRef}>
            <button
              onClick={(ev) => {
                ev.preventDefault();
                setUserMenuOpen(!userMenuOpen);
              }}
              title="My account"
            >
              <Avatar id={me.data.id} avatar={me.data.avatar} className="h-8" />
            </button>
            {userMenuOpen && (
              <div className="absolute border-black border bg-white right-0 top-10 p-4 z-10 text-center shadow-xl">
                <div className="border-sky-100 border-b-2 pb-2">
                  {me.data.username}#{me.data.discriminator}
                </div>
                <button
                  className="text-sky-600 font-bold pt-2"
                  onClick={() => initiateLogout()}
                >
                  Logout
                </button>
              </div>
            )}
          </div>
        ) : null}
      </nav>
    </div>
  );
}

export default NavHeader;
