import React from "react";

function Avatar({ id, avatar, className }) {
  return (
    <img
      src={`https://cdn.discordapp.com/avatars/${id}/${avatar}.png`}
      alt="Avatar"
      className={`rounded-full inline-block ${className ?? "h-8"}`}
    />
  );
}

export default Avatar;
