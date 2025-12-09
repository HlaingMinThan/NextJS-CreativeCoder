"use client";

import ROUTES from "@/routes";
import { signOut } from "next-auth/react";
import { useRouter } from "next/navigation";
import React from "react";
import { FaHome } from "react-icons/fa";

export default function LogoutNavLink() {
  let router = useRouter();
  let logout = async () => {
    await signOut({ redirect: false });
    return router.push(ROUTES.LOGIN);
  };
  return (
    <li className="cursor-pointer rounded-xl bg-red-500 p-3" onClick={logout}>
      <div className="flex items-center space-x-4 text-[16px] font-bold">
        <FaHome />
        <span>Logout</span>
      </div>
    </li>
  );
}
