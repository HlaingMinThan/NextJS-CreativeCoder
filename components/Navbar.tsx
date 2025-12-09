import Image from "next/image";
import React from "react";

import Input from "./Input";
import SearchInput from "./SearchInput";
import logo from "../public/logo.jpg";

import { auth } from "@/auth";
import Link from "next/link";
import ROUTES from "@/routes";

async function Navbar() {
  let session = await auth();
  let user = session?.user;

  const hasProfileImage = user?.image && user.image.trim() !== "";

  return (
    <nav className="flex justify-between px-10 py-6">
      <div className="flex items-center justify-center space-x-4">
        <Image
          src={logo}
          width={60}
          height={60}
          className="rounded-full"
          alt="logo"
        />
        <h1 className="font-bold">
          Creative <span className="text-main">Coder</span>
        </h1>
      </div>
      <div className="w-[600px]">
        <SearchInput />
      </div>
      <div>
        {user && (
          <Link href={ROUTES.PROFILE(user.id as string)}>
            {hasProfileImage ? (
              <Image
                src={user.image as string}
                width={45}
                height={45}
                className="aspect-square rounded-full object-cover"
                alt="user profile"
              />
            ) : (
              <div className="w-[45px] h-[45px] rounded-full bg-primary flex items-center justify-center border-2 border-main">
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  className="text-gray-400"
                >
                  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                  <circle cx="12" cy="7" r="4"></circle>
                </svg>
              </div>
            )}
          </Link>
        )}
      </div>
    </nav>
  );
}

export default Navbar;
