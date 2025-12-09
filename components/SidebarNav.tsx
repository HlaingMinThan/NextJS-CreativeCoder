"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import React from "react";
import { FaHome, FaNewspaper } from "react-icons/fa";

import ROUTES from "@/routes";

interface SidebarNavProps {
  isAuthenticated: boolean;
}

function SidebarNav({ isAuthenticated }: SidebarNavProps) {
  const pathname = usePathname();

  const isActive = (path: string) => {
    if (path === ROUTES.HOME) {
      return pathname === ROUTES.HOME;
    }
    return pathname.startsWith(path);
  };

  return (
    <ul className="space-y-6">
      <li
        className={`rounded-xl p-3 ${
          isActive(ROUTES.HOME) ? "bg-main" : "bg-primary"
        }`}
      >
        <Link
          href={ROUTES.HOME}
          className="flex items-center space-x-4 text-[16px] font-bold"
        >
          <FaHome />
          <span>Home</span>
        </Link>
      </li>
      <li
        className={`rounded-xl p-3 ${
          isActive(ROUTES.TAGS) ? "bg-main" : "bg-primary"
        }`}
      >
        <Link
          href={ROUTES.TAGS}
          className="flex items-center space-x-4 text-[16px] font-bold"
        >
          <FaHome />
          <span>Tags</span>
        </Link>
      </li>
      <li
        className={`rounded-xl p-3 ${
          isActive(ROUTES.QUESTIONS) ? "bg-main" : "bg-primary"
        }`}
      >
        <Link
          href={ROUTES.QUESTIONS}
          className="flex items-center space-x-4 text-[16px] font-bold"
        >
          <FaHome />
          <span>Popular Questions</span>
        </Link>
      </li>
      <li
        className={`rounded-xl p-3 ${
          isActive(ROUTES.TECH_NEWS) ? "bg-main" : "bg-primary"
        }`}
      >
        <Link
          href={ROUTES.TECH_NEWS}
          className="flex items-center space-x-4 text-[16px] font-bold"
        >
          <FaNewspaper />
          <span>Tech News</span>
        </Link>
      </li>
      {isAuthenticated && (
        <li
          className={`rounded-xl p-3 ${
            isActive(ROUTES.BOOKMARKS) ? "bg-main" : "bg-primary"
          }`}
        >
          <Link
            href={ROUTES.BOOKMARKS}
            className="flex items-center space-x-4 text-[16px] font-bold"
          >
            <FaHome />
            <span>Bookmarks</span>
          </Link>
        </li>
      )}
      <li
        className={`rounded-xl p-3 ${
          isActive(ROUTES.COMMUNITY) ? "bg-main" : "bg-primary"
        }`}
      >
        <Link
          href={ROUTES.COMMUNITY}
          className="flex items-center space-x-4 text-[16px] font-bold"
        >
          <FaHome />
          <span>Community</span>
        </Link>
      </li>
      {!isAuthenticated && (
        <li className="rounded-xl border-2 border-main p-3">
          <Link
            href={ROUTES.LOGIN}
            className="flex items-center space-x-4 text-[16px] font-bold"
          >
            <FaHome />
            <span>Login</span>
          </Link>
        </li>
      )}
    </ul>
  );
}

export default SidebarNav;
