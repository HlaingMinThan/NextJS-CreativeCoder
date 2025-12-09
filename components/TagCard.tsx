import Link from "next/link";
import React, { ReactNode } from "react";

function TagCard({ href, children }: { href: string; children: ReactNode }) {
  return (
    <Link
      href={href}
      className={`w-[100px] rounded-xl bg-tertiary px-4 py-2 text-gray-300`}
    >
      {children}
    </Link>
  );
}

export default TagCard;
