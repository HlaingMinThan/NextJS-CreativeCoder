import Image, { StaticImageData } from "next/image";
import Link from "next/link";
import React from "react";

function ButtonLink({
  icon,
  children,
  href,
  variant = "normal",
  ...props
}: {
  icon?: string | StaticImageData;
  children: React.ReactNode;
  href: string;
  variant?: "normal" | "outline";
}) {
  return (
    <Link
      href={href}
      {...props}
      className={` w-full  space-x-3 rounded-lg  px-4 py-2 ${
        variant === "outline" ? "border-2 border-main" : "bg-main"
      }
    ${icon ? "flex items-center" : ""}
      `}
    >
      {icon && <Image src={icon} alt="icon" width={30} height={30} />}
      <span>{children}</span>
    </Link>
  );
}

export default ButtonLink;
