import Image, { StaticImageData } from "next/image";
import React from "react";

function Button({
  icon,
  children,
  variant = "normal",
  ...props
}: {
  icon?: string | StaticImageData;
  children: React.ReactNode;
  variant?: "normal" | "outline";
} & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...props}
      className={` w-full  space-x-3 rounded-lg  px-4 py-2 ${
        variant === "outline" ? "border-2 border-main" : "bg-main"
      }
    ${icon ? "flex items-center" : ""}
      `}
    >
      {icon && <Image src={icon} alt="icon" width={30} height={30} />}
      <span>{children}</span>
    </button>
  );
}

export default Button;
