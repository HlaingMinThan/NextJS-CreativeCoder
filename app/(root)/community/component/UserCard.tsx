import ROUTES from "@/routes";
import Image from "next/image";
import Link from "next/link";
import React from "react";

function UserCard({
  id,
  name,
  image,
}: {
  id: string;
  name: string;
  image: string;
}) {
  return (
    <div>
      <Link
        href={ROUTES.PROFILE(id)}
        className="flex flex-col items-center justify-center bg-tertiary p-2 rounded-xl"
      >
        {image ? (
          <Image alt="logo" width={100} height={100} src={image}></Image>
        ) : (
          <div className="w-[100px] h-[100px] bg-tertiary"></div>
        )}
      </Link>
      <p className="text-center my-2">{name}</p>
    </div>
  );
}

export default UserCard;
