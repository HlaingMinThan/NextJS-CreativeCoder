import Image from "next/image";
import Link from "next/link";
import React from "react";

function TagInfoCard({
  id,
  name,
  count,
}: {
  id: string;
  name: string;
  count: number;
}) {
  return (
    <div>
      <Link
        href={`/tags/${id}`}
        className="flex flex-col items-center justify-center bg-tertiary p-2 rounded-xl"
      >
        <Image
          alt="logo"
          width={100}
          height={100}
          src={`https://cdn.jsdelivr.net/gh/devicons/devicon@latest/icons/${name.toLocaleLowerCase()}/${name.toLocaleLowerCase()}-original.svg`}
        ></Image>
        <p>
          {name} - ({count})
        </p>
      </Link>
    </div>
  );
}

export default TagInfoCard;
