"use client";
import { useRouter } from "next/navigation";
import queryString from "query-string";
import React from "react";

function Pagination({
  isNext,
  page = 1,
}: {
  isNext: boolean;
  page: number | string;
}) {
  page = Number(page);
  let router = useRouter();

  let handleClick = (type: "prev" | "next") => {
    const currentQuery = queryString.parse(window.location.search);
    console.log(currentQuery);
    const updatedQuery = {
      ...currentQuery,
      page: type === "prev" ? page - 1 : page + 1 || "",
    };

    const url = queryString.stringifyUrl(
      {
        url: window.location.pathname,
        query: updatedQuery,
      },
      { skipEmptyString: true, skipNull: true }
    );

    return router.push(url);
  };
  return (
    <div className="flex items-center justify-center gap-4 p-5">
      <button
        disabled={page <= 1}
        onClick={() => handleClick("prev")}
        className={`rounded-xl px-4 py-2 text-gray-300 ${
          page <= 1
            ? "cursor-not-allowed bg-tertiary opacity-50"
            : "bg-tertiary hover:bg-main"
        }`}
      >
        previous
      </button>
      <div className="rounded-xl bg-main px-4 py-2 text-gray-300"> {page}</div>
      <button
        disabled={!isNext}
        onClick={() => handleClick("next")}
        className={`rounded-xl px-4 py-2 text-gray-300 ${
          !isNext
            ? "cursor-not-allowed bg-tertiary opacity-50"
            : "bg-tertiary hover:bg-main"
        }`}
      >
        Next
      </button>
    </div>
  );
}

export default Pagination;
