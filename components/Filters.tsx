"use client";

import { useRouter, useSearchParams } from "next/navigation";
import queryString from "query-string";
import React, { useState } from "react";

function Filters() {
  const searchParams = useSearchParams();
  const [filter, setFilter] = useState(searchParams.get("filter") || "");
  const router = useRouter();

  const handleFilter = (filterType: string) => {
    if (filterType === filter) {
      setFilter("");
    } else {
      setFilter(filterType);
    }
    const currentQuery = queryString.parse(window.location.search);
    const updatedQuery = {
      ...currentQuery,
      filter: filterType === filter ? "" : filterType,
    };

    const url = queryString.stringifyUrl(
      {
        url: window.location.pathname,
        query: updatedQuery,
      },
      { skipEmptyString: true, skipNull: true }
    );

    router.push(url);
  };
  return (
    <div className="flex space-x-6 p-5">
      <button
        onClick={() => handleFilter("react")}
        className={`w-[100px] rounded-xl px-4 py-2 text-gray-300 ${
          filter === "react" ? "bg-main" : "bg-tertiary"
        }`}
      >
        React
      </button>
      <button
        onClick={() => handleFilter("vue")}
        className={`w-[100px] rounded-xl px-4 py-2 text-gray-300 ${
          filter === "vue" ? "bg-main" : "bg-tertiary"
        }`}
      >
        Vue
      </button>
    </div>
  );
}

export default Filters;
