"use client";
import { useRouter, useSearchParams } from "next/navigation";
import queryString from "query-string";
import React, { useState, useTransition } from "react";

interface Filter {
  name: string;
  value: string;
}

function CommonFilter({
  filters,
  defaultFilter,
}: {
  filters: Filter[];
  defaultFilter: string;
}) {
  const router = useRouter();
  let [isPending, startTransition] = useTransition();
  const searchParams = useSearchParams();
  const currentFilter = searchParams.get("filter") || defaultFilter || "";

  const handleFilterChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const selectedValue = e.target.value;

    const currentQuery = queryString.parse(window.location.search);
    console.log(currentQuery);
    const updatedQuery = {
      ...currentQuery,
      filter: selectedValue || "",
    };

    const url = queryString.stringifyUrl(
      {
        url: window.location.pathname,
        query: updatedQuery,
      },
      { skipEmptyString: true, skipNull: true }
    );
    startTransition(() => {
      router.push(url);
    });
  };
  return (
    <div className="p-5">
      <select
        value={currentFilter}
        onChange={handleFilterChange}
        className="rounded-xl px-4 py-2 bg-tertiary text-gray-300 border-none outline-none cursor-pointer hover:bg-main"
      >
        {filters.map((filter) => (
          <option value={filter.value} key={filter?.value}>
            {filter.name}
          </option>
        ))}
      </select>
      {isPending && <span>loading...</span>}
    </div>
  );
}

export default CommonFilter;
