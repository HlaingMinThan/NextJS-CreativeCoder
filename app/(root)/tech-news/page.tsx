//ISR (SSG+REVALIDATE)
export const dynamic = "force-static"; //SSG
export const revalidate = 10;

import React from "react";
import TechNewsCard from "./components/TechNewsCard";
import DataRenderer from "@/components/DataRenderer";
import GetTechNews from "@/lib/actions/GetTechNews";

async function page() {
  const { success, data, message } = await GetTechNews();
  const articles = data?.articles || [];
  const errorMessage = message || "";

  return (
    <>
      <div className="flex items-center justify-between p-5">
        <div>
          <h1 className="text-3xl font-bold">Tech News</h1>
          <p className="text-gray-400 mt-2">Latest articles from dev.to</p>
        </div>
      </div>
      <DataRenderer
        success={success}
        data={articles}
        errorMessage={errorMessage}
        render={(articles) =>
          articles.map((article: any) => (
            <TechNewsCard key={article.id} article={article} />
          ))
        }
      />
    </>
  );
}

export default page;
