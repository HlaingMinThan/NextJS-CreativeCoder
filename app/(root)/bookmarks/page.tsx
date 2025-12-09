import CommonFilter from "@/components/CommonFilter";
import DataRenderer from "@/components/DataRenderer";
import Filters from "@/components/Filters";
import Pagination from "@/components/Pagination";
import ThreadCard from "@/components/ThreadCard";
import {
  UserFilters,
  DefaultFilters,
  CollectionFilters,
} from "@/constant/filters";
import getBookMarkCollections from "@/lib/actions/getBookMarkCollections";

async function page({
  searchParams,
}: {
  searchParams: Promise<{
    [key: string]: string;
  }>;
}) {
  const { page, pageSize, search, filter } = await searchParams;

  const { success, data, message } = await getBookMarkCollections({
    page: Number(page) || 1,
    pageSize: Number(pageSize) || 10,
    search: search || "",
    filter: filter || "",
  });

  const { collections = [], isNext = false } = data || {};

  return (
    <>
      <div className="flex items-center justify-between p-5">
        <div className="flex justify-between items-center">
          <h1 className="text-3xl font-bold">Saved Threads</h1>
          <div>
            <CommonFilter
              filters={CollectionFilters}
              defaultFilter={DefaultFilters.CollectionFilters}
            />
          </div>
        </div>
      </div>
      <Filters />
      <DataRenderer
        success={success}
        data={collections}
        errorMessage={message}
        render={(collections) =>
          collections.map((collection) => (
            <ThreadCard key={collection._id} question={collection.question} />
          ))
        }
      />
      <Pagination isNext={isNext} page={page || 1} />
    </>
  );
}

export default page;
