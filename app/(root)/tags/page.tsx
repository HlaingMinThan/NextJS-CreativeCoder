import { auth } from "@/auth";
import CommonFilter from "@/components/CommonFilter";
import DataRenderer from "@/components/DataRenderer";
import Pagination from "@/components/Pagination";
import TagInfoCard from "@/components/TagInfoCard";
import {
  HomePageFilters,
  DefaultFilters,
  TagFilters,
} from "@/constant/filters";
import { getTags } from "@/lib/actions/GetTags.action";

async function page({
  searchParams,
}: {
  searchParams: Promise<{
    [key: string]: string;
  }>;
}) {
  const session = await auth();
  const { page, pageSize, search, filter } = await searchParams;

  const { success, data, message } = await getTags({
    page: Number(page) || 1,
    pageSize: Number(pageSize) || 10,
    search: search || "",
    filter: filter || "",
  });

  const { tags = [], isNext = false } = data || {};

  return (
    <>
      <div className="flex items-center justify-between p-5">
        <div className="flex justify-between items-center">
          <h1 className="text-3xl font-bold">All Tags</h1>
          <div>
            <CommonFilter
              filters={TagFilters}
              defaultFilter={DefaultFilters.TagFilters}
            />
          </div>
        </div>
      </div>
      <DataRenderer
        success={success}
        data={tags}
        errorMessage={message}
        render={(tags) => {
          return (
            <div className="grid grid-cols-4 gap-4">
              {tags.map((tag) => (
                <TagInfoCard
                  key={tag._id.toString()}
                  id={tag._id.toString()}
                  name={tag.name}
                  count={tag.questions}
                />
              ))}
            </div>
          );
        }}
      />
      <Pagination isNext={isNext} page={page || 1} />
    </>
  );
}

export default page;
