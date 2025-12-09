import { auth } from "@/auth";
import ButtonLink from "@/components/ButtonLink";
import CommonFilter from "@/components/CommonFilter";
import DataRenderer from "@/components/DataRenderer";
import Filters from "@/components/Filters";
import Pagination from "@/components/Pagination";
import ThreadCard from "@/components/ThreadCard";
import { DefaultFilters, HomePageFilters } from "@/constant/filters";
import { getQuestions } from "@/lib/actions/GetQuestions.action";
import { api } from "@/lib/api";
import fetchHandler from "@/lib/fetchHandler";
import ROUTES from "@/routes";

async function page({
  searchParams,
}: {
  searchParams: Promise<{
    [key: string]: string;
  }>;
}) {
  const session = await auth();
  const { page = 1, pageSize = 10, search, filter } = await searchParams;

  const { success, data, message } = await getQuestions({
    page: Number(page) || 1,
    pageSize: Number(pageSize) || 10,
    search: search || "",
    filter: filter || "",
  });

  const { questions = [], isNext = false } = data || {};

  return (
    <>
      <div className="flex items-center justify-between p-5">
        <div>
          <h1 className="text-3xl font-bold">All Threads</h1>
        </div>
        <div>
          <CommonFilter
            filters={HomePageFilters}
            defaultFilter={DefaultFilters.HomePageFilters}
          />
        </div>
        <div>
          <ButtonLink href={ROUTES.QUESTION_CREATE}>
            Create new thread
          </ButtonLink>
        </div>
      </div>
      <Filters />
      <DataRenderer
        success={success}
        data={questions}
        errorMessage={message}
        render={(questions) =>
          questions.map((question) => (
            <ThreadCard key={question._id} question={question} />
          ))
        }
      />
      <Pagination isNext={isNext} page={page} />
    </>
  );
}

export default page;
