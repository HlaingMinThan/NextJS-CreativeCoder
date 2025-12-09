import { auth } from "@/auth";
import ButtonLink from "@/components/ButtonLink";
import DataRenderer from "@/components/DataRenderer";
import Filters from "@/components/Filters";
import Pagination from "@/components/Pagination";
import ThreadCard from "@/components/ThreadCard";
import { getQuestions } from "@/lib/actions/GetQuestions.action";
import getTagQuestions from "@/lib/actions/GetTagQuestions";
import { api } from "@/lib/api";
import fetchHandler from "@/lib/fetchHandler";
import ROUTES from "@/routes";

async function page({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{
    [key: string]: string;
  }>;
}) {
  const { id } = await params;
  const { page, pageSize, search } = await searchParams;

  const { success, data, message } = await getTagQuestions({
    page: Number(page) || 1,
    pageSize: Number(pageSize) || 10,
    search: search || "",
    tagId: id,
  });

  const { questions = [], tag, isNext = false } = data || {};

  return (
    <>
      <div className="flex items-center justify-between p-5">
        <div>
          <h1 className="text-3xl font-bold">{tag?.name}</h1>
        </div>
      </div>
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
      <Pagination isNext={isNext} page={page || 1} />
    </>
  );
}

export default page;
