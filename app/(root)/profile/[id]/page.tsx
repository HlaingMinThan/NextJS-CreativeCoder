import React, { Suspense } from "react";
import GetUser from "@/lib/actions/GetUser";
import ProfileHeader from "../components/ProfileHeader";
import getUserQuestions from "@/lib/actions/getUserQuestions";
import DataRenderer from "@/components/DataRenderer";
import ThreadCard from "@/components/ThreadCard";
import getUserAnswers from "@/lib/actions/GetUserAnswers";
import AnswerCard from "../../questions/components/AnswerCard";
import Link from "next/link";
import Pagination from "@/components/Pagination";
import { auth } from "@/auth";

const Page = async ({
  params,
  searchParams,
}: {
  params: { id: string };
  searchParams: { tab: string; page: string };
}) => {
  const { id } = params;

  const activeTab = searchParams.tab || "questions";
  let page = searchParams.page || 1;
  page = Number(page);

  let isSuccess;
  let dataForLoop;
  let errorMessage;
  let isNextValue;
  if (activeTab === "questions") {
    let { success, data, message } = await getUserQuestions({
      userId: id,
      page,
      pageSize: 10,
    });
    const { questions = [], isNext = false } = data || {};
    isSuccess = success;
    dataForLoop = questions;
    errorMessage = message;
    isNextValue = isNext;
  } else {
    let { success, data, message } = await getUserAnswers({
      userId: id,
      page,
      pageSize: 10,
    });
    const { answers = [], isNext = false } = data || {};
    isSuccess = success;
    dataForLoop = answers;
    errorMessage = message;
    isNextValue = isNext;
  }

  const user_session = await auth();

  return (
    <div className="mx-auto max-w-5xl px-4 py-8">
      <Suspense fallback={<>loading...</>}>
        <ProfileHeader userId={id} />
      </Suspense>

      <div className="my-7 space-x-5">
        <Link
          href={`/profile/${id}?tab=questions`}
          className={` border-white border rounded-xl px-2 py-1 ${
            activeTab === "questions" ? "bg-main" : "bg-primary"
          }`}
        >
          Top Questions
        </Link>
        <Link
          href={`/profile/${id}?tab=answers`}
          className={` border-white border rounded-xl px-2 py-1 ${
            activeTab === "answers" ? "bg-main" : "bg-primary"
          }`}
        >
          Top Answers
        </Link>
      </div>
      {activeTab === "questions" ? (
        <>
          <DataRenderer
            success={isSuccess}
            data={dataForLoop}
            errorMessage={errorMessage}
            render={(questions) =>
              questions.map((question) => (
                <ThreadCard
                  key={question._id}
                  question={question}
                  showActions={user_session?.user?.id === question.author._id}
                />
              ))
            }
          />
          <Pagination isNext={isNextValue} page={page} />
        </>
      ) : (
        <>
          <DataRenderer
            success={isSuccess}
            data={dataForLoop}
            errorMessage={errorMessage}
            render={(answers) =>
              answers.map((answer) => (
                <AnswerCard
                  key={answer._id.toString()}
                  answer={answer}
                  showActions={user_session?.user?.id === answer.author._id}
                />
              ))
            }
          />
          <Pagination isNext={isNextValue} page={page} />
        </>
      )}
    </div>
  );
};

export default Page;
