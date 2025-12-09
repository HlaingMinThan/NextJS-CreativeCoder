import DataRenderer from "@/components/DataRenderer";
import React from "react";
import AnswerCard from "./AnswerCard";
import CommonFilter from "@/components/CommonFilter";
import { AnswerFilters, DefaultFilters } from "@/constant/filters";
import GetAnswers from "@/lib/actions/GetAnswers";
import Pagination from "@/components/Pagination";

async function AnswerList({
  page,
  pageSize,
  filter,
  id,
}: {
  page: number;
  pageSize: number;
  filter: string;
  id: string;
}) {
  const {
    success,
    data: answersData,
    message: answerError,
  } = await GetAnswers({
    page: Number(page),
    pageSize: Number(pageSize),
    filter: filter || DefaultFilters.AnswerFilters,
    questionId: id,
  });

  const { answers = [], totalAnswers = 0, isNext = false } = answersData || {};
  return (
    <>
      <div className="mt-8">
        <div className="flex justify-between items-center">
          <h3 className="font-bold text-xl">AnswerList - {totalAnswers}</h3>
          <div>
            <CommonFilter
              filters={AnswerFilters}
              defaultFilter={DefaultFilters.AnswerFilters}
            />
          </div>
        </div>
        <DataRenderer
          success={success}
          errorMessage={answerError}
          data={answers}
          render={(answers) => {
            return answers.map((answer) => {
              return <AnswerCard key={answer._id.toString()} answer={answer} />;
            });
          }}
        />
      </div>
      <Pagination isNext={isNext} page={page || 1} />
    </>
  );
}

export default AnswerList;
