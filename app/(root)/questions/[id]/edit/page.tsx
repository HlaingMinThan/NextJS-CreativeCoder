import React from "react";

import QuestionForm from "../../components/QuestionForm";
import { GetQuestion } from "@/lib/actions/GetQuestion.action";
import { notFound } from "next/navigation";

async function page({ params }: { params: { id: string } }) {
  let { data: question, success } = await GetQuestion({
    questionId: params.id,
  });
  if (!success) return notFound();

  return <QuestionForm question={question} isEdit={true} />;
}

export default page;
