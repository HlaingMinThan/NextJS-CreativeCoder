"use server";

import validateBody from "@/lib/validateBody";
import IncrementViewSchema from "../schemas/IncrementViewSchema";
import { actionError } from "../response";
import Question from "@/database/question.model";
export async function incrementViews(params: { questionId: string }): Promise<{
  success: boolean;
  data?: { views: number };
  message?: string;
  details?: object | null;
}> {
  const validatedData = validateBody(params, IncrementViewSchema);
  const { questionId } = validatedData.data;

  try {
    const question = await Question.findById(questionId);
    if (!question) throw new Error("Question not found");

    question.views += 1;
    await question.save();

    return {
      success: true,
      data: {
        views: question.views,
      },
    };
  } catch (e) {
    return actionError(e);
  }
}
