"use server";

import mongoose from "mongoose";
import Answer, { IAnswerDoc } from "@/database/answer.model";
import dbConnect from "../dbConnect";
import { actionError } from "../response";
import Question from "@/database/question.model";
import validateBody from "../validateBody";
import AnswerCreateSchema from "../schemas/AnswerCreateSchema";
import { auth } from "@/auth";

const AnswerCreate = async (params: {
  questionId: string;
  content: string;
}): Promise<{
  success: boolean;
  data?: { newAnswer: IAnswerDoc };
  message?: string;
  details?: object | null;
}> => {
  await dbConnect();
  const validatedData = validateBody(params, AnswerCreateSchema);
  const { questionId, content } = validatedData.data;

  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const auth_session = await auth();
    const userId = auth_session?.user?.id;
    const question = await Question.findById(questionId);
    if (!question) throw new Error("Question not found");

    const [newAnswer] = await Answer.create(
      [
        {
          author: userId,
          question: questionId,
          content,
        },
      ],
      { session }
    );

    question.answers += 1;
    await question.save({ session });
    await session.commitTransaction();

    return {
      success: true,
      data: {
        newAnswer: JSON.parse(JSON.stringify(newAnswer)),
      },
    };
  } catch (e) {
    session.abortTransaction();
    return actionError(e);
  } finally {
    await session.endSession();
  }
};

export default AnswerCreate;
