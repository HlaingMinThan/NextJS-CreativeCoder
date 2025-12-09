"use server";

import { auth } from "@/auth";
import dbConnect from "../dbConnect";
import { actionError } from "../response";
import validateBody from "../validateBody";
import DeleteAnswerSchema from "../schemas/DeleteAnswerSchema";
import Answer from "@/database/answer.model";
import Question from "@/database/question.model";
import Vote from "@/database/vote.model";
import { revalidatePath } from "next/cache";
import ROUTES from "@/routes";

const deleteAnswer = async (params: { answerId: string }) => {
  await dbConnect();
  const validatedData = validateBody(params, DeleteAnswerSchema);
  const { answerId } = validatedData.data;
  const auth_session = await auth();
  const user = auth_session?.user;
  try {
    const answer = await Answer.findById(answerId);
    if (!answer) throw new Error("Answer not found");

    await Question.findByIdAndUpdate(
      answer.question,
      {
        $inc: { answers: -1 },
      },
      { new: true }
    );

    await Vote.deleteMany({
      actionId: answerId,
      actionType: "answer",
    });

    await Answer.findByIdAndDelete(answerId);

    revalidatePath(ROUTES.PROFILE(user?.id as string));

    return { success: true };
  } catch (e) {
    return actionError(e);
  }
};

export default deleteAnswer;
