"use server";

import { auth } from "@/auth";
import dbConnect from "../dbConnect";
import DeleteQuestionSchema from "../schemas/DeleteQuestionSchema";
import validateBody from "../validateBody";
import mongoose from "mongoose";
import { actionError } from "../response";
import Question from "@/database/question.model";
import Collection from "@/database/collection.model";
import TagQuestion from "@/database/tag-question.model";
import Tag from "@/database/tag.model";
import Answer from "@/database/answer.model";
import Vote from "@/database/vote.model";
import { revalidatePath } from "next/cache";
import ROUTES from "@/routes";

const deleteQuestion = async (params: { questionId: string }) => {
  await dbConnect();
  const validatedData = validateBody(params, DeleteQuestionSchema);
  const { questionId } = validatedData.data;
  const auth_session = await auth();
  const user = auth_session?.user;

  const session = await mongoose.startSession();
  try {
    session.startTransaction();
    const question = await Question.findById(questionId);
    if (!question) throw new Error("Question not found");

    if (question.author.toString() !== user?.id) {
      throw new Error("Not authorized");
    }

    //collection
    await Collection.deleteMany({
      question: questionId,
    }).session(session);

    await TagQuestion.deleteMany({ question: questionId }).session(session);

    if (question.tags.length > 0) {
      await Tag.updateMany(
        { _id: { $in: question.tags } },
        {
          $inc: { questions: -1 },
        },
        {
          session,
        }
      );
    }

    await Vote.deleteMany({
      actionId: questionId,
      actionType: "question",
    }).session(session);

    const answers = await Answer.find({
      question: questionId,
    }).session(session);

    if (answers.length > 0) {
      await Answer.deleteMany({ question: questionId });

      await Vote.deleteMany({
        actionId: {
          $in: answers.map((a) => a._id),
        },
        actionType: "answer",
      }).session(session);
    }

    await Question.findByIdAndDelete(questionId).session(session);
    await session.commitTransaction();
    revalidatePath(ROUTES.PROFILE(user?.id as string));

    return { success: true };
  } catch (e) {
    await session.abortTransaction();
    return actionError(e);
  } finally {
    await session.endSession();
  }
};

export default deleteQuestion;
