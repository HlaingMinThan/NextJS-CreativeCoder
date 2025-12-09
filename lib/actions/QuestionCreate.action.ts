"use server";

import Question from "@/database/question.model";
import mongoose from "mongoose";
import dbConnect from "../dbConnect";
import QuestionCreateSchema from "../schemas/QuestionCreateSchema";
import validateBody from "../validateBody";
import { auth } from "@/auth";
import { actionError } from "../response";
import TagQuestion from "@/database/tag-question.model";
import Tag from "@/database/tag.model";

export async function QuestionCreate(params: {
  title: string;
  content: string;
  tags: string[];
}): Promise<{
  success: Boolean;
  data?: {
    _id: string;
    title: string;
    content: string;
    author: string;
    tags: string[];
  };
}> {
  await dbConnect();
  const validatedData = validateBody(params, QuestionCreateSchema);
  const { title, content, tags } = validatedData.data;
  const auth_session = await auth();
  const userId = auth_session?.user?.id;

  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    let [question] = await Question.create(
      [{ title, content, author: userId }],
      { session }
    );
    if (!question) {
      throw new Error("Failed to create a question");
    }

    const tagIds: mongoose.Types.ObjectId[] = [];
    const tagQuestionDocuments = [];

    for (const tag of tags) {
      const existingTag = await Tag.findOneAndUpdate(
        { name: { $regex: new RegExp(`^${tag}$`, "i") } },
        { $setOnInsert: { name: tag }, $inc: { questions: 1 } },
        { upsert: true, new: true, session }
      );

      tagIds.push(existingTag._id);
      tagQuestionDocuments.push({
        tag: existingTag._id,
        question: question._id,
      });
    }

    await TagQuestion.insertMany(tagQuestionDocuments, { session });

    await Question.findByIdAndUpdate(
      question._id,
      { $push: { tags: { $each: tagIds } } },
      { session }
    );

    await session.commitTransaction();

    return { success: true, data: JSON.parse(JSON.stringify(question)) };
  } catch (error) {
    await session.abortTransaction();
    return actionError(error);
  } finally {
    await session.endSession();
  }
}
