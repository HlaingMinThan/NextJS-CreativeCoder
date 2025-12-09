"use server";

import Question from "@/database/question.model";
import dbConnect from "../dbConnect";
import { actionError } from "../response";
import BookMarkSchema from "../schemas/BookMarkSchema";
import validateBody from "../validateBody";
import Collection from "@/database/collection.model";
import { auth } from "@/auth";
import { revalidatePath } from "next/cache";
import ROUTES from "@/routes";

const ToggleBookMarkAction = async (params: {
  questionId: string;
}): Promise<{
  success: boolean;
  data?: {
    saved: boolean;
  };
  message?: string;
  details?: object | null;
}> => {
  await dbConnect();
  const validatedData = validateBody(params, BookMarkSchema);
  const { questionId } = validatedData.data;
  try {
    const question = Question.findById(questionId);
    if (!question) throw new Error("question not found");
    const auth_session = await auth();
    const userId = auth_session?.user?.id;

    const collection = await Collection.findOne({
      question: questionId,
      author: userId,
    });
    if (collection) {
      await Collection.findByIdAndDelete(collection._id);
      return {
        success: true,
        data: {
          saved: false,
        },
      };
    }

    await Collection.create({
      question: questionId,
      author: userId,
    });
    return {
      success: true,
      data: {
        saved: true,
      },
    };
  } catch (e) {
    return actionError(e);
  }
};

export default ToggleBookMarkAction;
