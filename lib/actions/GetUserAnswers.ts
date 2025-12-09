"use server";

import Answer, { IAnswerDoc } from "@/database/answer.model";
import dbConnect from "../dbConnect";
import validateBody from "../validateBody";
import GetUserAnswersSchema from "../schemas/GetUserAnswersSchema";
import { actionError } from "../response";

const getUserAnswers = async (params: {
  userId: string;
  page?: number;
  pageSize?: number;
}): Promise<{
  success: boolean;
  data?: {
    answers: IAnswerDoc[];
    isNext: boolean;
  };
  message?: string;
  details?: object | null;
}> => {
  await dbConnect();
  const validatedData = validateBody(params, GetUserAnswersSchema);
  const { userId, page = 1, pageSize = 10 } = validatedData.data;

  const skip = (Number(page) - 1) * pageSize;
  const limit = Number(pageSize);

  try {
    const [totalAnswers, answers] = await Promise.all([
      Answer.countDocuments({ author: userId }),
      Answer.find({ author: userId })
        .populate("author", "_id name image")
        .populate("question", "_id title")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
    ]);

    const isNext = totalAnswers > skip + answers.length;

    return {
      success: true,
      data: {
        answers: JSON.parse(JSON.stringify(answers)),
        isNext,
      },
    };
  } catch (e) {
    return actionError(e);
  }
};

export default getUserAnswers;
