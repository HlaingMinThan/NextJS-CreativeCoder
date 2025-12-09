"use server";

import Question, { IQuestionDoc } from "@/database/question.model";
import dbConnect from "../dbConnect";
import PaginatedSearchParamsSchema from "../schemas/PaginatedSearchParamsSchema";
import validateBody from "../validateBody";
import { FilterQuery } from "mongoose";
import { actionError } from "../response";

export async function getQuestions(params: {
  page?: number;
  pageSize?: number;
  search?: string;
  filter?: string;
  sort?: string;
}): Promise<{
  data?: {
    questions: IQuestionDoc[];
    isNext: boolean;
  };
  success: boolean;
  message?: string;
  details?: object | null;
}> {
  await dbConnect();
  const validatedData = validateBody(params, PaginatedSearchParamsSchema);
  let { page = 1, pageSize = 10, search, filter, sort } = validatedData.data;

  const skip = (Number(page) - 1) * pageSize;
  const limit = Number(pageSize);

  const filterQuery: FilterQuery<typeof Question> = {};

  //implement later on
  if (filter === "recommended") {
    return { success: true, data: { questions: [], isNext: false } };
  }

  if (search) {
    filterQuery.$or = [
      { title: { $regex: new RegExp(search, "i") } },
      { content: { $regex: new RegExp(search, "i") } },
    ];
  }

  let sortCriteria = {};

  switch (filter) {
    case "newest":
      sortCriteria = { createdAt: -1 };
      break;
    case "unanswered":
      filterQuery.answers = 0;
      sortCriteria = { createdAt: -1 };
      break;
    case "popular":
      sortCriteria = { upvotes: -1 };
      break;
    default:
      sortCriteria = { createdAt: -1 };
      break;
  }

  try {
    const totalQuestions = await Question.countDocuments(filterQuery);
    const questions = await Question.find(filterQuery)
      .populate("tags", "name")
      .populate("author", "name image")
      .lean()
      .sort(sortCriteria)
      .skip(skip)
      .limit(limit);

    const isNext = totalQuestions > skip + questions.length;

    return {
      success: true,
      data: {
        questions: JSON.parse(JSON.stringify(questions)),
        isNext,
      },
    };
  } catch (e) {
    return actionError(e);
  }
}
