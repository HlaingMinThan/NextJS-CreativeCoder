import Question, { IQuestion } from "@/database/question.model";
import dbConnect from "../dbConnect";
import { actionError } from "../response";

const GetPopularQuestions = async (): Promise<{
  success: boolean;
  data?: {
    questions: IQuestion[];
  };
  message?: string;
  details?: object | null;
}> => {
  await dbConnect();
  try {
    const questions = await Question.find({})
      .select("_id title views upvotes")
      .lean()
      .sort({ views: -1, upvotes: -1 })
      .limit(5);
    return {
      success: true,
      data: {
        questions: JSON.parse(JSON.stringify(questions)),
      },
    };
  } catch (e) {
    return actionError(e);
  }
};

export default GetPopularQuestions;
