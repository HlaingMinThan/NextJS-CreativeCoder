"use server";

import { auth } from "@/auth";
import dbConnect from "../dbConnect";
import Vote from "@/database/vote.model";
import validateBody from "../validateBody";
import GetUserVoteSchema from "../schemas/GetUserVoteSchema";
import { actionError } from "../response";

let GetUserVote = async (params: {
  type: "question" | "answer";
  typeId: string;
}): Promise<{
  success: boolean;
  data?: {
    userVote: "upvote" | "downvote" | null;
  };
  message?: string;
  details?: object | null;
}> => {
  await dbConnect();
  const auth_session = await auth();
  const userId = auth_session?.user?.id;
  if (!userId) throw new Error("Unauthorized");
  const validatedData = validateBody(params, GetUserVoteSchema);

  const { type, typeId } = validatedData.data;

  try {
    const vote = await Vote.findOne({
      author: userId,
      type_id: typeId,
      type,
    });

    return {
      success: true,
      data: {
        userVote: vote?.voteType || null,
      },
    };
  } catch (e) {
    return actionError(e);
  }
};

export default GetUserVote;
