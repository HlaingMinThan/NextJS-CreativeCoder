import dbConnect from "../dbConnect";
import { actionError } from "../response";
import Tag, { ITag } from "@/database/tag.model";

const GetPopularTags = async (): Promise<{
  success: boolean;
  data?: {
    tags: ITag[];
  };
  message?: string;
  details?: object | null;
}> => {
  await dbConnect();
  try {
    const tags = await Tag.find({}).lean().sort({ questions: -1 }).limit(5);
    return {
      success: true,
      data: {
        tags: JSON.parse(JSON.stringify(tags)),
      },
    };
  } catch (e) {
    return actionError(e);
  }
};

export default GetPopularTags;
