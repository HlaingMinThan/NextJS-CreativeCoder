"use server";

import dbConnect from "../dbConnect";
import PaginatedSearchParamsSchema from "../schemas/PaginatedSearchParamsSchema";
import validateBody from "../validateBody";
import { FilterQuery } from "mongoose";
import { actionError } from "../response";
import Tag, { ITagDoc } from "@/database/tag.model";

export async function getTags(params: {
  page?: number;
  pageSize?: number;
  search?: string;
  filter?: string;
  sort?: string;
}): Promise<{
  data?: {
    tags: ITagDoc[];
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

  const filterQuery: FilterQuery<typeof Tag> = {};

  if (search) {
    filterQuery.$or = [{ name: { $regex: new RegExp(search, "i") } }];
  }

  let sortCriteria = {};

  switch (filter) {
    case "popular":
      sortCriteria = { questions: -1 };
      break;
    case "recent":
      sortCriteria = { createdAt: -1 };
      break;
    case "oldest":
      sortCriteria = { createdAt: 1 };
      break;
    case "name":
      sortCriteria = { name: 1 };
      break;
    default:
      sortCriteria = { questions: -1 };
      break;
  }

  try {
    const totalTags = await Tag.countDocuments(filterQuery);
    const tags = await Tag.find(filterQuery)
      .lean()
      .sort(sortCriteria)
      .skip(skip)
      .limit(limit);

    const isNext = totalTags > skip + tags.length;

    return {
      success: true,
      data: {
        tags: JSON.parse(JSON.stringify(tags)),
        isNext,
      },
    };
  } catch (e) {
    return actionError(e);
  }
}
