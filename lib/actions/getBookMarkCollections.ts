"use server";

import mongoose, { PipelineStage } from "mongoose";
import { ICollection } from "@/database/collection.model";
import Collection from "@/database/collection.model";
import dbConnect from "../dbConnect";
import { auth } from "@/auth";
import validateBody from "../validateBody";
import PaginatedSearchParamsSchema from "../schemas/PaginatedSearchParamsSchema";
import { actionError } from "../response";

const getBookMarkCollections = async (params: {
  page?: number;
  pageSize?: number;
  search?: string;
  filter?: string;
  sort?: string;
}): Promise<{
  data?: {
    collections: ICollection[];
    isNext: boolean;
  };
  success: boolean;
  message?: string;
  details?: object | null;
}> => {
  await dbConnect();
  const auth_session = await auth();
  const userId = auth_session?.user?.id;

  if (!userId) {
    return {
      success: true,
      data: { collections: [], isNext: false },
    };
  }

  const validatedData = validateBody(params, PaginatedSearchParamsSchema);

  let { page = 1, pageSize = 10, search, filter } = validatedData.data;

  const skip = (Number(page) - 1) * pageSize;
  const limit = Number(pageSize);

  // Define sort options for all filters
  const sortOptions: Record<string, Record<string, 1 | -1>> = {
    mostrecent: { "question.createdAt": -1 },
    oldest: { "question.createdAt": 1 },
    mostvoted: { "question.upvotes": -1 },
    mostviewed: { "question.views": -1 },
    mostanswered: { "question.answers": -1 },
  };

  const sortCriteria = sortOptions[filter] || sortOptions.mostrecent;
  /* collection -> {
    _id : "asdfsafsdf",
    question : { 
    _id : "adfasdf", 
    title: "adfasdfs", 
    content: "adfasdfs", 
    author:{_id:"asdfsaf"},
    tags:[]
    ]
   } */
  try {
    // Build aggregation pipeline - collection
    const pipeline: PipelineStage[] = [
      // Match collections for the current user
      {
        $match: { author: new mongoose.Types.ObjectId(userId) },
      },
      // Lookup questions -> join -> collection -> question
      {
        $lookup: {
          from: "questions",
          localField: "question",
          foreignField: "_id",
          as: "question",
        },
      },
      // Unwind question
      { $unwind: "$question" },
      // Lookup author
      {
        $lookup: {
          from: "users",
          localField: "question.author",
          foreignField: "_id",
          as: "question.author",
        },
      },
      // Unwind author
      { $unwind: "$question.author" },
      // Lookup tags
      {
        $lookup: {
          from: "tags",
          localField: "question.tags",
          foreignField: "_id",
          as: "question.tags",
        },
      },
    ];

    // Apply search filter if provided
    if (search) {
      pipeline.push({
        $match: {
          $or: [
            { "question.title": { $regex: search, $options: "i" } },
            { "question.content": { $regex: search, $options: "i" } },
          ],
        },
      });
    }

    // Get total count before pagination
    const [totalCountResult] = await Collection.aggregate([
      ...pipeline,
      { $count: "count" },
    ]); // [{count : 10}]

    const totalCollections = totalCountResult?.count || 0;

    // Add sorting and pagination &  Execute aggregation
    const collections = await Collection.aggregate([
      ...pipeline,
      { $sort: sortCriteria },
      { $skip: skip },
      { $limit: limit },
    ]); // []

    const isNext = totalCollections > skip + collections.length;

    return {
      success: true,
      data: {
        collections: JSON.parse(JSON.stringify(collections)),
        isNext,
      },
    };
  } catch (e) {
    return actionError(e);
  }
};

export default getBookMarkCollections;
