import { z } from "zod";

const GetAnswerSchema = z.object({
  page: z.number().positive(),
  pageSize: z.number().positive(),
  filter: z.string(),
  questionId: z.string(),
});

export default GetAnswerSchema;
