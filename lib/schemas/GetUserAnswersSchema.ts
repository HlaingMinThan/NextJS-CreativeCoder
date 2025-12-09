import z from "zod";

const GetUserAnswersSchema = z.object({
  userId: z.string(),
  page: z.number().positive().optional(),
  pageSize: z.number().positive().optional(),
});

export default GetUserAnswersSchema;
