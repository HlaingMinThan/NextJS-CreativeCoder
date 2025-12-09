import z from "zod";

const GetUserParamsSchema = z.object({
  userId: z.string(),
});

export default GetUserParamsSchema;
