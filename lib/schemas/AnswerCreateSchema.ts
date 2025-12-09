import { z } from "zod";

const AnswerCreateSchema = z.object({
  questionId: z.string(),
  content: z.string(),
});

export default AnswerCreateSchema;
