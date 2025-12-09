import { z } from "zod";

const generateAiAnswerSchema = z.object({
  title: z.string(),
  content: z.string(),
  userAnswer: z.string(),
});

export default generateAiAnswerSchema;
