import { z } from "zod";

const IncrementViewSchema = z.object({
  questionId: z.string(),
});

export default IncrementViewSchema;
