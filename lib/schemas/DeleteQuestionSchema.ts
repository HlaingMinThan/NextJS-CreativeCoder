import z from "zod";

const DeleteQuestionSchema = z.object({
  questionId: z.string(),
});

export default DeleteQuestionSchema;
