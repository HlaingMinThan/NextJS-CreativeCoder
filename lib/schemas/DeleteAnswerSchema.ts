import z from "zod";

const DeleteAnswerSchema = z.object({
  answerId: z.string(),
});

export default DeleteAnswerSchema;
