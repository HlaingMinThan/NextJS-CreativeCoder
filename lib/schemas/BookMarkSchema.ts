import z from "zod";

const BookMarkSchema = z.object({
  questionId: z.string(),
});

export default BookMarkSchema;
