"use server";
import dbConnect from "../dbConnect";
import { actionError } from "../response";
import generateAiAnswerSchema from "../schemas/generateAiAnswerSchema";
import validateBody from "../validateBody";
import { google } from "@ai-sdk/google";
import { generateText } from "ai";

const generateAiAnswerAction = async (params: {
  title: string;
  content: string;
  userAnswer: string;
}): Promise<{
  success: boolean;
  data?: {
    answer: string;
  };
  message?: string;
  details?: object | null;
}> => {
  await dbConnect();
  const validatedData = validateBody(params, generateAiAnswerSchema);
  const { title, content, userAnswer } = validatedData.data;

  const { text: answer } = await generateText({
    model: google("gemini-2.0-flash"),
    prompt: `Generate a clear and concise answer in markdown format to the question: "${title}".

Use the context and the user's answer **only to improve accuracy** — do not mention them or explain how they are used.

**Context:** ${content}  
**User's Answer:** ${userAnswer}

Rules:
- If the user's answer is correct, refine and expand on it.
- If the user's answer is incomplete or incorrect, correct it and provide the proper explanation.
- Do NOT reference the context, the prompt, or say things like "based on the context" or "the user's input".
- Final output must be the answer only, written in helpful markdown format.`,
    system:
      "You are a helpful assistant that provides informative responses in markdown format. Use appropriate markdown syntax for headings, lists, code blocks, and emphasis where necessary. For code blocks, use short-form smaller case language identifiers (e.g., 'js' for JavaScript, 'py' for Python, 'ts' for TypeScript, 'html' for HTML, 'css' for CSS, etc.).",
  });

  try {
    //ai answer generation
    return {
      success: true,
      data: {
        answer,
      },
    };
  } catch (error) {
    return actionError(error);
  }
};

export default generateAiAnswerAction;
