"use client";

import Button from "@/components/Button";
import Editor from "@/components/Editor";
import AnswerCreate from "@/lib/actions/AnswerCreate";
import generateAiAnswerAction from "@/lib/actions/generateAiAnswerAction";
import ROUTES from "@/routes";
import { useRouter } from "next/navigation";
import React, { useState } from "react";
import { Bounce, toast } from "react-toastify";

function AnswerForm({
  questionId,
  questionTitle,
  questionContent,
}: {
  questionId: string;
  questionTitle: string;
  questionContent: string;
}) {
  const [content, setContent] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const generateAiAnswer = async () => {
    try {
      setLoading(true);
      const { success, data } = await generateAiAnswerAction({
        title: questionTitle,
        content: questionContent,
        userAnswer: content,
      });
      if (success && data) {
        let { answer = "" } = data || {};
        setContent(answer);
      }
      setLoading(false);
    } catch (e) {
      if (e instanceof Error) {
        toast.error(e.message, {
          position: "bottom-right",
          autoClose: 5000,
          hideProgressBar: false,
          closeOnClick: false,
          pauseOnHover: true,
          draggable: true,
          progress: undefined,
          theme: "colored",
          transition: Bounce,
        });
      }
    }
    setLoading(false);
  };
  const submit = async (e: React.FormEvent<HTMLFormElement>) => {
    try {
      e.preventDefault();
      const { success, data } = await AnswerCreate({
        questionId,
        content,
      });
      setContent("");
      if (success && data) {
        toast.success("Answer submitted successfully.", {
          position: "bottom-right",
          autoClose: 5000,
          hideProgressBar: false,
          closeOnClick: false,
          pauseOnHover: true,
          draggable: true,
          progress: undefined,
          theme: "colored",
          transition: Bounce,
        });
        return router.push(ROUTES.QUESTION_DETAILS(questionId));
      }
    } catch (e) {
      if (e instanceof Error) {
        toast.error(e.message, {
          position: "bottom-right",
          autoClose: 5000,
          hideProgressBar: false,
          closeOnClick: false,
          pauseOnHover: true,
          draggable: true,
          progress: undefined,
          theme: "colored",
          transition: Bounce,
        });
      }
    }
  };
  return (
    <form onSubmit={submit}>
      <div className="mt-3">
        <Editor
          label="Any Question ?"
          value={content}
          onChange={(v) => {
            console.log(v);
            setContent(v);
          }}
        />
      </div>
      <div className="flex justify-end">
        <div className="w-[50%] flex space-x-3">
          <div className="w-[50%]">
            {content.length > 10 && (
              <Button
                variant="outline"
                type="button"
                onClick={generateAiAnswer}
              >
                {loading ? "Loading.." : "Generate Ai Answer"}
              </Button>
            )}
          </div>
          <div className="w-[50%]">
            <Button type="submit">Submit Answer</Button>
          </div>
        </div>
      </div>
    </form>
  );
}

export default AnswerForm;
