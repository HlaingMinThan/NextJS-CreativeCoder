"use client";

import React, { useState } from "react";

import Button from "@/components/Button";
import Editor from "@/components/Editor";
import Input from "@/components/Input";
import RemovableTagCard from "@/components/RemovableTagCard";
import { toast, Bounce } from "react-toastify";
import { QuestionCreate } from "@/lib/actions/QuestionCreate.action";
import { useRouter } from "next/navigation";
import ROUTES from "@/routes";
import { IQuestion } from "@/database/question.model";
import { QuestionEdit } from "@/lib/actions/QuestionEdit.action";

function QuestionForm({
  question,
  isEdit = false,
}: {
  question: IQuestion;
  isEdit: boolean;
}) {
  const [title, setTitle] = useState(question?.title ?? "");
  const [content, setContent] = useState(question?.content ?? "");
  const [tags, setTags] = useState<string[]>(
    question?.tags.map((tag) => tag.name) ?? []
  );
  const [error, setError] = useState("");
  const [newTag, setNewTag] = useState("");

  const handleEnterPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      if (!tags.includes(newTag)) {
        setTags([...tags, newTag]);
        setNewTag("");
        setError("");
      } else {
        setError("you are adding an existing tag");
      }
    }
  };

  let router = useRouter();

  let submit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    try {
      if (isEdit && question) {
        let result = await QuestionEdit({
          questionId: question._id as string,
          title,
          content,
          tags,
        });
        if (result.success && result.data) {
          toast.success("Question Updated successfully.", {
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
          return router.push(ROUTES.QUESTION_DETAILS(result.data?._id));
        }
        return;
      }
      let result = await QuestionCreate({
        title,
        content,
        tags,
      });
      if (result.success && result.data) {
        toast.success("Question created successfully.", {
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
        return router.push(ROUTES.QUESTION_DETAILS(result.data?._id));
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
  let removeTag = (tag: string) => {
    setTags((prevTags) => {
      return prevTags.filter((eachTag) => eachTag != tag);
    });
  };
  return (
    <form className="space-y-5" onSubmit={submit}>
      <h1 className="text-2xl font-bold">Ask A New Question?</h1>
      <Input
        label="Title"
        value={title}
        onChange={(e) => setTitle(e.target.value)}
        text="Describe your question title in short way."
      />
      <div className="mt-3">
        <Editor
          label="Any Question ?"
          value={content}
          onChange={(v) => setContent(v)}
        />
      </div>
      <Input
        onKeyDown={handleEnterPress}
        value={newTag}
        onChange={(e) => setNewTag(e.target.value)}
        label="Tags"
        text="Please press enter to add a new tag."
      />
      {error && <p className="text-sm text-red-600">{error}</p>}
      <div className="mt-5 space-x-3 flex">
        {tags?.map((tag, i) => (
          <RemovableTagCard key={tag} onRemove={() => removeTag(tag)}>
            {tag}
          </RemovableTagCard>
        ))}
      </div>
      <Button type="submit">{isEdit ? "Update" : "Create"}</Button>
    </form>
  );
}

export default QuestionForm;
