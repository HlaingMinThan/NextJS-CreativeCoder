import Image from "next/image";
import React from "react";
import { AiFillLike } from "react-icons/ai";
import { IoMdEye } from "react-icons/io";
import { MdQuestionAnswer } from "react-icons/md";

import profile from "@/public/profile.jpg";

import TagCard from "./TagCard";
import { IQuestionDoc } from "@/database/question.model";
import Link from "next/link";
import ROUTES from "@/routes";
import Actions from "./Actions";

function ThreadCard({
  question,
  showActions = false,
}: {
  question: IQuestionDoc;
  showActions?: boolean;
}) {
  return (
    <div className="space-y-7 rounded-xl bg-card px-10 py-5 my-3">
      <Link
        href={ROUTES.QUESTION_DETAILS(question._id as string)}
        className="hover:text-main"
      >
        <h1 className="text-xl font-bold">{question.title}</h1>
      </Link>
      <div className="space-x-3">
        {question.tags?.map((tag, i) => (
          <TagCard href={`/filters/${tag?.name}`} key={i}>
            {tag.name}
          </TagCard>
        ))}
      </div>
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3 text-[14px] text-gray-300">
          <Image
            src={profile}
            width={30}
            height={30}
            className="aspect-square rounded-full object-cover"
            alt="logo"
          />
          <span>{question.author?.name} . asked 3 minutes ago</span>
        </div>
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-1 text-[14px] text-gray-300">
            <span>
              <AiFillLike />
            </span>
            <span>{question.upvotes} Likes</span>
          </div>
          <div className="flex items-center space-x-1 text-[14px] text-gray-300">
            <span>
              <MdQuestionAnswer />
            </span>
            <span>{question.answers} Answers</span>
          </div>
          <div className="flex items-center space-x-1 text-[14px] text-gray-300">
            <span>
              <IoMdEye />
            </span>
            <span>{question.views} Views</span>
          </div>
          <Actions
            type="question"
            typeId={question._id as string}
            showActions={showActions}
          />
        </div>
      </div>
    </div>
  );
}

export default ThreadCard;
