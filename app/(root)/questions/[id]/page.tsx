import Preview from "@/components/Preview";
import TagCard from "@/components/TagCard";
import Pagination from "@/components/Pagination";
import { GetQuestion } from "@/lib/actions/GetQuestion.action";
import { incrementViews } from "@/lib/actions/incrementViews.action";
import { notFound } from "next/navigation";
import { after } from "next/server";
import AnswerForm from "../components/AnswerForm";
import GetAnswers from "@/lib/actions/GetAnswers";
import AnswerList from "../components/AnswerList";
import VoteButtons from "@/components/VoteButtons";
import ToggleBookmark from "../components/ToggleBookmark";
import { DefaultFilters } from "@/constant/filters";
import { Suspense } from "react";
import GetUserVote from "@/lib/actions/GetUserVote";
import { Metadata } from "next";

type Props = {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
};

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { id } = await params;
  let { data: question } = await GetQuestion(id);

  return {
    title: question?.title,
    description: question?.content.slice(0, 100),
  };
}

export default async function page({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{
    [key: string]: string;
  }>;
}) {
  const { id } = await params;
  const { page = 1, pageSize = 10, filter = "" } = await searchParams;
  let { data: question } = await GetQuestion(id);

  after(async () => {
    await incrementViews({
      questionId: id,
    });
  });

  // const question = {
  //   id: "q123",
  //   title: "How to improve React app performance?",
  //   content: `### Question

  // I'm looking for tips and best practices to enhance the performance of a React application. I have a moderately complex app with multiple components, and I've noticed some performance bottlenecks. What should I focus on?

  // #### What I've Tried:
  // - Lazy loading components
  // - Using React.memo on some components
  // - Managing state with React Context API

  // #### Issues:
  // - The app still lags when rendering large lists.
  // - Switching between pages feels sluggish.
  // - Sometimes, re-renders happen unexpectedly.

  // #### Key Areas I Need Help With:
  // 1. Efficiently handling large datasets.
  // 2. Reducing unnecessary re-renders.
  // 3. Optimizing state management.

  // Here is a snippet of my code that renders a large list. Maybe I'm doing something wrong here:

  // \`\`\`js
  // import React, { useState, useMemo } from "react";

  // const LargeList = ({ items }) => {
  //   const [filter, setFilter] = useState("");

  //   // Filtering items dynamically
  //   const filteredItems = useMemo(() => {
  //     return items.filter((item) => item.includes(filter));
  //   }, [items, filter]);

  //   return (
  //     <div>
  //       <input
  //         type="text"
  //         value={filter}
  //         onChange={(e) => setFilter(e.target.value)}
  //         placeholder="Filter items"
  //       />
  //       <ul>
  //         {filteredItems.map((item, index) => (
  //           <li key={index}>{item}</li>
  //         ))}
  //       </ul>
  //     </div>
  //   );
  // };

  // export default LargeList;
  // \`\`\`

  // #### Questions:
  // 1. Is using \`useMemo\` the right approach here, or is there a better alternative?
  // 2. Should I implement virtualization for the list? If yes, which library would you recommend?
  // 3. Are there better ways to optimize state changes when dealing with user input and dynamic data?

  // Looking forward to your suggestions and examples!

  // **Tags:** React, Performance, State Management
  //   `,
  //   createdAt: "2025-01-15T12:34:56.789Z",
  //   upvotes: 42,
  //   downvotes: 3,
  //   views: 1234,
  //   answers: 5,
  //   tags: [
  //     { _id: "tag1", name: "React" },
  //     { _id: "tag2", name: "Node" },
  //     { _id: "tag3", name: "PostgreSQL" },
  //   ],
  //   author: {
  //     _id: "u456",
  //     name: "Jane Doe",
  //     image: "/avatars/jane-doe.png",
  //   },
  // };

  if (!question) notFound();

  return (
    <div className="p-3">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">{question.title}</h1>
        <div className="flex justify-center items-center gap-3 text-xs text-gray-200">
          <Suspense fallback={<div>loading...</div>}>
            <VoteButtons
              GetUserVotePromise={GetUserVote({
                type: "question",
                typeId: id,
              })}
              type="question"
              typeId={id.toString()}
              initialUpvotes={question.upvotes}
              initialDownvotes={question.downvotes}
            />
          </Suspense>
          <div>{question.answers} Answers</div>
          <div>{question.views} Views</div>
          <div>
            <ToggleBookmark questionId={id} saved={question?.saved} />
          </div>
        </div>
      </div>
      <div className="my-3">
        <Preview content={question.content} />
      </div>
      <div className="mt-8 flex flex-wrap gap-2">
        {question.tags.map((tag) => (
          <TagCard href={`/tags/${tag._id}`} key={tag._id.toString()}>
            {" "}
            {tag.name}
          </TagCard>
        ))}
      </div>
      <div className="my-3">
        <Suspense fallback={<div>loading...</div>}>
          <AnswerList
            page={page as number}
            pageSize={pageSize as number}
            filter={filter}
            id={id}
          />
        </Suspense>
      </div>
      <div className="my-3">
        <AnswerForm
          questionId={id}
          questionTitle={question.title}
          questionContent={question.content}
        />
      </div>
    </div>
  );
}
