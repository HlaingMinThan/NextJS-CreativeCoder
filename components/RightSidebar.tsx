import GetPopularQuestions from "@/lib/actions/GetPopularQuestions";
import GetPopularTags from "@/lib/actions/GetPopularTags";
import GetTechNews from "@/lib/actions/GetTechNews";
import React from "react";
import { AiFillQuestionCircle } from "react-icons/ai";
import {
  FaReact,
  FaVuejs,
  FaLaravel,
  FaPython,
  FaNodeJs,
} from "react-icons/fa";
import DataRenderer from "./DataRenderer";
import Link from "next/link";
import ROUTES from "@/routes";
import Image from "next/image";

async function RightSidebar() {
  let { success, data, message } = await GetPopularQuestions();
  let { questions = [] } = data || {};
  let {
    success: successTags,
    data: dataTags,
    message: errorTag,
  } = await GetPopularTags();
  let { tags = [] } = dataTags || {};
  let {
    success: successTechNews,
    data: dataTechNews,
    message: errorTechNews,
  } = await GetTechNews();
  let { articles = [] } = dataTechNews || {};
  // Get first 10 articles
  const techNewsTitles = articles.slice(0, 10);

  return (
    <div className="p-5">
      <div>
        <h1 className="text-xl font-bold">Popular Questions</h1>
        <div className="mt-5 space-y-5 pl-3">
          <DataRenderer
            success={success}
            data={questions}
            errorMessage={message}
            render={(questions) =>
              questions.map((question) => (
                <Link
                  key={question._id}
                  href={ROUTES.QUESTION_DETAILS(question._id)}
                  className="my-3 flex items-center space-x-2"
                >
                  <span className="text-xl text-main">
                    <AiFillQuestionCircle />
                  </span>
                  <span className="line-clamp-2 text-sm">{question.title}</span>
                </Link>
              ))
            }
          />
        </div>
      </div>
      <div className="mt-5">
        <h1 className="text-xl font-bold">Popular Tags</h1>
        <DataRenderer
          success={successTags}
          data={tags}
          errorMessage={errorTag}
          render={(tags) =>
            tags.map((tag) => (
              <Link
                href={ROUTES.TAG_DETAILS(tag._id)}
                className="mt-7 space-y-5 pl-3"
                key={tag._id}
              >
                <div className="flex items-center space-x-2">
                  <span className="text-xl" style={{ color: "#61DAFB" }}>
                    <Image
                      alt="logo"
                      width={30}
                      height={30}
                      src={`https://cdn.jsdelivr.net/gh/devicons/devicon@latest/icons/${tag.name.toLocaleLowerCase()}/${tag.name.toLocaleLowerCase()}-original.svg`}
                    ></Image>
                  </span>
                  <span className="line-clamp-2 text-[16px]">{tag.name}</span>
                </div>
              </Link>
            ))
          }
        />
      </div>
      <div className="mt-5">
        <h1 className="text-xl font-bold">Tech News</h1>
        <div className="mt-5 space-y-3 pl-3">
          <DataRenderer
            success={successTechNews}
            data={techNewsTitles}
            errorMessage={errorTechNews}
            render={(articles) =>
              articles.map((article: any) => (
                <a
                  key={article.id}
                  href={article.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block line-clamp-1 text-sm hover:text-main transition-colors my-3 underline "
                >
                  {article.title}
                </a>
              ))
            }
          />
        </div>
      </div>
    </div>
  );
}

export default RightSidebar;
