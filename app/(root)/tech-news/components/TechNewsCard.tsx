import Image from "next/image";
import React from "react";
import { AiFillLike } from "react-icons/ai";
import { FaClock, FaComment } from "react-icons/fa";

interface TechNewsCardProps {
  article: {
    id: number;
    title: string;
    description: string;
    url: string;
    cover_image?: string;
    social_image?: string;
    user: {
      name: string;
      username: string;
      profile_image_90?: string;
    };
    published_at: string;
    readable_publish_date: string;
    public_reactions_count: number;
    comments_count: number;
    reading_time_minutes: number;
    tag_list: string[];
  };
}

function TechNewsCard({ article }: TechNewsCardProps) {
  const imageUrl = article.cover_image || article.social_image;
  const profileImage = article.user?.profile_image_90 || "/profile.jpg";

  return (
    <div className="space-y-4 rounded-xl bg-card px-10 py-5 my-3">
      <a
        href={article.url}
        target="_blank"
        rel="noopener noreferrer"
        className="hover:text-main"
      >
        <h1 className="text-xl font-bold">{article.title}</h1>
      </a>

      {article.description && (
        <p className="text-gray-300 line-clamp-2">{article.description}</p>
      )}

      {imageUrl && (
        <div className="relative w-full h-64 rounded-lg overflow-hidden">
          <Image
            src={imageUrl}
            alt={article.title}
            fill
            className="object-cover"
            sizes="(max-width: 768px) 100vw, (max-width: 1200px) 50vw, 33vw"
          />
        </div>
      )}

      {article.tag_list && article.tag_list.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {article.tag_list.slice(0, 5).map((tag, i) => (
            <span
              key={i}
              className="px-3 py-1 text-xs rounded-full bg-primary text-gray-300"
            >
              #{tag}
            </span>
          ))}
        </div>
      )}

      <div className="flex items-center justify-between pt-2 border-t border-gray-700">
        <div className="flex items-center space-x-3 text-[14px] text-gray-300">
          <Image
            src={profileImage}
            width={30}
            height={30}
            className="aspect-square rounded-full object-cover"
            alt={article.user?.name || "Author"}
          />
          <span>
            {article.user?.name || article.user?.username} •{" "}
            {article.readable_publish_date}
          </span>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-1 text-[14px] text-gray-300">
            <AiFillLike />
            <span>{article.public_reactions_count}</span>
          </div>
          <div className="flex items-center space-x-1 text-[14px] text-gray-300">
            <FaComment />
            <span>{article.comments_count}</span>
          </div>
          <div className="flex items-center space-x-1 text-[14px] text-gray-300">
            <FaClock />
            <span>{article.reading_time_minutes} min read</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default TechNewsCard;
