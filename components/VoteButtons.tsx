"use client";

import GetUserVote from "@/lib/actions/GetUserVote";
import VoteAction from "@/lib/actions/VoteAction";
import React, { use, useEffect, useState } from "react";
import { Bounce, toast } from "react-toastify";

function VoteButtons({
  GetUserVotePromise,
  typeId,
  type,
  initialUpvotes,
  initialDownvotes,
}: {
  GetUserVotePromise: Promise<{
    success: boolean;
    data?: {
      userVote: "upvote" | "downvote" | null;
    };
  }>;
  typeId: string;
  type: "question" | "answer";
  initialUpvotes: number;
  initialDownvotes: number;
}) {
  let { success, data } = use(GetUserVotePromise);
  let [upvotes, setUpvotes] = useState(initialUpvotes);
  let [downvotes, setDownvotes] = useState(initialDownvotes);
  let [userVote, setUserVote] = useState<"upvote" | "downvote" | null>(
    success ? data?.userVote ?? null : null
  );

  let handleVote = async (voteType: "upvote" | "downvote") => {
    try {
      let { success, data, message } = await VoteAction({
        type,
        typeId,
        voteType,
      });
      if (success) {
        let { upvotes = 0, downvotes = 0, userVote } = data || {};
        setUpvotes(upvotes);
        setDownvotes(downvotes);
        setUserVote(userVote ?? null);
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
    <div className="flex items-center space-x-2 text-xs">
      <div>
        <button
          onClick={() => handleVote("upvote")}
          className={`p-2 border-[1px] border-white space-x-2 rounded-lg ${
            userVote === "upvote" ? "border-green-300 text-green-300" : ""
          }`}
        >
          <span>{upvotes}</span>
          <span>Likes</span>
        </button>
      </div>
      <div>
        <button
          onClick={() => handleVote("downvote")}
          className={`p-2 border-[1px] border-white space-x-2 rounded-lg ${
            userVote === "downvote" ? "border-red-300 text-red-300" : ""
          }`}
        >
          <span>{downvotes}</span>
          <span>Dislikes</span>
        </button>
      </div>
    </div>
  );
}

export default VoteButtons;
