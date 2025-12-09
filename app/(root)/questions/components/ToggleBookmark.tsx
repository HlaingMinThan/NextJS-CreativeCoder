"use client";

import ToggleBookMarkAction from "@/lib/actions/ToggleBookMarkAction";
import React, { useState } from "react";
import { Bounce, toast } from "react-toastify";

function ToggleBookmark({
  questionId,
  saved,
}: {
  questionId: string;
  saved: boolean;
}) {
  let [isSaved, setIsSaved] = useState(saved);

  const handleSave = async () => {
    try {
      let { success, data, message } = await ToggleBookMarkAction({
        questionId,
      });
      if (success && data) {
        setIsSaved(data.saved);
      } else {
        toast.error(message, {
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
    <div>
      {!isSaved ? (
        <button onClick={handleSave} className="px-3 py-2 rounded-lg bg-main">
          save
        </button>
      ) : (
        <button
          onClick={handleSave}
          className="px-3 py-2 rounded-lg border-[1px] border-main"
        >
          unsave
        </button>
      )}
    </div>
  );
}

export default ToggleBookmark;
