"use client";

import React from "react";
import { FaEdit, FaTrash } from "react-icons/fa";
import Link from "next/link";
import ROUTES from "@/routes";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import deleteQuestion from "@/lib/actions/deleteQuestion";
import { Bounce, toast } from "react-toastify";
import deleteAnswer from "@/lib/actions/deleteAnswer";
import { success } from "zod/v4";
interface ActionsProps {
  type: "question" | "answer";
  typeId: string;
  showActions: boolean;
}

function Actions({ type, typeId, showActions }: ActionsProps) {
  if (!showActions) {
    return null;
  }

  const deleteAction = async () => {
    let successValue;
    try {
      if (type === "question") {
        let { success } = await deleteQuestion({
          questionId: typeId,
        });
        successValue = success;
      } else {
        let { success } = await deleteAnswer({
          answerId: typeId,
        });
        successValue = success;
      }

      if (successValue) {
        toast.success("Deleted successfully.", {
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
    <div className="flex items-center gap-2">
      {type === "question" && (
        <Link
          href={ROUTES.QUESTION_DETAILS(typeId) + "/edit"}
          className="flex items-center gap-1 text-sm text-gray-400 hover:text-main transition-colors"
        >
          <FaEdit className="w-4 h-4" />
          <span>Edit</span>
        </Link>
      )}

      <AlertDialog>
        <AlertDialogTrigger className="flex space-x-2 items-center text-sm">
          <FaTrash className="w-3 h-3" />
          <span>Delete</span>
        </AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you absolutely sure?</AlertDialogTitle>
            <AlertDialogDescription>
              This action cannot be undone. This will permanently delete your
              account and remove your data from our servers.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={deleteAction}
              className="bg-red-500 text-white"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

export default Actions;
