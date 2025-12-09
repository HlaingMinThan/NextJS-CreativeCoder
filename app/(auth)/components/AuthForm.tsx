"use client";
import { signIn } from "next-auth/react";
import React from "react";
import { Bounce, toast } from "react-toastify";

import Button from "@/components/Button";
import github from "@/public/github.png";
import google from "@/public/google.webp";
import ROUTES from "@/routes";

function AuthForm() {
  const oauthSignIn = async (type: "google" | "github") => {
    try {
      await signIn(type, {
        redirectTo: ROUTES.HOME,
      });
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
    <div className="flex space-x-3">
      <Button
        variant="outline"
        icon={google}
        onClick={() => oauthSignIn("google")}
      >
        Login with Google
      </Button>

      <Button
        variant="outline"
        icon={github}
        onClick={() => oauthSignIn("github")}
      >
        Login with Github
      </Button>
    </div>
  );
}

export default AuthForm;
