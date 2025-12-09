import React, { ReactNode } from "react";

import LeftSidebar from "@/components/LeftSidebar";
import Navbar from "@/components/Navbar";
import RightSidebar from "@/components/RightSidebar";
import { Metadata } from "next";

export const metadata: Metadata = {
  title: "Creative Coder Forum",
  description: "A forum for developers",
};

function layout({ children }: { children: ReactNode }) {
  return (
    <>
      <Navbar />
      <div className="flex">
        <LeftSidebar />
        <div className="w-3/5">{children}</div>
        <div className="w-1/5">
          <RightSidebar />
        </div>
      </div>
    </>
  );
}

export default layout;
