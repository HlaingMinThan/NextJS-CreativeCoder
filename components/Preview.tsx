import React from "react";
import { MDXRemote } from "next-mdx-remote/rsc";
import { Code } from "bright";
Code.theme = {
  light: "github-light",
  dark: "github-dark",
  lightSelector: "html.light",
};

function Preview({ content }: { content: string }) {
  return (
    <div className="prose prose-invert prose-headings:text-gray-200 prose-p:text-gray-400 prose-ul:text-gray-400 prose-ol:text-gray-400 max-w-none">
      <MDXRemote
        source={content}
        components={{
          pre: (props) => {
            return <Code {...props} lineNumbers className="shadow-light-200" />;
          },
        }}
      ></MDXRemote>
    </div>
  );
}

export default Preview;
