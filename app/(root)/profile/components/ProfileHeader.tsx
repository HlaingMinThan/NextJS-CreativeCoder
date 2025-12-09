import React from "react";
import Button from "@/components/Button";
import GetUser from "@/lib/actions/GetUser";

//HLinag min than -> H
function getInitials(name?: string) {
  if (!name) return "U";
  const parts = name.trim().split(" ").filter(Boolean);
  const first = parts[0]?.[0] ?? "";
  const last = parts.length > 1 ? parts[parts.length - 1][0] : "";
  return (first + last).toUpperCase() || "U";
}

const ProfileHeader = async ({ userId }: { userId: string }) => {
  const result = await GetUser({ userId });
  if (!result.success || !result.data) {
    return (
      <div className="mx-auto max-w-5xl px-4 py-10 text-zinc-700 dark:text-zinc-300">
        Failed to load user.
      </div>
    );
  }

  const { user, totalQuestions, totalAnswers } = result.data;
  const { name, username, bio, image, location, portfolio, reputation } = user;

  return (
    <section className="w-full rounded-xl border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-primary">
      <div className="flex flex-col items-start gap-6 sm:flex-row sm:items-center">
        <div className="relative h-24 w-24 shrink-0 overflow-hidden rounded-full bg-zinc-200 dark:bg-zinc-800">
          {image ? (
            // Using img to avoid external domain config issues
            <img
              src={image}
              alt={name || username}
              className="h-full w-full object-cover"
            />
          ) : (
            <div className="flex h-full w-full items-center justify-center text-xl font-semibold text-zinc-600 dark:text-zinc-300">
              {getInitials(name || username)}
            </div>
          )}
        </div>

        <div className="flex min-w-0 flex-1 flex-col gap-2">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="truncate text-2xl font-semibold text-zinc-900 dark:text-zinc-100">
              {name || username}
            </h1>
            <span className="rounded-full bg-zinc-100 px-3 py-1 text-sm text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
              @{username}
            </span>
            <span className="rounded-full bg-amber-100 px-3 py-1 text-sm font-medium text-amber-800 dark:bg-amber-900/40 dark:text-amber-300">
              {typeof reputation === "number" ? reputation : 0} rep
            </span>
          </div>

          {bio ? (
            <p className="max-w-prose text-sm text-zinc-700 dark:text-zinc-300">
              {bio}
            </p>
          ) : (
            <p className="text-sm text-zinc-500 dark:text-zinc-400">
              No bio provided.
            </p>
          )}

          <div className="mt-2 flex flex-wrap items-center gap-4 text-sm">
            {location ? (
              <div className="inline-flex items-center gap-2 text-zinc-600 dark:text-zinc-300">
                <span className="inline-block h-2 w-2 rounded-full bg-emerald-500" />
                <span>{location}</span>
              </div>
            ) : null}

            {portfolio ? (
              <a
                href={
                  /^https?:\/\//.test(portfolio)
                    ? portfolio
                    : `https://${portfolio}`
                }
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-600 underline-offset-2 hover:underline dark:text-blue-400"
              >
                Portfolio
              </a>
            ) : null}
          </div>
        </div>

        <div className="w-full sm:w-auto">
          <Button variant="normal">Edit Profile</Button>
        </div>
      </div>

      <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-3">
        <div className="rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
          <div className="text-xs uppercase text-zinc-500 dark:text-zinc-400">
            Questions
          </div>
          <div className="mt-1 text-2xl font-semibold text-zinc-900 dark:text-zinc-100">
            {totalQuestions}
          </div>
        </div>
        <div className="rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
          <div className="text-xs uppercase text-zinc-500 dark:text-zinc-400">
            Answers
          </div>
          <div className="mt-1 text-2xl font-semibold text-zinc-900 dark:text-zinc-100">
            {totalAnswers}
          </div>
        </div>
        <div className="rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
          <div className="text-xs uppercase text-zinc-500 dark:text-zinc-400">
            Reputation
          </div>
          <div className="mt-1 text-2xl font-semibold text-zinc-900 dark:text-zinc-100">
            {typeof user.reputation === "number" ? user.reputation : 0}
          </div>
        </div>
      </div>
    </section>
  );
};

export default ProfileHeader;
