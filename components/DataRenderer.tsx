import React from "react";

function DataRenderer({
  success,
  data,
  errorMessage,
  render,
}: {
  success: Boolean;
  data: any[];
  errorMessage?: string | undefined;
  render: (data: any[]) => React.ReactNode;
}) {
  if (!success) {
    return (
      <div className="flex flex-col items-center justify-center py-12 px-4">
        <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mb-4">
          <svg
            className="w-8 h-8 text-red-600"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"
            />
          </svg>
        </div>
        <h3 className="text-lg font-semibold text-white mb-2">
          Oops! Something went wrong
        </h3>
        <p className="text-gray-600 text-center max-w-md">
          {errorMessage ||
            "We encountered an unexpected error. Please try again later."}
        </p>
        {/* <button
          onClick={() => window.location.reload()}
          className="mt-4 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors duration-200"
        >
          Try Again
        </button> */}
      </div>
    );
  }

  if (!data || !data.length) {
    return (
      <div className="flex flex-col items-center justify-center py-12 px-4">
        <div className="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mb-4">
          <svg
            className="w-8 h-8 text-gray-400"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M9.172 16.172a4 4 0 015.656 0M9 12h6m-6-4h6m2 5.291A7.962 7.962 0 0112 15c-2.34 0-4.29-1.009-5.824-2.709M15 6.291A7.962 7.962 0 0012 5c-2.34 0-4.29 1.009-5.824 2.709"
            />
          </svg>
        </div>
        <h3 className="text-lg font-semibold text-white mb-2">
          No results found
        </h3>
        <p className="text-gray-600 text-center max-w-md">
          We couldn't find any data matching your criteria. Try adjusting your
          search or filters.
        </p>
      </div>
    );
  }
  return <div>{render(data)}</div>;
}

export default DataRenderer;
