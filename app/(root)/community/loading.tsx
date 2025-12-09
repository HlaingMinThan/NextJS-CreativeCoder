function loading() {
  return (
    <>
      {/* Header Skeleton */}
      <div className="flex items-center justify-between p-5">
        <div className="flex justify-between items-center w-full">
          {/* Title Skeleton */}
          <div className="h-9 w-32 bg-tertiary rounded-lg animate-pulse"></div>
          {/* Filter Skeleton */}
          <div className="h-10 w-40 bg-tertiary rounded-lg animate-pulse"></div>
        </div>
      </div>

      {/* Grid Skeleton */}
      <div className="grid grid-cols-4 gap-4">
        {Array.from({ length: 8 }).map((_, index) => (
          <div key={index}>
            {/* Card Container Skeleton */}
            <div className="flex flex-col items-center justify-center bg-tertiary p-2 rounded-xl">
              {/* Image Skeleton */}
              <div className="w-[100px] h-[100px] bg-card rounded-lg animate-pulse"></div>
            </div>
            {/* Name Skeleton */}
            <div className="h-5 w-24 bg-tertiary rounded mx-auto mt-2 animate-pulse"></div>
          </div>
        ))}
      </div>

      {/* Pagination Skeleton */}
      <div className="flex justify-center items-center gap-2 mt-6">
        <div className="h-10 w-10 bg-tertiary rounded-lg animate-pulse"></div>
        <div className="h-10 w-10 bg-tertiary rounded-lg animate-pulse"></div>
        <div className="h-10 w-10 bg-tertiary rounded-lg animate-pulse"></div>
      </div>
    </>
  );
}

export default loading;
