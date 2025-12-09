import { handleErrorResponse, handleSuccessResponse } from "@/lib/response";

// Fisher-Yates shuffle algorithm
function shuffleArray<T>(array: T[]): T[] {
  const shuffled = [...array];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
}

export async function GET() {
  try {
    // Fetch articles from dev.to API
    const response = await fetch("https://dev.to/api/articles?per_page=10", {
      next: { revalidate: 3600 }, // Revalidate every hour
    });

    if (!response.ok) {
      throw new Error("Failed to fetch tech news");
    }

    const articles = await response.json();

    // Shuffle the articles array
    const shuffledArticles = shuffleArray(articles);
    // Delay response by 2 seconds
    await new Promise((resolve) => setTimeout(resolve, 2000));
    console.log("result in tech news api");
    console.log(shuffleArray);
    return handleSuccessResponse(shuffledArticles);
  } catch (e: unknown) {
    console.log(e, "error in tech news api");
    return handleErrorResponse(e);
  }
}
