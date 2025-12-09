import { unstable_cache } from "next/cache";
import { actionError } from "../response";

interface TechNewsArticle {
  id: number;
  title: string;
  description: string;
  url: string;
  cover_image?: string;
  social_image?: string;
  user: {
    name: string;
    username: string;
    profile_image_90?: string;
  };
  published_at: string;
  readable_publish_date: string;
  public_reactions_count: number;
  comments_count: number;
  reading_time_minutes: number;
  tag_list: string[];
}

const GetTechNews = unstable_cache(
  async (): Promise<{
    success: boolean;
    data?: {
      articles: TechNewsArticle[];
    };
    message?: string;
    details?: object | null;
  }> => {
    try {
      console.log("hit ");
      // Construct the API URL - use localhost for development, or get from env
      const baseUrl =
        process.env.NEXT_PUBLIC_APP_URL || process.env.VERCEL_URL
          ? `https://${process.env.VERCEL_URL}`
          : "http://localhost:3000";

      const response = await fetch(`${baseUrl}/api/tech-news`, {
        cache: "no-store", // auto no cache
      });

      if (!response.ok) {
        throw new Error("Failed to fetch tech news");
      }

      const data = await response.json();

      if (data.success) {
        return {
          success: true,
          data: {
            articles: data.data || [],
          },
        };
      } else {
        return {
          success: false,
          message: data.message || "Failed to load tech news",
        };
      }
    } catch (e) {
      return actionError(e);
    }
  },
  ["users"],
  {
    revalidate: 100,
  }
);

export default GetTechNews;
