import Account from "@/database/account.model";
import { handleErrorResponse, handleSuccessResponse } from "@/lib/response";
import dbConnect from "@/lib/dbConnect";

// /api/accounts/provider
export async function POST(request: Request) {
  try {
    await dbConnect();
    const { providerAccountId } = await request.json();
    const account = await Account.findOne({ providerAccountId });
    if (!account) {
      throw new Error("Account not found");
    }
    return handleSuccessResponse(account);
  } catch (e) {
    return handleErrorResponse(e);
  }
}
