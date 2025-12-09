import User from "@/database/user.model";
import dbConnect from "@/lib/dbConnect";
import { handleErrorResponse, handleSuccessResponse } from "@/lib/response";
import UserSchema from "@/lib/schemas/UserSchema";
import validateBody from "@/lib/validateBody";

// get all users
export async function GET() {
  try {
    await dbConnect();
    const users = await User.find();
    return handleSuccessResponse(users);
  } catch (e: unknown) {
    return handleErrorResponse(e);
  }
}

// create a user or register user
export async function POST(request: Request) {
  try {
    await dbConnect();
    const body = await request.json();
    validateBody(body, UserSchema);
    const existingEmail = await User.findOne({ email: body.email });
    if (existingEmail) throw new Error("Email already exists");

    const existingUsername = await User.findOne({ username: body.username });
    if (existingUsername) throw new Error("Username already exists");

    const newUser = await User.create(body);

    return handleSuccessResponse(newUser, 201);
  } catch (e: unknown) {
    return handleErrorResponse(e);
  }
}
