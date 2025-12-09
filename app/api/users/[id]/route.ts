import { Types } from "mongoose";

import User from "@/database/user.model";
import { handleErrorResponse, handleSuccessResponse } from "@/lib/response";
import UserSchema from "@/lib/schemas/UserSchema";
import validateBody from "@/lib/validateBody";

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    if (!Types.ObjectId.isValid(id)) {
      throw new Error("Invalid user id");
    }
    const user = await User.findById(id);
    if (!user) {
      throw new Error("User not found");
    }
    return handleSuccessResponse(user);
  } catch (e) {
    return handleErrorResponse(e);
  }
}

// DELETE API
export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    if (!Types.ObjectId.isValid(id)) {
      throw new Error("Invalid user id");
    }
    const user = await User.findByIdAndDelete(id);
    if (!user) {
      throw new Error("User not found");
    }
    return handleSuccessResponse(user);
  } catch (e) {
    return handleErrorResponse(e);
  }
}

// PUT API
export async function PUT(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const body = await request.json();
    if (!Types.ObjectId.isValid(id)) {
      throw new Error("Invalid user id");
    }

    const validatedData = validateBody(body, UserSchema,true);
    const user = await User.findByIdAndUpdate(id, validatedData.data, {
      new: true,
    });
    if (!user) {
      throw new Error("User not found");
    }
    return handleSuccessResponse(user);
  } catch (e) {
    return handleErrorResponse(e);
  }
}
