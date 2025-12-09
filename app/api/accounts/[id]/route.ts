import { Types } from "mongoose";

import Account from "@/database/account.model";
import { handleErrorResponse, handleSuccessResponse } from "@/lib/response";
import AccountSchema from "@/lib/schemas/AccountSchema";
import validateBody from "@/lib/validateBody";

export async function GET(
  _: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    if (!Types.ObjectId.isValid(id)) {
      throw new Error("Invalid account id");
    }
    const account = await Account.findById(id);
    if (!account) {
      throw new Error("Account not found");
    }
    return handleSuccessResponse(account);
  } catch (e) {
    return handleErrorResponse(e);
  }
}

export async function DELETE(
  _: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    if (!Types.ObjectId.isValid(id)) {
      throw new Error("Invalid account id");
    }
    const account = await Account.findByIdAndDelete(id);
    if (!account) {
      throw new Error("Account not found");
    }
    return handleSuccessResponse(account);
  } catch (e) {
    return handleErrorResponse(e);
  }
}

export async function PUT(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const body = await request.json();
    if (!Types.ObjectId.isValid(id)) {
      throw new Error("Invalid account id");
    }

    const validatedData = validateBody(body, AccountSchema, true);
    const account = await Account.findByIdAndUpdate(id, validatedData.data, {
      new: true,
    });
    if (!account) {
      throw new Error("Account not found");
    }
    return handleSuccessResponse(account);
  } catch (e) {
    return handleErrorResponse(e);
  }
}
