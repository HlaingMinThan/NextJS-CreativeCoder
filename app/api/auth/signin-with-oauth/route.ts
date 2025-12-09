import mongoose from "mongoose";
import slugify from "slugify";

import Account from "@/database/account.model";
import User from "@/database/user.model";
import dbConnect from "@/lib/dbConnect";
import { handleSuccessResponse } from "@/lib/response";
import SigninWithOauthSchema from "@/lib/schemas/SignInWithOauthSchema";
import validateBody from "@/lib/validateBody";

export async function POST(request: Request) {
  const { provider, providerAccountId, user } = await request.json();
  await dbConnect();
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const validatedData = validateBody(
      {
        provider,
        providerAccountId,
        user,
      },
      SigninWithOauthSchema
    );

    const { email, image, name, username } = validatedData.data.user;
    let existingUser = await User.findOne({
      email,
    }).session(session);
    if (!existingUser) {
      [existingUser] = await User.create(
        [
          {
            email,
            image,
            name,
            username: slugify(username, {
              lower: true,
              strict: true,
              trim: true,
            }),
          },
        ],
        { session }
      );
    } else {
      await User.updateOne(
        {
          _id: existingUser._id,
        },
        {
          $set: {
            image,
            name,
          },
        }
      ).session(session);
    }

    const existingAccount = await Account.findOne({
      userId: existingUser._id,
      provider,
      providerAccountId,
    }).session(session);

    if (!existingAccount) {
      await Account.create(
        [
          {
            userId: existingUser._id,
            provider,
            providerAccountId,
            name,
            image,
          },
        ],
        { session }
      );
    }

    await session.commitTransaction();
    return handleSuccessResponse({
      existingUser,
    });
  } catch (error: unknown) {
    console.log(error);
    session.abortTransaction();
  } finally {
    session.endSession();
  }
}
