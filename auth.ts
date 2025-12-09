import bcrypt from "bcryptjs";
import Credentials from "next-auth/providers/credentials";
import NextAuth from "next-auth";

import validateBody from "./lib/validateBody";
import SignInSchema from "./lib/schemas/SignInSchema";
import dbConnect from "./lib/dbConnect";
import Account from "./database/account.model";
import User from "./database/user.model";
import { authConfig } from "./auth.config";

export const { handlers, signIn, signOut, auth } = NextAuth({
  ...authConfig,
  providers: [
    ...authConfig.providers,
    Credentials({
      async authorize(credentials) {
        let validationFields = validateBody(credentials, SignInSchema);
        if (validationFields.success) {
          await dbConnect();
          const { email, password } = validationFields.data;
          const existingAccount = await Account.findOne({
            providerAccountId: email,
            provider: "credentials",
          });
          if (!existingAccount) return null;

          const existingUser = await User.findById(existingAccount.userId);
          if (!existingUser) return null;

          const isValidPassword = await bcrypt.compare(
            password,
            existingAccount.password
          );
          if (isValidPassword) {
            return {
              id: existingAccount.userId.toString(),
              name: existingUser.name,
              username: existingUser.username,
              email: existingUser.email,
              image: existingUser.image,
            };
          }
        }
        return null;
      },
    }),
  ],
});
