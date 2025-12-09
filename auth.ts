import bcrypt from "bcryptjs";
import Credentials from "next-auth/providers/credentials";
import NextAuth from "next-auth";
import GitHub from "next-auth/providers/github";
import Google from "next-auth/providers/google";

import { api } from "./lib/api";
import validateBody from "./lib/validateBody";
import SignInSchema from "./lib/schemas/SignInSchema";

export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    GitHub,
    Google,
    Credentials({
      async authorize(credentials) {
        let validationFields = validateBody(credentials, SignInSchema);
        if (validationFields.success) {
          const { email, password } = validationFields.data;
          const { data: existingAccount } = await api.accounts.getByProvider(
            email
          );
          if (!existingAccount) return null;

          const { data: existingUser } = await api.users.getById(
            existingAccount.userId.toString()
          );
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
  callbacks: {
    async signIn({ user, profile, account }) {
      if (account?.type === "credentials") return true;
      if (!account || !user) return false;

      const { success } = await api.auth.oauthSignIn({
        user: {
          email: user.email || "",
          name: user.name || "",
          image: user.image || "",
          username:
            account.provider === "github"
              ? (profile?.login as string)
              : (user?.name?.toLocaleLowerCase() as string),
        },
        provider: account.provider,
        providerAccountId: account.providerAccountId,
      });
      return success;
    },
    async jwt({ token, account, user }) {
      if (account) {
        // Handle OAuth providers
        const { success, data: accountData } = await api.accounts.getByProvider(
          account?.providerAccountId
        );

        if (!success || !accountData) return token;

        const userId = accountData?.userId;

        if (userId) token.sub = userId.toString();
      } else if (user?.id) {
        // Handle credentials provider - user.id comes from authorize function
        token.sub = user.id;
      }
      return token;
    },
    async session({ session, token }) {
      session.user.id = token.sub as string;
      return session;
    },
  },
});
