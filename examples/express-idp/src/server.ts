import express from "express";
import { createIdentityProvider } from "@0-auth/zero-auth-idp";

const port = Number(process.env["PORT"] ?? 3001);

const idp = createIdentityProvider({
  issuer: `http://localhost:${port}/auth`,
  clients: [
    {
      clientId: "demo-app",
      name: "Demo app",
      clientType: "public",
      redirectUris: [`http://localhost:${port}/callback`],
      allowedScopes: ["profile"],
    },
  ],
  authenticateUser: ({ email, password }) => {
    if (email !== "user@example.com" || password !== "correct-horse") return null;
    return { id: "user-1", email, name: "Demo user" };
  },
});

const app = express();
app.use("/auth", idp.router());

app.get("/callback", (request, response) => {
  response.json({ receivedCode: Boolean(request.query.code), state: request.query.state ?? null });
});

app.get("/api/session", idp.requireSession(), (request, response) => {
  response.json({ userId: request.idpUser?.id, email: request.idpUser?.email });
});

app.get("/api/profile", idp.authenticateBearer(["profile"]), (request, response) => {
  response.json({ userId: request.oauth?.user.id, scopes: request.oauth?.scopes });
});

if (process.env["NODE_ENV"] !== "test") {
  app.listen(port, () => {
    console.log(`zero-auth-idp example running at http://localhost:${port}`);
    console.log("Login: user@example.com / correct-horse");
  });
}

export { app, idp };
