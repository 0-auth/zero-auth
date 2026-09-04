import http from "node:http";

process.env["NODE_ENV"] = "test";
const { app } = await import("./src/server.js");

async function runTests() {
  const server = http.createServer(app);

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve());
  });

  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Could not get server port");
  const baseUrl = `http://127.0.0.1:${address.port}`;
  console.log(`🚀 Test server listening on ${baseUrl}`);

  try {
    console.log("\n--- 1. Testing Register ---");
    const regRes = await fetch(`${baseUrl}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "testuser@example.com",
        password: "secretpassword",
        role: "user",
      }),
    });
    const regData = (await regRes.json()) as any;
    console.log("Register status:", regRes.status);
    console.log("Register token pair received:", !!regData.accessToken, !!regData.refreshToken);
    if (regRes.status !== 201 || !regData.accessToken || !regData.refreshToken) {
      throw new Error("Register failed");
    }

    console.log("\n--- 2. Testing Login (Admin) ---");
    const loginRes = await fetch(`${baseUrl}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "admin@example.com",
        password: "admin123",
      }),
    });
    const loginData = (await loginRes.json()) as any;
    console.log("Login status:", loginRes.status);
    console.log("Login token pair received:", !!loginData.accessToken, !!loginData.refreshToken);
    const adminToken = loginData.accessToken;
    const adminRefresh = loginData.refreshToken;

    console.log("\n--- 3. Testing Protected Profile (with Bearer Token) ---");
    const profileRes = await fetch(`${baseUrl}/profile`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    const profileData = (await profileRes.json()) as any;
    console.log("Profile status:", profileRes.status);
    console.log("Profile user:", profileData.user);
    if (profileRes.status !== 200 || profileData.user.id !== "1") throw new Error("Profile failed");

    console.log("\n--- 4. Testing Protected Profile without Token (401 expected) ---");
    const noAuthRes = await fetch(`${baseUrl}/profile`);
    const noAuthData = (await noAuthRes.json()) as any;
    console.log("No-auth status:", noAuthRes.status, noAuthData);
    if (noAuthRes.status !== 401 || noAuthData.error.code !== "AUTH_TOKEN_MISSING") {
      throw new Error("No-auth check failed");
    }

    console.log("\n--- 5. Testing Optional Auth (Guest) ---");
    const guestPostsRes = await fetch(`${baseUrl}/posts`);
    const guestPosts = (await guestPostsRes.json()) as any;
    console.log("Guest posts message:", guestPosts.message, "count:", guestPosts.posts.length);

    console.log("\n--- 6. Testing Optional Auth (Authenticated) ---");
    const userPostsRes = await fetch(`${baseUrl}/posts`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    const userPosts = (await userPostsRes.json()) as any;
    console.log("Auth posts message:", userPosts.message, "count:", userPosts.posts.length);

    console.log("\n--- 7. Testing Refresh Token ---");
    const refreshRes = await fetch(`${baseUrl}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken: adminRefresh }),
    });
    const refreshData = (await refreshRes.json()) as any;
    console.log("Refresh status:", refreshRes.status);
    console.log("New access token generated:", !!refreshData.accessToken);
    if (!refreshData.accessToken) throw new Error("Refresh failed");

    console.log("\n--- 8. Testing RBAC (Admin-only route with user vs admin) ---");
    // User attempt (forbidden)
    const userToken = regData.accessToken;
    const forbidRes = await fetch(`${baseUrl}/admin/users/1`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${userToken}` },
    });
    const forbidData = (await forbidRes.json()) as any;
    console.log("User delete attempt status:", forbidRes.status, forbidData);
    if (forbidRes.status !== 403 || forbidData.error.code !== "AUTH_FORBIDDEN") {
      throw new Error("RBAC forbidden check failed");
    }

    // Admin attempt (allowed)
    const allowRes = await fetch(`${baseUrl}/admin/users/2`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    const allowData = (await allowRes.json()) as any;
    console.log("Admin delete status:", allowRes.status, allowData);
    if (allowRes.status !== 200) throw new Error("Admin delete failed");

    console.log("\n--- 9. Testing Token Inspection / Debug ---");
    const inspectRes = await fetch(`${baseUrl}/token/inspect?token=${adminToken}`);
    const inspectData = (await inspectRes.json()) as any;
    console.log("Inspect status:", inspectRes.status, "email claim:", inspectData.decoded.email);
    if (inspectData.decoded.email !== "admin@example.com") throw new Error("Token inspect failed");

    console.log("\n✅ ALL REST API EXAMPLE TESTS PASSED SUCCESSFULLY!\n");
  } finally {
    server.close();
  }
}

runTests().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
