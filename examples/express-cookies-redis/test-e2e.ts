import http from "node:http";

process.env["NODE_ENV"] = "test";
const { app, redis } = await import("./src/server.js");

async function runTests() {
  const server = http.createServer(app);

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve());
  });

  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Could not get server port");
  const baseUrl = `http://127.0.0.1:${address.port}`;
  console.log(`🚀 Cookie + Redis Test Server listening on ${baseUrl}`);

  try {
    console.log("\n--- 1. Testing Register with Cookies ---");
    const regRes = await fetch(`${baseUrl}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "cookieuser@example.com",
        password: "secretpassword",
        role: "user",
      }),
    });
    const regCookies = regRes.headers.getSetCookie ? regRes.headers.getSetCookie() : [regRes.headers.get("set-cookie") || ""];
    const regData = (await regRes.json()) as any;
    console.log("Register status:", regRes.status);
    console.log("Register Set-Cookie headers:", regCookies);
    if (regRes.status !== 201 || regCookies.length === 0) throw new Error("Register cookies failed");

    console.log("\n--- 2. Testing Login (Admin) with Cookies ---");
    const loginRes = await fetch(`${baseUrl}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "admin@example.com",
        password: "admin123",
      }),
    });
    const setCookieHeaders = loginRes.headers.getSetCookie ? loginRes.headers.getSetCookie() : [loginRes.headers.get("set-cookie") || ""];
    const loginData = (await loginRes.json()) as any;
    console.log("Login status:", loginRes.status);
    console.log("Set-Cookie headers received:", setCookieHeaders);

    // Extract access_token and refresh_token from cookies
    const cookieHeader = setCookieHeaders.map((c) => c.split(";")[0]).join("; ");
    console.log("Cookie header for subsequent requests:", cookieHeader);

    console.log("\n--- 3. Testing Protected Profile (using Cookie) ---");
    const profileRes = await fetch(`${baseUrl}/profile`, {
      headers: { Cookie: cookieHeader },
    });
    const profileData = (await profileRes.json()) as any;
    console.log("Profile status:", profileRes.status);
    console.log("Profile user:", profileData.user);
    if (profileRes.status !== 200 || profileData.user.id !== "1") throw new Error("Cookie profile failed");

    console.log("\n--- 4. Testing Refresh Token Rotation via Cookie ---");
    const refreshRes = await fetch(`${baseUrl}/auth/refresh`, {
      method: "POST",
      headers: { Cookie: cookieHeader },
    });
    const refreshData = (await refreshRes.json()) as any;
    const rotatedCookies = refreshRes.headers.getSetCookie ? refreshRes.headers.getSetCookie() : [refreshRes.headers.get("set-cookie") || ""];
    console.log("Refresh status:", refreshRes.status);
    console.log("Rotated tokens in body:", !!refreshData.accessToken, !!refreshData.refreshToken);
    console.log("Rotated Set-Cookie headers:", rotatedCookies);

    const rotatedCookieHeader = rotatedCookies.map((c) => c.split(";")[0]).join("; ");

    console.log("\n--- 5. Testing Profile with New Rotated Cookie ---");
    const profileAfterRotate = await fetch(`${baseUrl}/profile`, {
      headers: { Cookie: rotatedCookieHeader },
    });
    console.log("Profile status with rotated cookie:", profileAfterRotate.status);
    if (profileAfterRotate.status !== 200) throw new Error("Rotated cookie failed");

    console.log("\n--- 6. Testing Logout (Clears Cookies) ---");
    const logoutRes = await fetch(`${baseUrl}/auth/logout`, {
      method: "POST",
      headers: { Cookie: rotatedCookieHeader },
    });
    const logoutCookies = logoutRes.headers.getSetCookie ? logoutRes.headers.getSetCookie() : [logoutRes.headers.get("set-cookie") || ""];
    console.log("Logout status:", logoutRes.status);
    console.log("Logout clear cookies:", logoutCookies);

    console.log("\n✅ ALL COOKIES-REDIS EXAMPLE TESTS PASSED SUCCESSFULLY!\n");
  } finally {
    server.close();
    await redis.quit().catch(() => {});
  }
}

runTests().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
