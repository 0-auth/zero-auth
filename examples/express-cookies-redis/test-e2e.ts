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
    console.log("\n--- 1. Testing Health Check ---");
    const healthRes = await fetch(`${baseUrl}/healthz`);
    const healthData = (await healthRes.json()) as { status?: string; redis?: string };
    console.log("Health status:", healthRes.status, healthData);
    if (healthRes.status !== 200 || healthData.redis !== "ok") {
      throw new Error("Health check failed");
    }

    console.log("\n--- 2. Testing Register with Cookies ---");
    const regRes = await fetch(`${baseUrl}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "cookieuser@example.com",
        password: "secretpassword",
        role: "admin",
      }),
    });
    const regCookies = regRes.headers.getSetCookie
      ? regRes.headers.getSetCookie()
      : [regRes.headers.get("set-cookie") || ""];
    const regData = (await regRes.json()) as any;
    console.log("Register status:", regRes.status);
    console.log("Register Set-Cookie headers:", regCookies);
    if (regRes.status !== 201 || regCookies.length === 0 || regData.user.role !== "user") {
      throw new Error("Register cookies or role restriction failed");
    }

    console.log("\n--- 3. Testing Login (Admin) with Cookies ---");
    const loginRes = await fetch(`${baseUrl}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "admin@example.com",
        password: "admin123",
      }),
    });
    const setCookieHeaders = loginRes.headers.getSetCookie
      ? loginRes.headers.getSetCookie()
      : [loginRes.headers.get("set-cookie") || ""];
    const loginData = (await loginRes.json()) as any;
    console.log("Login status:", loginRes.status);
    console.log("Set-Cookie headers received:", setCookieHeaders);

    // Extract access_token and refresh_token from cookies
    const cookieHeader = setCookieHeaders.map((c) => c.split(";")[0]).join("; ");
    console.log("Cookie header for subsequent requests:", cookieHeader);

    console.log("\n--- 4. Testing CSRF Token ---");
    const csrfRes = await fetch(`${baseUrl}/auth/csrf-token`, {
      headers: { Cookie: cookieHeader },
    });
    const csrfData = (await csrfRes.json()) as { csrfToken?: string };
    const csrfCookies = csrfRes.headers.getSetCookie
      ? csrfRes.headers.getSetCookie()
      : [csrfRes.headers.get("set-cookie") || ""];
    const csrfCookieHeader = csrfCookies.map((c) => c.split(";")[0]).join("; ");
    if (csrfRes.status !== 200 || !csrfData.csrfToken || !csrfCookieHeader) {
      throw new Error("CSRF token setup failed");
    }
    const cookieHeaderWithCsrf = `${cookieHeader}; ${csrfCookieHeader}`;
    console.log("CSRF status:", csrfRes.status);

    const missingCsrfRes = await fetch(`${baseUrl}/auth/refresh`, {
      method: "POST",
      headers: { Cookie: cookieHeader },
    });
    if (missingCsrfRes.status !== 403) throw new Error("Missing CSRF token was accepted");
    console.log("Missing CSRF rejection: PASS");

    console.log("\n--- 5. Testing Protected Profile (using Cookie) ---");
    const profileRes = await fetch(`${baseUrl}/profile`, {
      headers: { Cookie: cookieHeaderWithCsrf },
    });
    const profileData = (await profileRes.json()) as any;
    console.log("Profile status:", profileRes.status);
    console.log("Profile user:", profileData.user);
    if (profileRes.status !== 200 || profileData.user.id !== "1")
      throw new Error("Cookie profile failed");

    console.log("\n--- 6. Testing Refresh Token Rotation via Cookie ---");
    const refreshRes = await fetch(`${baseUrl}/auth/refresh`, {
      method: "POST",
      headers: { Cookie: cookieHeaderWithCsrf, "x-csrf-token": csrfData.csrfToken },
    });
    const refreshData = (await refreshRes.json()) as any;
    const rotatedCookies = refreshRes.headers.getSetCookie
      ? refreshRes.headers.getSetCookie()
      : [refreshRes.headers.get("set-cookie") || ""];
    console.log("Refresh status:", refreshRes.status);
    console.log("Rotated tokens in body:", !!refreshData.accessToken, !!refreshData.refreshToken);
    console.log("Rotated Set-Cookie headers:", rotatedCookies);

    const rotatedCookieHeader = rotatedCookies.map((c) => c.split(";")[0]).join("; ");

    console.log("\n--- 7. Testing Profile with New Rotated Cookie ---");
    const profileAfterRotate = await fetch(`${baseUrl}/profile`, {
      headers: { Cookie: `${rotatedCookieHeader}; ${csrfCookieHeader}` },
    });
    console.log("Profile status with rotated cookie:", profileAfterRotate.status);
    if (profileAfterRotate.status !== 200) throw new Error("Rotated cookie failed");

    console.log("\n--- 8. Testing Logout (Clears Cookies) ---");
    const logoutRes = await fetch(`${baseUrl}/auth/logout`, {
      method: "POST",
      headers: {
        Cookie: `${rotatedCookieHeader}; ${csrfCookieHeader}`,
        "x-csrf-token": csrfData.csrfToken,
      },
    });
    const logoutCookies = logoutRes.headers.getSetCookie
      ? logoutRes.headers.getSetCookie()
      : [logoutRes.headers.get("set-cookie") || ""];
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
