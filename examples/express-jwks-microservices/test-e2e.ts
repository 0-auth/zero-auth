import http from "node:http";
import type { AddressInfo } from "node:net";
import { generateKeyPairSync } from "node:crypto";
import { signToken } from "@0-auth/zero-auth";

process.env["NODE_ENV"] = "test";
const { createAuthServer } = await import("./src/auth-server.js");
const { createResourceServer } = await import("./src/resource-server.js");

async function runTests() {
  console.log("🚀 Starting E2E test for JWKS & Microservices Example...\n");

  // 1. Start Central Auth Server on ephemeral port
  let authServer!: http.Server;
  let authBaseUrl!: string;

  await new Promise<void>((resolve) => {
    // Temporary placeholder server to get port
    const tempServer = http.createServer();
    tempServer.listen(0, "127.0.0.1", () => {
      const address = tempServer.address() as AddressInfo;
      authBaseUrl = `http://127.0.0.1:${address.port}`;
      tempServer.close(() => {
        const authApp = createAuthServer({
          issuer: authBaseUrl,
          audience: "microservices-api",
        });
        authServer = http.createServer(authApp);
        authServer.listen(address.port, "127.0.0.1", () => resolve());
      });
    });
  });

  console.log(`🔐 Central Auth Server running on ${authBaseUrl}`);

  // 2. Start Downstream Resource Server pointing to auth server's JWKS
  const jwksUri = `${authBaseUrl}/.well-known/jwks.json`;
  const resourceApp = createResourceServer({
    jwksUri,
    issuer: authBaseUrl,
    audience: "microservices-api",
  });
  const resourceServer = http.createServer(resourceApp);

  let resourceBaseUrl!: string;
  await new Promise<void>((resolve) => {
    resourceServer.listen(0, "127.0.0.1", () => {
      const address = resourceServer.address() as AddressInfo;
      resourceBaseUrl = `http://127.0.0.1:${address.port}`;
      resolve();
    });
  });

  console.log(`📦 Downstream Resource Server running on ${resourceBaseUrl}`);
  console.log(`   Verifying tokens via JWKS: ${jwksUri}\n`);

  try {
    // Step 1: Verify JWKS Endpoint on Auth Server
    console.log("--- 1. Testing JWKS Endpoint ---");
    const jwksRes = await fetch(jwksUri);
    const jwksData = (await jwksRes.json()) as any;
    console.log("JWKS status:", jwksRes.status);
    console.log("JWKS Cache-Control:", jwksRes.headers.get("cache-control"));
    console.log("Keys count:", jwksData.keys?.length);
    console.log("Key 0:", { kid: jwksData.keys?.[0]?.kid, alg: jwksData.keys?.[0]?.alg, kty: jwksData.keys?.[0]?.kty });

    if (
      jwksRes.status !== 200 ||
      !Array.isArray(jwksData.keys) ||
      jwksData.keys.length !== 1 ||
      jwksData.keys[0].kty !== "RSA" ||
      jwksData.keys[0].alg !== "RS256"
    ) {
      throw new Error("JWKS endpoint response is invalid");
    }

    // Step 2: Public route without token
    console.log("\n--- 2. Testing Resource Public Route ---");
    const pubRes = await fetch(`${resourceBaseUrl}/api/public`);
    const pubData = (await pubRes.json()) as any;
    console.log("Public route status:", pubRes.status, pubData.message);
    if (pubRes.status !== 200) throw new Error("Public route failed");

    // Step 3: Unauthenticated request to protected route (Expect 401)
    console.log("\n--- 3. Testing Protected Route without Token (Expect 401) ---");
    const unauthRes = await fetch(`${resourceBaseUrl}/api/documents`);
    const unauthData = (await unauthRes.json()) as any;
    console.log("Unauth status:", unauthRes.status, unauthData.error?.code);
    if (unauthRes.status !== 401 || unauthData.error?.code !== "AUTH_TOKEN_MISSING") {
      throw new Error("Protected route did not reject unauthenticated request");
    }

    // Step 4: Login as standard user
    console.log("\n--- 4. Testing Login as Member ---");
    const userLoginRes = await fetch(`${authBaseUrl}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "user@example.com", password: "user123" }),
    });
    const userLoginData = (await userLoginRes.json()) as any;
    console.log("User login status:", userLoginRes.status, "Token:", !!userLoginData.accessToken);
    const userToken = userLoginData.accessToken;
    if (userLoginRes.status !== 200 || !userToken) throw new Error("User login failed");

    // Step 5: Access protected route with user token verified via remote JWKS
    console.log("\n--- 5. Testing Protected Route with Member Token ---");
    const docsRes = await fetch(`${resourceBaseUrl}/api/documents`, {
      headers: { Authorization: `Bearer ${userToken}` },
    });
    const docsData = (await docsRes.json()) as any;
    console.log("Docs access status:", docsRes.status);
    console.log("Verified User Claim:", docsData.user);
    console.log("Documents returned:", docsData.documents?.length);
    if (docsRes.status !== 200 || docsData.user?.id !== "user-2" || docsData.documents?.length !== 2) {
      throw new Error("Protected route failed to verify valid user token via JWKS");
    }

    // Step 6: Test RBAC (Member accessing Admin route -> Expect 403)
    console.log("\n--- 6. Testing Member accessing Admin-Only Route (Expect 403) ---");
    const forbiddenRes = await fetch(`${resourceBaseUrl}/api/admin/metrics`, {
      headers: { Authorization: `Bearer ${userToken}` },
    });
    const forbiddenData = (await forbiddenRes.json()) as any;
    console.log("Member admin access status:", forbiddenRes.status, forbiddenData.error?.code);
    if (forbiddenRes.status !== 403 || forbiddenData.error?.code !== "AUTH_FORBIDDEN") {
      throw new Error("Admin route did not enforce role check");
    }

    // Step 7: Login as Admin
    console.log("\n--- 7. Testing Login as Admin ---");
    const adminLoginRes = await fetch(`${authBaseUrl}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "admin@example.com", password: "admin123" }),
    });
    const adminLoginData = (await adminLoginRes.json()) as any;
    const adminToken = adminLoginData.accessToken;
    console.log("Admin login status:", adminLoginRes.status, "Token:", !!adminToken);

    // Step 8: Access Admin route with Admin token
    console.log("\n--- 8. Testing Admin accessing Admin Route ---");
    const adminMetricsRes = await fetch(`${resourceBaseUrl}/api/admin/metrics`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    const adminMetricsData = (await adminMetricsRes.json()) as any;
    console.log("Admin metrics status:", adminMetricsRes.status);
    console.log("System metrics:", adminMetricsData.systemMetrics);
    if (adminMetricsRes.status !== 200 || !adminMetricsData.systemMetrics) {
      throw new Error("Admin metrics route failed for admin user");
    }

    // Step 9: Dynamic Key Rotation
    console.log("\n--- 9. Testing Zero-Downtime Dynamic Key Rotation ---");
    const rotateRes = await fetch(`${authBaseUrl}/auth/rotate-keys`, { method: "POST" });
    const rotateData = (await rotateRes.json()) as any;
    console.log("Rotate keys response:", rotateData.message);
    const rotatedToken = rotateData.sampleToken;

    // Check updated JWKS has 2 keys now
    const updatedJwks = await (await fetch(jwksUri)).json() as any;
    console.log("Updated JWKS key count:", updatedJwks.keys?.length);
    if (updatedJwks.keys?.length !== 2) throw new Error("Updated JWKS should contain 2 keys");

    // Wait slightly for cooldown
    await new Promise((resolve) => setTimeout(resolve, 150));

    // Access resource server with token signed by the brand-new rotated key!
    const rotatedAccessRes = await fetch(`${resourceBaseUrl}/api/documents`, {
      headers: { Authorization: `Bearer ${rotatedToken}` },
    });
    const rotatedAccessData = (await rotatedAccessRes.json()) as any;
    console.log("Access with rotated key status:", rotatedAccessRes.status);
    console.log("Verified User:", rotatedAccessData.user?.email);
    if (rotatedAccessRes.status !== 200 || rotatedAccessData.user?.id !== "user-rotated") {
      throw new Error("Resource server failed to verify token signed with newly rotated key");
    }

    // Previous tokens signed with old key must STILL verify!
    const oldKeyAccessRes = await fetch(`${resourceBaseUrl}/api/documents`, {
      headers: { Authorization: `Bearer ${userToken}` },
    });
    console.log("Access with previous key after rotation status:", oldKeyAccessRes.status);
    if (oldKeyAccessRes.status !== 200) {
      throw new Error("Resource server failed to verify old key token during rotation period");
    }

    // Step 10: Signature Forgery Rejection
    console.log("\n--- 10. Testing Signature Forgery Rejection (Expect 401) ---");
    const attackerKey = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const forgedToken = await signToken(
      { id: "attacker", role: "admin" },
      attackerKey.privateKey,
      "15m",
      {
        algorithm: "RS256",
        keyId: "auth-server-key-2026-v1", // claiming legitimate kid
        issuer: authBaseUrl,
        audience: "microservices-api",
      }
    );

    const forgedRes = await fetch(`${resourceBaseUrl}/api/documents`, {
      headers: { Authorization: `Bearer ${forgedToken}` },
    });
    const forgedData = (await forgedRes.json()) as any;
    console.log("Forged token status:", forgedRes.status, forgedData.error?.code);
    if (forgedRes.status !== 401 || forgedData.error?.code !== "AUTH_TOKEN_INVALID") {
      throw new Error("Resource server failed to reject forged token signature");
    }

    console.log("\n✅ ALL JWKS & MICROSERVICES E2E TESTS PASSED SUCCESSFULLY!");
  } finally {
    authServer.close();
    resourceServer.close();
  }
}

runTests().catch((err) => {
  console.error("\n❌ Test failed with error:", err);
  process.exit(1);
});
