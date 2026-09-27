import { createAuthServer } from "./auth-server.js";
import { createResourceServer } from "./resource-server.js";

const authPort = Number(process.env["AUTH_PORT"] ?? 4000);
const resourcePort = Number(process.env["RESOURCE_PORT"] ?? 4001);

const authApp = createAuthServer({
  issuer: `http://localhost:${authPort}`,
  audience: "microservices-api",
});

const resourceApp = createResourceServer({
  jwksUri: `http://localhost:${authPort}/.well-known/jwks.json`,
  issuer: `http://localhost:${authPort}`,
  audience: "microservices-api",
});

authApp.listen(authPort, () => {
  console.log(`\n======================================================`);
  console.log(`🔐 1. Central Auth Server (JWKS Publisher)`);
  console.log(`   URL:  http://localhost:${authPort}`);
  console.log(`   JWKS: http://localhost:${authPort}/.well-known/jwks.json`);
  console.log(`======================================================`);

  resourceApp.listen(resourcePort, () => {
    console.log(`\n======================================================`);
    console.log(`📦 2. Downstream Microservice (JWKS Verifier)`);
    console.log(`   URL:  http://localhost:${resourcePort}`);
    console.log(`   Mode: Verifier-Only (Zero Private Keys)`);
    console.log(`======================================================\n`);

    console.log(`Try it out with curl:`);
    console.log(`1. Inspect published JWKS:`);
    console.log(`   curl http://localhost:${authPort}/.well-known/jwks.json\n`);
    console.log(`2. Log in on Central Auth Server:`);
    console.log(`   curl -X POST http://localhost:${authPort}/auth/login -H "Content-Type: application/json" -d '{"email":"user@example.com","password":"user123"}'\n`);
    console.log(`3. Access Protected Microservice with Bearer token:`);
    console.log(`   curl http://localhost:${resourcePort}/api/documents -H "Authorization: Bearer <TOKEN>"\n`);
  });
});
