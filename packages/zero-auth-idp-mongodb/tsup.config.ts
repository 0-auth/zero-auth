import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  sourcemap: true,
  target: "es2022",
  banner: {
    js: "/* @0-auth/zero-auth-idp-mongodb v0.2.0 */",
  },
});
