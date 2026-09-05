import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  treeshake: true,
  minify: false,
  target: "es2022",
  outDir: "dist",
  banner: {
    js: `/**
 * zero-auth-idp v0.1.0
 * A minimal self-hosted OAuth authorization server for Express
 * MIT License
 */`,
  },
});
