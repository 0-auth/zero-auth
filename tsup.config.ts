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
 * zero-auth v1.0.0
 * A lightweight, developer-first JWT authentication package for Node.js
 * MIT License
 */`,
  },
});
