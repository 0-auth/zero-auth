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
 * zero-auth v1.0.1
 * A lightweight, developer-first authentication layer for Node.js
 * MIT License
 */`,
  },
});
