// @ts-check
import js from "@eslint/js";
import tsParser from "@typescript-eslint/parser";
import tsPlugin from "@typescript-eslint/eslint-plugin";
import prettierConfig from "eslint-config-prettier";
import { fileURLToPath } from "node:url";

const configDir = fileURLToPath(new URL(".", import.meta.url));

const tsRules = {
  "@typescript-eslint/no-explicit-any": "error",
  "@typescript-eslint/consistent-type-imports": ["error", { prefer: "type-imports" }],
  "@typescript-eslint/no-unused-vars": [
    "error",
    { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
  ],
  "@typescript-eslint/no-floating-promises": "error",
  "@typescript-eslint/await-thenable": "error",
  "@typescript-eslint/no-misused-promises": "error",
  // Turn off base rules superseded by TypeScript equivalents
  "no-undef": "off",
  "no-unused-vars": "off",
};

export default [
  js.configs.recommended,

  // ── Source files ─────────────────────────────────────────────────────────
  {
    files: ["packages/zero-auth/src/**/*.ts", "packages/zero-auth-idp/src/**/*.ts"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        project: ["./packages/zero-auth/tsconfig.json", "./packages/zero-auth-idp/tsconfig.json"],
        tsconfigRootDir: configDir,
      },
    },
    plugins: { "@typescript-eslint": tsPlugin },
    rules: tsRules,
  },

  // ── Test files (separate tsconfig that includes tests/) ──────────────────
  {
    files: ["packages/zero-auth/tests/**/*.ts", "packages/zero-auth-idp/tests/**/*.ts"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        project: [
          "./packages/zero-auth/tsconfig.test.json",
          "./packages/zero-auth-idp/tsconfig.test.json",
        ],
        tsconfigRootDir: configDir,
      },
    },
    plugins: { "@typescript-eslint": tsPlugin },
    rules: {
      ...tsRules,
      // Relax some rules for test files
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-member-access": "off",
    },
  },

  prettierConfig,

  {
    ignores: ["dist/**", "node_modules/**", "coverage/**", "examples/**", "**/*.mjs"],
  },
];
