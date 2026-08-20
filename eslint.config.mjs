// @ts-check
import js from "@eslint/js";
import tsParser from "@typescript-eslint/parser";
import tsPlugin from "@typescript-eslint/eslint-plugin";
import prettierConfig from "eslint-config-prettier";

const tsRules = {
  "@typescript-eslint/no-explicit-any": "error",
  "@typescript-eslint/consistent-type-imports": [
    "error",
    { prefer: "type-imports" },
  ],
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
    files: ["src/**/*.ts"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        project: "./tsconfig.json",
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: { "@typescript-eslint": tsPlugin },
    rules: tsRules,
  },

  // ── Test files (separate tsconfig that includes tests/) ──────────────────
  {
    files: ["tests/**/*.ts"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        project: "./tsconfig.test.json",
        tsconfigRootDir: import.meta.dirname,
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
