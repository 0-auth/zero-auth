# Contributing to @0-auth/zero-auth

Thank you for your interest in contributing to `@0-auth/zero-auth`! We welcome contributions of all kinds — bug fixes, documentation improvements, test coverage expansions, and feature proposals.

---

## Code of Conduct

Please be respectful, collaborative, and constructive when interacting with maintainers and other contributors.

---

## Development Setup

### Prerequisites

- **Node.js**: `>= 18.0.0`
- **npm**: `>= 9.0.0`
- **Git**

### Getting Started

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/<your-username>/zero-auth.git
   cd zero-auth
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Verify the environment by running tests:**
   ```bash
   npm test
   ```

---

## Available Scripts

| Command | Description |
|---|---|
| `npm run dev` | Runs `tsup` in watch mode to compile TypeScript changes on the fly. |
| `npm run build` | Compiles ESM (`.mjs`), CommonJS (`.js`), and TypeScript definitions (`.d.ts`, `.d.mts`). |
| `npm test` | Runs the full Vitest test suite. |
| `npm run test:watch` | Runs Vitest in interactive watch mode. |
| `npm run test:coverage` | Generates a code coverage report using `@vitest/coverage-v8`. |
| `npm run lint` | Checks code against ESLint rules. |
| `npm run lint:fix` | Automatically fixes autofixable ESLint issues. |
| `npm run format` | Formats all code with Prettier. |
| `npm run typecheck` | Validates TypeScript types across `src/` and `tests/` without emitting files. |
| `npm run prepublishOnly` | Complete verification pipeline (`lint` + `typecheck` + `test` + `build`). |

---

## Contribution Workflow

1. **Create a branch:**
   ```bash
   git checkout -b feat/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. **Write your changes:**
   - Keep pull requests focused on a single change.
   - Maintain full test coverage for any new features or bug fixes.
   - Follow existing code style and formatting standards.

3. **Run the quality check:**
   Ensure all checks pass cleanly before submitting:
   ```bash
   npm run prepublishOnly
   ```

4. **Commit and open a Pull Request:**
   - Use clear, conventional commit messages (e.g. `feat: add custom error codes`, `fix: handle edge case in cookie parser`).
   - Describe what the PR accomplishes and reference any related GitHub issues.

---

## Architecture & Code Guidelines

- **Zero Unnecessary Dependencies**: The core package relies only on `jose` for cryptographic primitives. Avoid adding heavy dependencies unless strictly necessary.
- **Strict TypeScript**: Avoid `any` types wherever possible. Ensure all public APIs have explicit TypeScript types and JSDoc comments.
- **Fail Secure**: All authentication and verification logic must fail closed by default.
