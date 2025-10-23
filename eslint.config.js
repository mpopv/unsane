import eslintPluginImport from "eslint-plugin-import";
import tseslint from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
import prettierConfig from "eslint-config-prettier";
import js from "@eslint/js";
import globals from "globals";

const prettierRules = prettierConfig?.rules ?? {};

const importRecommended = eslintPluginImport.configs.recommended.rules;
const importTypescript = eslintPluginImport.configs.typescript.rules;

export default [
  {
    ignores: ["dist/**", "coverage/**", "node_modules/**"],
  },
  {
    files: ["**/*.js", "**/*.ts"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
      },
      globals: {
        ...globals.node,
      },
    },
    plugins: {
      "@typescript-eslint": tseslint,
      import: eslintPluginImport,
    },
    rules: {
      ...js.configs.recommended.rules,
      ...tseslint.configs.recommended.rules,
      ...importRecommended,
      ...importTypescript,
      ...prettierRules,
    },
    settings: {
      "import/extensions": [".js", ".ts"],
      "import/resolver": {
        typescript: {
          project: ["./tsconfig.json", "./tsconfig.cjs.json"],
        },
        node: {
          extensions: [".js", ".ts"],
        },
      },
    },
  },
  {
    files: ["**/*.test.ts", "**/*.test.js"],
    languageOptions: {
      globals: {
        ...globals.node,
        ...globals.vitest,
      },
    },
  },
];
