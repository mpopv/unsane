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
    files: ["**/*.{js,mjs,ts}"],
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
      "import/no-unresolved": ["error", { ignore: ["(?:^|/)dist/"] }],
    },
    settings: {
      "import/extensions": [".js", ".mjs", ".ts"],
      "import/resolver": {
        typescript: {
          project: ["./tsconfig.json", "./tsconfig.test.json"],
        },
        node: {
          extensions: [".js", ".mjs", ".ts"],
        },
      },
    },
  },
  {
    files: ["test/browser/**/*.ts"],
    languageOptions: {
      globals: {
        ...globals.browser,
      },
    },
  },
];
