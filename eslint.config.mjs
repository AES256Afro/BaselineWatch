import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["node_modules/", "dist/", "data/", "docs/"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: { globals: { ...globals.node } },
    rules: {
      "@typescript-eslint/consistent-type-imports": ["error", { prefer: "type-imports" }],
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      "no-console": "off",
    },
  },
  {
    // The one script served to browsers (public/scan.js): a plain ES module with the browser's globals and none of Node's.
    files: ["public/**/*.js"],
    languageOptions: { globals: { ...globals.browser }, sourceType: "module" },
  },
);
