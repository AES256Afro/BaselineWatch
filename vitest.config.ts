import { configDefaults, defineConfig } from "vitest/config";

// The suite is test/**; a checkout that carries worktrees under .claude/ must not run their copies too.
export default defineConfig({
  test: { exclude: [...configDefaults.exclude, ".claude/**"] },
});
