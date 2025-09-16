import { expect, test } from "bun:test";
import { fromRuleSource } from "./index";

const paths = [
  "plugins/eslint-plugin-jsdoc/src/rules/checkAccess.js",
  "plugins/eslint-plugin-jsdoc/src/rules/checkTypes.js",
] satisfies string[];

test.each(paths)("should parse rule %s", (path) => {
  expect(() => {
    fromRuleSource(path);
  }).not.toThrow();
});
