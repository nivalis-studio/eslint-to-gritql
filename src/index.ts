import { readFileSync } from "node:fs";
import { parse as parseJs } from "espree";
import { parse as parseTs } from "@typescript-eslint/typescript-estree";

type PathSeg = { kind: "prop"; name: string } | { kind: "index"; idx: number } | { kind: "length" };

type SelectorAttribute = {
  path: string;
  segments: PathSeg[];
  operator: "=" | "!=" | "regex";
  value: string | RegExp;
};

type ESQuerySelector = {
  nodeType: string;
  attributes: Array<SelectorAttribute>;
};

declare const prog: unique symbol;
type Program = unknown & { [prog]: true };

function extractAstFromJs(ruleContent: string) {
  return parseJs(ruleContent, {
    ecmaVersion: "latest",
    ecmaFeatures: { jsx: true },
    sourceType: "module",
    loc: true,
    range: true,
    tokens: true,
    comment: true,
  }) as unknown as Program;
}

function extractAstFromTs(ruleContent: string) {
  return parseTs(ruleContent, {
    ecmaVersion: "latest",
    ecmaFeatures: { jsx: true },
    sourceType: "module",
    loc: true,
    range: true,
    tokens: true,
    comment: true,
  }) as unknown as Program;
}

function extractSelector(program: Program): ESQuerySelector[] {
  const selectors: ESQuerySelector[] = [];

  return selectors;
}

type GenerationOptions = {
  message?: string;
  severity?: "error" | "warn" | "info";
  ruleName?: string;
};

function generateGritQLFromSelectors(selectors: ESQuerySelector[], _options: GenerationOptions): string {
  if (selectors.length === 0) {
    throw new Error("No selectors provided");
  }

  return "";
}

const fileNameRegex = /\.(js|ts)$/;

function extractRuleNameFromPath(rulePath: string): string {
  const fileName = rulePath.split("/").pop() || "";
  return fileName.replace(fileNameRegex, "");
}

const messagePatterns = [
  /message\s*:\s*['"`]([^'"`]+)['"`]/,
  /messageId\s*:\s*['"`]([^'"`]+)['"`]/,
  /report\s*\(\s*[^,]*,\s*['"`]([^'"`]+)['"`]/,
  /report\s*\(\s*`([^`]+)`/,
  /report\s*\(\s*['"`]([^'"`]+)['"`]/,
  /report\s*\(\s*`([^`]*\$\{[^}]*\}[^`]*)`/,
];

function extractMessageFromRule(ruleContent: string): string | undefined {
  for (const pattern of messagePatterns) {
    const match = ruleContent.match(pattern);
    if (match?.[1]) {
      let message = match[1];

      if (message.includes("${")) {
        message = message.replace(/\$\{[^}]*\}/g, "N");
      }

      return message;
    }
  }
}

export function fromRuleSource(rulePath: string) {
  const ruleContent = readFileSync(rulePath, "utf-8");
  const ruleName = extractRuleNameFromPath(rulePath);
  const isTypescript = rulePath.endsWith(".ts") || rulePath.endsWith(".tsx");

  const ast = isTypescript ? extractAstFromTs(ruleContent) : extractAstFromJs(ruleContent);
  const extractedSelectors = extractSelector(ast);

  const gritql = generateGritQLFromSelectors(extractedSelectors, {
    message: extractMessageFromRule(ruleContent),
    severity: "error",
    ruleName,
  });

  return { gritql, ruleName };
}
