/** biome-ignore-all lint/complexity/noExcessiveCognitiveComplexity: <explanation> */
import { readFileSync } from 'node:fs';
import { parse as parseTs } from '@typescript-eslint/typescript-estree';
import { visitorKeys as tsVisitorKeys } from '@typescript-eslint/visitor-keys';
import { KEYS as jsVisitorKeys } from 'eslint-visitor-keys';
import { parse as parseJs } from 'espree';

type PathSeg =
  | { kind: 'prop'; name: string }
  | { kind: 'index'; idx: number }
  | { kind: 'length' };

type SelectorAttribute = {
  path: string;
  segments: PathSeg[];
  operator: '=' | '!=' | 'regex';
  value: string | RegExp;
};

type ESQuerySelector = {
  nodeType: string;
  attributes: Array<SelectorAttribute>;
  reportPath: string | undefined;
};

declare const prog: unique symbol;
type Program = unknown & { [prog]: true };

function extractAstFromJs(ruleContent: string) {
  return parseJs(ruleContent, {
    ecmaVersion: 'latest',
    ecmaFeatures: { jsx: true },
    sourceType: 'module',
    loc: true,
    range: true,
    tokens: true,
    comment: true,
  }) as unknown as Program;
}

function extractAstFromTs(ruleContent: string) {
  return parseTs(ruleContent, {
    ecmaVersion: 'latest',
    ecmaFeatures: { jsx: true },
    sourceType: 'module',
    loc: true,
    range: true,
    tokens: true,
    comment: true,
  }) as unknown as Program;
}

const VISITOR_KEYS = { ...jsVisitorKeys, ...tsVisitorKeys } as Record<
  string,
  string[]
>;
const AST_NODE_TYPES = new Set([
  'CallExpression',
  'ImportDeclaration',
  'BinaryExpression',
  'NewExpression',
  'MemberExpression',
  'LogicalExpression',
  'AssignmentExpression',
  'IfStatement',
]);

function isNode(obj: any): obj is { type: string } {
  return obj && typeof obj === 'object' && typeof obj.type === 'string';
}

function getKeys(node: any): string[] {
  return (VISITOR_KEYS as any)[node.type] ?? [];
}

function traverse(node: any, enter: (n: any, parent: any) => void) {
  const stack: Array<{ n: any; p: any }> = [{ n: node, p: null }];

  while (stack.length) {
    const { n, p } = stack.pop()!;

    if (!isNode(n)) {
      continue;
    }

    enter(n, p);
    const keys = getKeys(n);

    for (const k of keys) {
      const child = (n as any)[k];
      if (Array.isArray(child)) {
        for (let i = child.length - 1; i >= 0; i--) {
          stack.push({ n: child[i], p: n });
        }
      } else {
        stack.push({ n: child, p: n });
      }
    }
  }
}

function escapeRegexForAlt(s: string) {
  return s.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&');
}

function parsePathFromMemberExpression(
  node: any,
  baseIdent: string,
): string | undefined {
  const segs: string[] = [];
  let cur: any = node;
  while (cur) {
    if (cur.type === 'ChainExpression') {
      cur = cur.expression;
    }
    if (cur.type === 'Identifier') {
      if (cur.name !== baseIdent) {
        return;
      }
      segs.reverse();
      return segs.join('.');
    }
    if (cur.type === 'MemberExpression') {
      const prop = cur.property;
      if (cur.computed) {
        if (
          prop?.type === 'Literal' &&
          (typeof prop.value === 'number' || typeof prop.value === 'string')
        ) {
          segs.push(String(prop.value));
        } else {
          return;
        }
      } else if (prop?.type === 'Identifier') {
        segs.push(prop.name);
      } else {
        return;
      }
      cur = cur.object;
      continue;
    }
    return;
  }
  return;
}

const numberRegex = /^\d+$/;

function toSegments(path: string): PathSeg[] {
  const out: PathSeg[] = [];
  for (const part of path.split('.')) {
    if (part === 'length') {
      out.push({ kind: 'length' });
    } else if (numberRegex.test(part)) {
      out.push({ kind: 'index', idx: Number.parseInt(part, 10) });
    } else {
      out.push({ kind: 'prop', name: part });
    }
  }
  return out;
}

function regExpFromLiteral(lit: any): RegExp | undefined {
  if (lit?.type === 'Literal' && lit.regex) {
    try {
      return new RegExp(lit.regex.pattern, lit.regex.flags || '');
    } catch {
      /* ignore */
    }
  }
  return;
}
function valueFromLiteral(lit: any): string | undefined {
  if (
    lit?.type === 'Literal' &&
    (typeof lit.value === 'string' ||
      typeof lit.value === 'number' ||
      typeof lit.value === 'boolean')
  ) {
    return String(lit.value);
  }
  return;
}

type FoundVisitor = {
  nodeType: string;
  fn: any /* FunctionExpression|ArrowFunctionExpression */;
};

function findVisitors(program: any): FoundVisitor[] {
  const out: FoundVisitor[] = [];

  traverse(program, (n, p) => {
    if (n.type === 'Property' && p?.type === 'ObjectExpression') {
      const keyName =
        n.key.type === 'Identifier'
          ? n.key.name
          : n.key.type === 'Literal'
            ? String(n.key.value)
            : undefined;

      if (!keyName) {
        return;
      }
      const base = keyName.split(':')[0];
      if (!AST_NODE_TYPES.has(base)) {
        return;
      }

      const v = n.value;
      if (
        v.type === 'FunctionExpression' ||
        v.type === 'ArrowFunctionExpression'
      ) {
        out.push({ nodeType: base, fn: v });
      }
    }
  });

  return out;
}

function extractSelector(program: Program): ESQuerySelector[] {
  const selectors: ESQuerySelector[] = [];
  const visitors = findVisitors(program as any);

  for (const v of visitors) {
    const paramName =
      v.fn.params?.[0]?.type === 'Identifier' ? v.fn.params[0].name : 'node';
    const attrs: SelectorAttribute[] = [];
    let reportPath: string | undefined;

    traverse(v.fn.body, (n, _p) => {
      if (
        n.type === 'CallExpression' &&
        n.callee?.type === 'MemberExpression'
      ) {
        const obj = n.callee.object;
        const prop = n.callee.property;
        if (
          obj?.type === 'Identifier' &&
          obj.name === 'context' &&
          prop?.type === 'Identifier' &&
          prop.name === 'report'
        ) {
          const first = n.arguments?.[0];
          if (first?.type === 'ObjectExpression') {
            for (const pr of first.properties) {
              if (
                pr.type === 'Property' &&
                pr.key.type === 'Identifier' &&
                pr.key.name === 'node'
              ) {
                const pth = parsePathFromMemberExpression(pr.value, paramName);
                if (pth) {
                  reportPath = pth;
                }
              }
            }
          } else if (first && first.type !== 'SpreadElement') {
            const pth = parsePathFromMemberExpression(first, paramName);
            if (pth) {
              reportPath = pth;
            }
          }
        }

        if (prop?.type === 'Identifier' && prop.name === 'test') {
          const re = regExpFromLiteral(n.callee.object);
          const arg = n.arguments?.[0];
          if (re && arg) {
            const pth = parsePathFromMemberExpression(arg, paramName);
            if (pth) {
              attrs.push({
                path: pth,
                segments: toSegments(pth),
                operator: 'regex',
                value: re,
              });
            }
          }
        }

        if (prop?.type === 'Identifier' && prop.name === 'includes') {
          const arr = n.callee.object;
          const arg = n.arguments?.[0];
          if (arr?.type === 'ArrayExpression' && arg) {
            const pth = parsePathFromMemberExpression(arg, paramName);
            if (pth) {
              const vals = (arr.elements || [])
                .map((el: any) => valueFromLiteral(el))
                .filter((x: any): x is string => typeof x === 'string');
              if (vals.length > 0) {
                const re = new RegExp(
                  `^(?:${vals.map(escapeRegexForAlt).join('|')})$`,
                );
                attrs.push({
                  path: pth,
                  segments: toSegments(pth),
                  operator: 'regex',
                  value: re,
                });
              }
            }
          }
        }
      }

      if (
        n.type === 'BinaryExpression' &&
        ['===', '==', '!==', '!='].includes(n.operator)
      ) {
        const leftPath = parsePathFromMemberExpression(n.left, paramName);
        const rightPath = parsePathFromMemberExpression(n.right, paramName);

        if (leftPath) {
          const lit = n.right;
          const val = valueFromLiteral(lit);
          if (val !== undefined) {
            attrs.push({
              path: leftPath,
              segments: toSegments(leftPath),
              operator: n.operator.includes('!') ? '!=' : '=',
              value: val,
            });
          }
        } else if (rightPath) {
          const lit = n.left;
          const val = valueFromLiteral(lit);
          if (val !== undefined) {
            attrs.push({
              path: rightPath,
              segments: toSegments(rightPath),
              operator: n.operator.includes('!') ? '!=' : '=',
              value: val,
            });
          }
        }
      }
    });

    const dedup = new Map<string, SelectorAttribute>();
    for (const a of attrs) {
      const key = `${a.path}|${a.operator}|${a.value instanceof RegExp ? `re:${a.value}` : `str:${a.value}`}`;
      if (!dedup.has(key)) {
        dedup.set(key, a);
      }
    }
    const attributes = Array.from(dedup.values());

    if (attributes.length > 0) {
      selectors.push({ nodeType: v.nodeType, attributes, reportPath });
    }
  }

  return selectors;
}

type GenerationOptions = {
  message?: string;
  severity?: 'error' | 'warn' | 'info' | 'hint';
  ruleName?: string;
};

function gritIdent(v: string) {
  return `\`${v.replace(/`/g, '\\`')}\``;
}

function gritRegex(v: RegExp) {
  const flags = v.flags || '';
  const src = v.source.replace(/"/g, '\\"').replace(/\\/g, '\\\\');
  const inline =
    (flags.includes('i') ? '(?i)' : '') +
    (flags.includes('m') ? '(?m)' : '') +
    (flags.includes('s') ? '(?s)' : '');
  return `r"${inline}${src}"`;
}

function atom(val: string | RegExp) {
  return val instanceof RegExp ? gritRegex(val) : gritIdent(String(val));
}

function sevToken(s?: GenerationOptions['severity']) {
  const map: Record<string, string> = {
    error: 'error',
    warn: 'warn',
    info: 'info',
    hint: 'hint',
  };
  return map[(s || 'error').toLowerCase()] || 'error';
}

function captureFor(nodeType: string, path: string): string | undefined {
  switch (nodeType) {
    case 'CallExpression':
      if (path === 'callee.object.name') {
        return '$obj';
      }
      if (path === 'callee.property.name') {
        return '$method';
      }
      if (path === 'callee.name') {
        return '$callee';
      }
      return;
    case 'ImportDeclaration':
      if (path === 'source.value') {
        return '$from';
      }
      return;
    case 'BinaryExpression':
      if (path === 'left.name') {
        return '$left';
      }
      if (path === 'right.name') {
        return '$right';
      }
      if (path === 'operator') {
        return '$op';
      }
      return;
    case 'MemberExpression':
      if (path === 'object.name') {
        return '$object';
      }
      if (path === 'property.name') {
        return '$property';
      }
      return;
    case 'NewExpression':
      if (path === 'callee.name') {
        return '$constructor';
      }
      return;
    default:
      return;
  }
}

function patternFor(
  nodeType: string,
  attrs: SelectorAttribute[],
): { pattern: string; span: string } {
  if (nodeType === 'CallExpression') {
    const hasObj = attrs.some(a => a.path === 'callee.object.name');
    const hasProp = attrs.some(a => a.path === 'callee.property.name');
    return {
      pattern: hasObj || hasProp ? '`$obj.$method($args)`' : '`$callee($args)`',
      span: hasObj || hasProp ? '$method' : '$callee',
    };
  }

  if (nodeType === 'ImportDeclaration') {
    return { pattern: '`import $what from $from`', span: '$from' };
  }

  if (nodeType === 'BinaryExpression') {
    const hard = attrs.find(
      a =>
        a.path === 'operator' &&
        a.operator === '=' &&
        typeof a.value === 'string',
    ) as SelectorAttribute | undefined;
    const op = hard && typeof hard.value === 'string' ? hard.value : '$op';

    return {
      pattern: `\`$left ${op} $right\``,
      span: hard ? '$left' : '$op',
    };
  }

  if (nodeType === 'NewExpression') {
    return { pattern: '`new $constructor($args)`', span: '$constructor' };
  }

  if (nodeType === 'MemberExpression') {
    return { pattern: '`$object.$property`', span: '$property' };
  }
  return { pattern: '`$node`', span: '$node' };
}

function generateConstraints(
  nodeType: string,
  attrs: SelectorAttribute[],
): string[] {
  const cons: string[] = [];

  for (const a of attrs) {
    const cap = captureFor(nodeType, a.path) || '$node';
    const base = `${cap} <: ${atom(a.value)}`;
    cons.push(a.operator === '!=' ? `not ${base}` : base);
  }

  return cons;
}

function generateGritQLFromSelectors(
  selectors: ESQuerySelector[],
  options: GenerationOptions,
): string {
  const blocks: string[] = [];

  for (let i = 0; i < selectors.length; i++) {
    // biome-ignore lint/style/noNonNullAssertion: can't be null
    const sel = selectors[i]!;
    const { pattern, span: defaultSpan } = patternFor(
      sel.nodeType,
      sel.attributes,
    );
    const constraints = generateConstraints(sel.nodeType, sel.attributes);
    const spanCap = (() => {
      if (sel.reportPath) {
        const maybe = captureFor(sel.nodeType, sel.reportPath);

        if (maybe) {
          return maybe;
        }
      }
      return defaultSpan;
    })();

    const diag = `register_diagnostic(
  span = ${spanCap},
  severity = ${sevToken(options.severity)},
  message = "${(options.message || 'ESLint rule violation').replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"
)`;

    const header = `// ESLint rule: ${options.ruleName || 'custom-rule'}${selectors.length > 1 ? `-${i + 1}` : ''}
// Generated from visitor: ${sel.nodeType}`;

    blocks.push(
      `${header}

language js

${pattern} where {
  ${[...constraints, diag].join('\n  ')}
}`,
    );
  }

  return blocks.join('\n\n');
}

const fileNameRegex = /\.(js|ts|tsx|jsx)$/;
function extractRuleNameFromPath(rulePath: string): string {
  const fileName = rulePath.split('/').pop() || '';
  return fileName.replace(fileNameRegex, '');
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

      if (message.includes('${')) {
        message = message.replace(/\$\{[^}]*\}/g, 'N');
      }
      return message;
    }
  }
}

const isTsFileRegex = /\.(ts|tsx)$/;

export function fromRuleSource(rulePath: string) {
  const ruleContent = readFileSync(rulePath, 'utf-8');
  const ruleName = extractRuleNameFromPath(rulePath);
  const isTypescript = isTsFileRegex.test(rulePath);

  let ast: Program;
  try {
    ast = isTypescript
      ? extractAstFromTs(ruleContent)
      : extractAstFromJs(ruleContent);
  } catch {
    ast = extractAstFromTs(ruleContent);
  }
  const extractedSelectors = extractSelector(ast);
  if (extractedSelectors.length === 0) {
    throw new Error(
      `Could not extract a supported selector pattern from ${rulePath}.`,
    );
  }

  const gritql = generateGritQLFromSelectors(extractedSelectors, {
    message: extractMessageFromRule(ruleContent),
    severity: 'error',
    ruleName,
  });

  return { gritql, ruleName };
}
