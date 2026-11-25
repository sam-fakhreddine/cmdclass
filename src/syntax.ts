import { createRequire } from "node:module";
import { Language, Parser } from "web-tree-sitter";
import type { Node } from "web-tree-sitter";

const require = createRequire(import.meta.url);
const languages = new Map<string, Promise<Language>>();
export const maxInputBytes = 1024 * 1024;
const maxSyntaxDepth = 128;

export class InputError extends Error {
  readonly line: number;
  readonly column: number;
  constructor(message: string, line: number, column: number) {
    super(message);
    this.line = line;
    this.column = column;
  }
}

export async function withSyntax<T>(
  language: "bash" | "python", source: string, visit: (root: Node) => T | Promise<T>,
): Promise<T> {
  if (Buffer.byteLength(source) > maxInputBytes) {
    throw new InputError("input exceeds the 1 MiB analysis limit", 1, 1);
  }
  let grammar = languages.get(language);
  if (!grammar) {
    grammar = Parser.init().then(() =>
      Language.load(require.resolve(`@vscode/tree-sitter-wasm/wasm/tree-sitter-${language}.wasm`)));
    languages.set(language, grammar);
  }
  const resolved = await grammar;
  const parser = new Parser();
  try {
    parser.setLanguage(resolved);
    const tree = parser.parse(source);
    if (!tree) throw new Error(`${language} parser returned no syntax tree`);
    try {
      const root = tree.rootNode;
      if (root.hasError) {
        let error = root;
        while (!error.isError && !error.isMissing) {
          const next = error.children.find((child) => child.hasError || child.isMissing);
          if (!next) break;
          error = next;
        }
        throw new InputError(`invalid ${language === "bash" ? "shell" : "Python"} syntax`,
          error.startPosition.row + 1, error.startPosition.column + 1);
      }
      const work = [{ node: root, depth: 0 }];
      while (work.length) {
        const entry = work.pop();
        if (!entry) break;
        if (language === "python" && entry.node.type === "block" &&
            !entry.node.namedChildren.some((node) => node.type !== "comment")) {
          throw new InputError("invalid Python syntax: expected a statement",
            entry.node.startPosition.row + 1, entry.node.startPosition.column + 1);
        }
        if (entry.depth >= maxSyntaxDepth) {
          throw new InputError("syntax nesting exceeds the analysis limit",
            entry.node.startPosition.row + 1, entry.node.startPosition.column + 1);
        }
        for (const node of entry.node.namedChildren) work.push({ node, depth: entry.depth + 1 });
      }
      return await visit(root);
    } finally {
      tree.delete();
    }
  } finally {
    parser.delete();
  }
}
