import type { Node } from "web-tree-sitter";

export function staticPrefix(node: Node): { prefix: string; literal: string | null } {
  const raw = node.text;
  if (node.type === "command_name" && node.firstNamedChild) return staticPrefix(node.firstNamedChild);
  if (node.type === "raw_string") return { prefix: raw.slice(1, -1), literal: raw.slice(1, -1) };
  if (node.type === "string" || node.type === "concatenation") {
    let prefix = "";
    for (const child of node.namedChildren) {
      if (node.type === "string") {
        if (child.type !== "string_content") return { prefix, literal: null };
        prefix += child.text.replace(/\\([$`"\\\n])/g, (_, c: string) => c === "\n" ? "" : c);
      } else {
        const part = staticPrefix(child);
        prefix += part.prefix;
        if (part.literal === null) return { prefix, literal: null };
      }
    }
    return { prefix, literal: prefix };
  }
  if (node.type === "variable_assignment") {
    const name = node.childForFieldName("name");
    const value = node.childForFieldName("value");
    if (name) return { prefix: `${name.text}=${value ? staticPrefix(value).prefix : ""}`, literal: null };
  }
  if (node.type === "word" || node.type === "number") {
    if (/(^|[^\\])[$`*?[\]{}~]/.test(raw)) return { prefix: raw.split(/[$`*?[\]{}~]/, 1)[0], literal: null };
    const literal = raw.replace(/\\([\s\S])/g, (_, c: string) => c === "\n" ? "" : c);
    return { prefix: literal, literal };
  }
  return { prefix: "", literal: null };
}

export function inlineBody(words: Node[], redirects: Node[], executable: string | undefined) {
  if (!executable || !["bash", "sh", "eval", "python", "python3"].includes(executable)) return;
  const language = executable.startsWith("python") ? "python" as const : "bash" as const;
  const isEval = executable === "eval";
  if ((isEval && words.length === 2) ||
      (!isEval && words[1] && staticPrefix(words[1]).literal === "-c")) {
    const argument = words[isEval ? 1 : 2];
    if (argument && ["raw_string", "string"].includes(argument.type)) {
      const text = argument.text.slice(1, -1);
      if (staticPrefix(argument).literal === text) return { text, offset: argument.startIndex + 1, language };
    }
    return;
  }
  if (isEval || words.length !== 1) return;
  const document = redirects.find((redirect) => redirect.type === "heredoc_redirect");
  const body = document?.namedChildren.find((child) => child.type === "heredoc_body");
  const start = document?.namedChildren.find((child) => child.type === "heredoc_start");
  if (body && start && (!/[$`\\]/.test(body.text) || /^['"]/.test(start.text)) &&
      !document?.text.startsWith("<<-")) {
    return { text: body.text, offset: body.startIndex, language };
  }
}

export function originalPosition(source: string, offset: number, line: number, column: number) {
  const before = source.slice(0, offset);
  const lastNewline = before.lastIndexOf("\n");
  return {
    line: before.split("\n").length + line - 1,
    column: line === 1 ? offset - lastNewline + column - 1 : column,
  };
}

export function commandAssignments(words: readonly Node[]) {
  const values = new Map<string, string | null>();
  for (const word of words) {
    if (word.type !== "variable_assignment") break;
    const name = word.childForFieldName("name");
    const value = word.childForFieldName("value");
    if (name) values.set(name.text, value ? staticPrefix(value).literal : "");
  }
  return values;
}
