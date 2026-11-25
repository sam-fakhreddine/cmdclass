import type { Node } from "web-tree-sitter";
import { classifyAws } from "./aws/cli.ts";
import { classifyLocal, isNestedReadOnlyCommand } from "./local.ts";
import { classifyProvider } from "./providers.ts";
import { isDatabaseProvider } from "./provider/database.ts";
import { classes } from "./report.ts";
import { redactCommand } from "./redact.ts";
import type { Finding } from "./report.ts";
import { commandAssignments, inlineBody, originalPosition, staticPrefix } from "./shell/source.ts";
import { unwrap } from "./shell/wrappers.ts";
import { InputError, withSyntax } from "./syntax.ts";
import { analyzePython } from "./python.ts";

export { InputError } from "./syntax.ts";

const traversable = new Set([
  "program", "list", "pipeline", "if_statement", "elif_clause", "else_clause", "do_group",
  "for_statement", "while_statement", "case_statement", "case_item", "compound_statement",
  "subshell", "negated_command",
]);

function pendingNested(node: Node): boolean {
  return ["command_substitution", "process_substitution", "arithmetic_expansion"].includes(node.type) ||
    node.namedChildren.some(pendingNested);
}

function containsArithmeticExpansion(node: Node): boolean {
  return node.type === "arithmetic_expansion" || node.namedChildren.some(containsArithmeticExpansion);
}

const maxInlineDepth = 12;
const remoteInputs = new Set(["curl", "wget"]);
const findActions = new Set(["-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"]);
export async function analyzeShell(source: string): Promise<Finding[]> {
  return analyzeShellSource(source, 0);
}

async function analyzeShellSource(source: string, depth: number): Promise<Finding[]> {
  return withSyntax("bash", source, async (root) => {
      const findings: Promise<Finding[]>[] = [];
      const functions = new Map<string, Promise<Finding[]>[] | null>();
      function visitSubstitutions(node: Node) {
        if (node.type === "command_substitution" || node.type === "process_substitution") {
          for (const child of node.namedChildren) visit(child);
          return;
        }
        for (const child of node.namedChildren) visitSubstitutions(child);
      }

      function visit(node: Node, redirections: Node[] = []) {
        if (node.type === "redirected_statement") {
          const body = node.childForFieldName("body");
          const redirects = node.childrenForFieldName("redirect");
          if (body && ["command", "list", "pipeline"].includes(body.type)) {
            visit(body, [...redirects, ...redirections]);
            return;
          }
          if (body) visit(body);
          record(node, [], [...redirects, ...redirections]);
        } else if (traversable.has(node.type)) {
          const children = node.namedChildren.filter((child) => child.type !== "comment");
          const executableOf = (child: Node) => staticPrefix(child.childForFieldName("name") ?? child)
            .literal?.split("/").at(-1) ?? "";
          for (const [index, child] of children.entries()) {
            if (node.type === "pipeline" && index > 0 &&
                ["sh", "bash"].includes(executableOf(child)) &&
                remoteInputs.has(executableOf(children[index - 1]))) {
              findings.push(Promise.resolve([{
                line: child.startPosition.row + 1, column: child.startPosition.column + 1,
                command: executableOf(child), class: "DANGEROUS", reason: "runs downloaded code", source: "shell pipeline",
              }]));
            } else visit(child, index === children.length - 1 ? redirections : []);
          }
        } else if (node.type === "command") {
          const words = node.namedChildren.filter((child) =>
            !["file_redirect", "heredoc_redirect", "herestring_redirect", "comment"].includes(child.type));
          record(node, words, [...node.childrenForFieldName("redirect"), ...redirections]);
        } else if (node.type === "test_command") {
          const unsupported = node.text.trimStart().startsWith("((")
            ? "arithmetic command is not analysed"
            : pendingNested(node) ? "nested code is not yet analysed" : undefined;
          record(node, [], redirections, unsupported);
          visitSubstitutions(node);
        } else if (node.type === "variable_assignment") {
          record(node, [node], redirections);
        } else if (node.type === "function_definition") {
          const name = node.childForFieldName("name")?.text;
          const body = node.childForFieldName("body");
          if (!name || !body) {
            record(node, [], redirections, "shell construct is not yet analysed");
            return;
          }
          const start = findings.length;
          const previous = functions.has(name);
          functions.set(name, null); // Recursive calls must not wait on their own result.
          visit(body);
          functions.set(name, previous ? null : findings.slice(start));
        } else if (["declaration_command", "unset_command"].includes(node.type)) {
          record(node, [], redirections, "shell construct is not yet analysed");
          visitSubstitutions(node);
        }
      }

      function record(node: Node, words: Node[], redirects: Node[], unsupported?: string) {
        const parts = words.map(staticPrefix);
        const commandWords = words.filter((word) => word.type !== "variable_assignment");
        const args = parts.filter((_, index) => words[index].type !== "variable_assignment")
          .map(({ literal }) => literal);
        const assignments = commandAssignments(words);
        const noteWrapper = (name: string) => {
          if (name === "xargs") unsupported ??= "nested arguments are supplied at runtime";
        };
        let command = unwrap(args, assignments, noteWrapper);
        const outer = command[0]?.split("/").at(-1);
        if (outer === "parallel") {
          const offset = command[1] === "--" ? 2 : 1;
          if (command[offset] && !command[offset]?.startsWith("-")) {
            unsupported ??= "nested arguments are supplied at runtime";
            command = unwrap(command.slice(offset), assignments, noteWrapper);
          }
        } else if (outer === "find" && !command.includes("-delete")) {
          const start = command.findIndex((part) => part === "-exec" || part === "-execdir");
          const end = command.findIndex((part, i) => i > start && (part === ";" || part === "+"));
          if (start >= 0 && end > start + 1) {
            const predicates = [...command.slice(1, start), ...command.slice(end + 1)];
            if (predicates.some((part) => part === null || findActions.has(part))) {
              unsupported ??= "additional find actions are not analysed";
            }
            command = unwrap(command.slice(start + 1, end), assignments, noteWrapper);
          }
        }
        const executable = command[0]?.split("/").at(-1);
        const functionName = args[0];
        const functionBinding = functionName ? functions.get(functionName) : undefined;
        const body = depth < maxInlineDepth && !unsupported && outer !== "find" && outer !== "parallel"
          ? inlineBody(commandWords.slice(args.length - command.length), redirects, executable) : undefined;
        const substitutions = [...words, ...redirects].filter(pendingNested);
        const arithmeticExpansion = substitutions.some(containsArithmeticExpansion);
        const interpreter = executable !== undefined && ["sh", "bash", "python", "python3"].includes(executable);
        const otherInline = executable === "node" && command[1] === "-e";
        const externalScript = interpreter && command[1] !== undefined && command[1] !== null &&
          !command[1].startsWith("-");
        const nested = substitutions.length > 0 || redirects.some((r) => r.type !== "file_redirect") ||
          interpreter || executable === "eval" || otherInline;
        const output = redirects.flatMap((r) => {
          const op = r.children.find((child) => !child.isNamed)?.type;
          const target = r.childForFieldName("destination");
          if (!op || !op.includes(">") || !target) return [];
          const destination = staticPrefix(target).literal;
          return [{ destination, duplicatesDescriptor: op === ">&" && /^\d+-?$|^-$/.test(destination ?? "") }];
        });
        const last = redirects.at(-1);
        const displayEnd = Math.max(node.endIndex, last?.endIndex ?? 0);
        const raw = source.slice(node.startIndex, displayEnd);
        const redactable = words.map((word, index) => ({
          start: word.startIndex - node.startIndex, end: word.endIndex - node.startIndex, prefix: parts[index].prefix,
        }));
        const omit = nested || !!unsupported || isDatabaseProvider(executable) || (words.length === 0 &&
          (node.type === "test_command" || node.childForFieldName("body") !== null)) ||
          redirects.some((r) => /[a-z][a-z0-9+.-]*:\/\/[^/?#@\s]+@/i.test(r.text));
        const rendered = omit ? "<shell text omitted>" : redactCommand(raw, redactable);
        const location = { line: node.startPosition.row + 1, column: node.startPosition.column + 1 };
        const provider = classifyProvider(executable, command.slice(1), assignments);
        const local = classifyLocal(executable === "aws" || provider || functionBinding !== undefined ? [] : command, output);
        const profile = assignments.get("AWS_PROFILE");
        findings.push((async () => {
          if (body) {
            try {
              const inner = body.language === "python"
                ? await analyzePython(body.text) : await analyzeShellSource(body.text, depth + 1);
              if (!output.length) return inner.map((entry) => ({
                ...entry, ...originalPosition(source, body.offset, entry.line, entry.column),
              }));
              return [
                { ...location, command: "<shell text omitted>", ...local, source: "shell redirect" },
                ...inner.map((entry) => ({ ...entry, ...originalPosition(source, body.offset, entry.line, entry.column) })),
              ];
            } catch (error) {
              if (!(error instanceof InputError)) throw error;
              const position = originalPosition(source, body.offset, error.line, error.column);
              throw new InputError(error.message, position.line, position.column);
            }
          }
          let effect: Pick<Finding, "class" | "reason" | "source" | "context">;
          if (functionBinding !== undefined) {
            const body = functionBinding && (await Promise.all(functionBinding)).flat();
            const severity = body?.length ? body.reduce<number>((worst, entry) =>
              Math.min(worst, classes.indexOf(entry.class)), classes.length - 1) : undefined;
            const classification = severity === undefined ? "UNKNOWN" : classes[severity];
            effect = { class: classification, reason: `calls ${functionName} (${classification})`, source: "shell function" };
          } else {
            effect = executable === "aws" ? await classifyAws(command, profile) : provider ?? { ...local, source: "shell" };
          }
          if (classes.indexOf(local.class) < classes.indexOf(effect.class)) effect = { ...effect, ...local, source: "shell" };
          const nestedEffectIsModeled = !unsupported && substitutions.length > 0 && !arithmeticExpansion &&
            !interpreter && executable !== "eval" && !otherInline &&
            redirects.every((redirect) => redirect.type === "file_redirect") && effect.source === "shell" &&
            (effect.class === "LOCAL" ||
              (effect.class === "READ-ONLY" && isNestedReadOnlyCommand(executable)));
          if (effect.class !== "DANGEROUS" && effect.class !== "SENSITIVE") {
            if (unsupported || (nested && !nestedEffectIsModeled)) effect = {
              class: "UNKNOWN",
              reason: unsupported ?? (externalScript ? "runs another file" :
                otherInline ? "inline code not analysed" :
                  arithmeticExpansion ? "arithmetic expansion is not analysed" : "nested code is not yet analysed"),
              source: "shell",
            };
            else if (node.type === "variable_assignment" && effect.class === "READ-ONLY") {
              effect = { class: "LOCAL", reason: "sets a shell variable", source: "shell" };
            }
          }
          return [{ ...location, command: rendered, ...effect }];
        })());
        for (const node of substitutions) visitSubstitutions(node);
      }

      visit(root);
      return (await Promise.all(findings)).flat();
  });
}
