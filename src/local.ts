import type { Classification } from "./report.ts";

type Word = string | null;
type Effect = Readonly<{ class: Classification; reason: string }>;

const reads = new Set([
  "echo", "printf", "true", "false", ":", "pwd", "cd", "test", "[",
  "grep", "cat", "dirname", "basename", "cut", "tr", "jq", "sleep",
]);
const nestedReadOnlyCommands = new Set([
  "echo", "true", "false", ":", "pwd", "test", "[", "grep", "cat",
  "dirname", "basename", "cut", "tr", "jq", "sleep", "sort",
]);
const deletes = new Set(["rm", "shred", "unlink", "rmdir", "truncate"]);
const writes = new Set(["cp", "mv", "mkdir", "touch", "chmod", "tee"]);

interface OutputRedirect {
  destination: Word;
  duplicatesDescriptor: boolean;
}

export function isNestedReadOnlyCommand(name: string | undefined): boolean {
  return name !== undefined && nestedReadOnlyCommands.has(name);
}

export function classifyLocal(words: readonly Word[], redirects: readonly OutputRedirect[]): Effect {
  const [name, ...args] = words;
  if (redirects.some(({ destination, duplicatesDescriptor }) =>
    !duplicatesDescriptor && (destination?.startsWith("/dev/tcp/") || destination?.startsWith("/dev/udp/")))) {
    return { class: "DANGEROUS", reason: "redirect can write to a network socket" };
  }
  if (name === null) return { class: "UNKNOWN", reason: "command is in a variable" };
  const executable = name?.slice(name.lastIndexOf("/") + 1);
  if (executable && (deletes.has(executable) || (executable === "find" && args.includes("-delete")))) {
    return { class: "DANGEROUS", reason: "can delete or destroy local data" };
  }
  if (name === "source" || name === ".") {
    return { class: "UNKNOWN", reason: "runs another file" };
  }
  if (name?.startsWith("./") && /\.(?:sh|py)$/.test(name)) {
    return { class: "UNKNOWN", reason: "runs another file" };
  }
  if (name === "sort" && args.some((arg) => arg === null ||
      arg === "-o" || arg === "--output" || arg?.startsWith("--output=") ||
      (arg?.startsWith("-") && !arg.startsWith("--") && arg.slice(1).includes("o")))) {
    return { class: "UNKNOWN", reason: "sort output file is not analysed" };
  }
  const numericControl = (name === "return" || name === "shift") &&
    args.length <= 1 && (args.length === 0 || (typeof args[0] === "string" && /^\d+$/.test(args[0])));
  const dateOptions = name === "date" && args.length <= 2 &&
    args.every((arg) => typeof arg === "string" &&
      (["-u", "--utc", "--universal"].includes(arg) || arg.startsWith("+"))) &&
    args.filter((arg) => arg?.startsWith("+")).length <= 1 &&
    args.filter((arg) => arg && ["-u", "--utc", "--universal"].includes(arg)).length <= 1;
  // Only accept exact spellings for builtins: a path could name an unrelated executable.
  if (name !== undefined && !reads.has(name) && name !== "sort" && !(executable && writes.has(executable)) &&
      !numericControl && !dateOptions) {
    return { class: "UNKNOWN", reason: "command is not supported by the local rules" };
  }
  if (name === "printf" && args[0] === null) {
    return { class: "UNKNOWN", reason: "printf options are dynamic" };
  }
  if (redirects.some((r) => !r.duplicatesDescriptor && r.destination === null)) {
    return { class: "UNKNOWN", reason: "output redirect target is dynamic" };
  }
  if (redirects.some((r) => !r.duplicatesDescriptor && r.destination !== "/dev/null")) {
    return { class: "LOCAL", reason: "writes to a local output redirect" };
  }
  if (executable && writes.has(executable)) return { class: "LOCAL", reason: "changes local data" };
  if (name === "shift") return { class: "LOCAL", reason: "changes shell positional parameters" };
  if (name === "printf" && args[0] === "-v") {
    return { class: "LOCAL", reason: "writes to a shell variable" };
  }
  return { class: "READ-ONLY", reason: "no filesystem or remote write identified" };
}
