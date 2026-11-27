import type { Classification } from "./report.ts";

type Word = string | null;
type Effect = Readonly<{ class: Classification; reason: string }>;

const reads = new Set([
  "echo", "printf", "true", "false", ":", "pwd", "cd", "test", "[",
  "grep", "cat", "dirname", "basename", "cut", "tr", "jq", "sleep",
  // Report to standard output only; none has an option that writes a file or runs a command.
  "head", "tail", "wc", "bc", "seq", "tac", "rev", "nl", "ls", "stat", "df", "du", "realpath", "readlink",
  "mountpoint", "which", "type", "id", "whoami", "uname", "nproc", "uptime", "free", "ps", "pgrep", "wait",
  "diff", "cmp", "comm", "column", "expand", "unexpand", "fmt", "fold", "join", "paste", "strings",
  "md5sum", "sha1sum", "sha256sum", "sha512sum", "printenv", "groups", "whereis", "yes", "netstat",
]);
const hostnameQueries = new Set([
  "-f", "--fqdn", "-s", "--short", "-i", "--ip-address", "-I", "--all-ip-addresses", "-d", "--domain", "-A", "--all-fqdns",
]);
const findWrites = new Set(["-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"]);
const readOnly: Effect = { class: "READ-ONLY", reason: "no filesystem or remote write identified" };

/** An awk call whose program is a literal that cannot write a file, open a pipe or run a command. */
function awkOnlyPrints(args: readonly Word[]): boolean {
  let index = 0;
  while (index < args.length) {
    const word = args[index];
    if (word === "-F" || word === "-v") index += 2;
    else if (word !== null && /^-[Fv]./.test(word)) index++;
    else break;
  }
  const program = args[index];
  return typeof program === "string" && !program.startsWith("-") && !/system|getline|[|>]/.test(program);
}

/** One sed script that is a substitution, delete or print with no file-writing or command flag. */
function sedScriptOnlyEdits(script: string): boolean {
  if (/^(?:\d+|\$)?(?:,(?:\d+|\$))?[dp]$/.test(script) || /^\/(?:[^/\\]|\\.)*\/[dp]$/.test(script)) return true;
  const delimiter = script[1];
  if (script[0] !== "s" || !delimiter || /[\w\s\\]/.test(delimiter)) return false;
  const parts = [""];
  for (let index = 2; index < script.length; index++) {
    const character = script[index];
    if (character === "\\") parts[parts.length - 1] += character + (script[++index] ?? "");
    else if (character === delimiter) parts.push("");
    else parts[parts.length - 1] += character;
  }
  return parts.length === 3 && /^[gpIi0-9]*$/.test(parts[2]);
}

/** A sed call that filters its input to standard output: no in-place edit, no script from a file. */
function sedOnlyFilters(args: readonly Word[]): boolean {
  const scripts: string[] = [];
  let index = 0;
  for (; index < args.length; index++) {
    const word = args[index];
    if (word === null) return false;
    if (word === "-e") {
      const script = args[++index];
      if (typeof script !== "string") return false;
      scripts.push(script);
    } else if (!["-n", "-E", "-r", "--quiet", "--silent"].includes(word)) break;
  }
  if (!scripts.length) {
    const script = args[index++];
    if (typeof script !== "string" || script.startsWith("-")) return false;
    scripts.push(script);
  }
  // sed accepts options after its operands, so every remaining word must be a plain file name.
  const files = args.slice(index);
  return files.every((word) => word !== null && !word.startsWith("-")) && scripts.every(sedScriptOnlyEdits);
}

/**
 * Builtins and tools that are safe only in some forms. Returns the effect for a recognised form,
 * "unproven" for a form that is not, and undefined when the command is not one of them.
 */
function constrainedForm(name: string, args: readonly Word[]): Effect | "unproven" | undefined {
  switch (name) {
    case "exit": case "break": case "continue":
      return args.length <= 1 ? readOnly : "unproven";
    case "set": return { class: "LOCAL", reason: "changes shell options or positional parameters" };
    case "read": return { class: "LOCAL", reason: "reads input into shell variables" };
    case "mktemp": return { class: "LOCAL", reason: "creates a temporary file" };
    case "command": return args.length === 2 && (args[0] === "-v" || args[0] === "-V") ? readOnly : "unproven";
    case "kill": return args.length === 2 && args[0] === "-0" ? readOnly : "unproven";
    case "hostname": return args.every((word) => word !== null && hostnameQueries.has(word)) ? readOnly : "unproven";
    case "uniq":
      return args.every((word) => word !== null) && args.filter((word) => !word?.startsWith("-")).length <= 1
        ? readOnly : "unproven";
    case "find": return args.every((word) => word !== null && !findWrites.has(word)) ? readOnly : "unproven";
    case "awk": return awkOnlyPrints(args) ? readOnly : "unproven";
    case "sed": return sedOnlyFilters(args) ? readOnly : "unproven";
    default: return undefined;
  }
}
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
    return { class: "MUTATING", reason: "redirect can write to a network socket" };
  }
  if (name === null) return { class: "UNKNOWN", reason: "command is in a variable" };
  const executable = name?.slice(name.lastIndexOf("/") + 1);
  if (executable && (deletes.has(executable) || (executable === "find" && args.includes("-delete")))) {
    return { class: "MUTATING", reason: "can delete or destroy local data" };
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
  const constrained = name === undefined ? undefined : constrainedForm(name, args);
  if (name !== undefined && !reads.has(name) && name !== "sort" && !(executable && writes.has(executable)) &&
      !numericControl && !dateOptions && (constrained === undefined || constrained === "unproven")) {
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
  if (constrained && constrained !== "unproven") return constrained;
  if (name === "shift") return { class: "LOCAL", reason: "changes shell positional parameters" };
  if (name === "printf" && args[0] === "-v") {
    return { class: "LOCAL", reason: "writes to a shell variable" };
  }
  return readOnly;
}
