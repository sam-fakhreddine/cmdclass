import { constants } from "node:fs";
import { open, type FileHandle } from "node:fs/promises";
import { extname } from "node:path";
import { analyzePython } from "./python.ts";
import { buildReport } from "./report.ts";
import { analyzeShell } from "./shell.ts";
import { InputError, maxInputBytes } from "./syntax.ts";

type Language = "shell" | "python";

function languageFromShebang(firstLine: string): Language | undefined {
  const interpreter = /^#![ \t]*(?:\S*\/env[ \t]+(?:-S[ \t]+)?|(?:\S*\/)?)([^\s/]+)(?=\s|$)/
    .exec(firstLine)?.[1];
  if (interpreter === "bash" || interpreter === "sh") return "shell";
  if (interpreter && /^python(?:[23](?:\.\d+)?)?$/.test(interpreter)) return "python";
}

async function fill(handle: FileHandle, buffer: Buffer, length = 0): Promise<number> {
  while (length < buffer.length) {
    const { bytesRead } = await handle.read(buffer, length, buffer.length - length, length);
    if (!bytesRead) break;
    length += bytesRead;
  }
  return length;
}

async function readInput(path: string, discovered: boolean) {
  const extension = extname(path).toLowerCase();
  const detect = discovered && !extension;
  const language = extension === ".py" ? "python" : "shell";
  if (discovered && !detect && ![".sh", ".bash", ".py"].includes(extension)) return;

  const handle = await open(path, constants.O_RDONLY | constants.O_NONBLOCK |
    (discovered ? constants.O_NOFOLLOW : 0));
  try {
    if (!(await handle.stat()).isFile()) throw new InputError("input must be a regular file", 1, 1);
    let detected: Language | undefined;
    let prefix: Buffer | undefined;
    let length = 0;
    if (detect) {
      prefix = Buffer.alloc(512);
      length = await fill(handle, prefix);
      const newline = prefix.subarray(0, length).indexOf(10);
      // Do not guess from a truncated interpreter line.
      if (newline === -1 && length === prefix.length) return;
      detected = languageFromShebang(prefix.toString("utf8", 0, newline < 0 ? length : newline));
      if (!detected) return;
    }

    const bytes = Buffer.alloc(maxInputBytes + 1);
    prefix?.copy(bytes, 0, 0, length);
    length = await fill(handle, bytes, length);
    if (length > maxInputBytes) throw new InputError("input exceeds the 1 MiB analysis limit", 1, 1);
    const source = bytes.toString("utf8", 0, length);
    const shebang = source.startsWith("#!") ? source.split("\n", 1)[0] : "";
    const shellShebang = discovered
      ? languageFromShebang(shebang) === "shell"
      : /(?:[/ \t])(?:bash|sh)(?:[ \t\r]|$)/.test(shebang);
    if ((detected ?? language) === "shell" &&
        ([".ps1", ".zsh", ".fish"].includes(extension) || (shebang && !shellShebang))) {
      throw new InputError("unsupported shell", 1, 1);
    }
    return { source, language: detected ?? language };
  } finally {
    await handle.close();
  }
}

export async function analyzeFile(path: string, discovered = false) {
  const input = await readInput(path, discovered);
  if (!input) return;
  return buildReport(await (input.language === "python" ? analyzePython(input.source) : analyzeShell(input.source)));
}

export function inputErrorMessage(error: unknown, fallback: string): string {
  return error instanceof InputError
    ? `line ${error.line}, column ${error.column}: ${error.message}`
    : fallback;
}
