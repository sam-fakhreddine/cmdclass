import { constants } from "node:fs";
import { open, type FileHandle } from "node:fs/promises";
import { stat } from "node:fs/promises";
import { dirname, extname, join, resolve } from "node:path";
import { analyzePython } from "./python.ts";
import { buildReport } from "./report.ts";
import type { LoadedModule, ModuleLoader } from "./python/modules.ts";
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

const repositoryMarker = ".git";
const projectMarkers = ["pyproject.toml", "setup.py", "setup.cfg"];
const maxAncestorLevels = 8;
const skippedSegments = new Set(["node_modules", "__pycache__", "secrets", "credentials", "site-packages"]);
const loadedModules = new Map<string, Promise<LoadedModule | undefined>>();
const importRoots = new Map<string, Promise<string[]>>();

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    // Missing or unreadable: either way it is not a marker we can rely on.
    return false;
  }
}

/**
 * The script's directory and its ancestors up to the repository root, or the outermost project
 * marker when there is no repository: a nested project can import from the one that contains it.
 * Only the script's directory when neither is found.
 */
function importRootsFor(directory: string): Promise<string[]> {
  let roots = importRoots.get(directory);
  if (!roots) {
    roots = (async () => {
      const chain: string[] = [];
      let outermost = 1;
      let current = directory;
      for (let level = 0; level < maxAncestorLevels; level++) {
        chain.push(current);
        if (await exists(join(current, repositoryMarker))) return chain;
        for (const marker of projectMarkers) if (await exists(join(current, marker))) outermost = chain.length;
        const parent = dirname(current);
        if (parent === current) break;
        current = parent;
      }
      return chain.slice(0, outermost);
    })();
    importRoots.set(directory, roots);
  }
  return roots;
}

function loadModuleFile(path: string): Promise<LoadedModule | undefined> {
  let loaded = loadedModules.get(path);
  if (!loaded) {
    loaded = readInput(path, true).then((input) => input?.language === "python"
      ? { key: path, source: input.source, package: path.endsWith("__init__.py"), loader: moduleLoader(path) }
      : undefined,
    // No readable module at this candidate path; the caller tries the next one.
    () => undefined);
    loadedModules.set(path, loaded);
  }
  return loaded;
}

/**
 * Finds project modules imported by the script at `scriptPath`. Module names are validated
 * identifiers, so a candidate path never leaves the script's directory chain.
 */
export function moduleLoader(scriptPath: string): ModuleLoader {
  const directory = dirname(resolve(scriptPath));
  return async (name) => {
    const match = /^(\.*)((?:[A-Za-z_]\w*)(?:\.[A-Za-z_]\w*)*)?$/.exec(name);
    if (!match || (!match[1] && !match[2])) return undefined;
    const segments = match[2] ? match[2].split(".") : [];
    if (segments.some((segment) => skippedSegments.has(segment))) return undefined;
    const roots = match[1]
      ? [resolve(directory, ...Array<string>(match[1].length - 1).fill(".."))]
      : await importRootsFor(directory);
    for (const root of roots) {
      const candidates = segments.length
        ? [`${join(root, ...segments)}.py`, join(root, ...segments, "__init__.py")]
        : [join(root, "__init__.py")];
      for (const candidate of candidates) {
        const loaded = await loadModuleFile(candidate);
        if (loaded) return loaded;
      }
    }
    return undefined;
  };
}

export async function analyzeFile(path: string, discovered = false) {
  const input = await readInput(path, discovered);
  if (!input) return;
  return buildReport(await (input.language === "python"
    ? analyzePython(input.source, { loadModule: moduleLoader(path) }) : analyzeShell(input.source)));
}

export function inputErrorMessage(error: unknown, fallback: string): string {
  return error instanceof InputError
    ? `line ${error.line}, column ${error.column}: ${error.message}`
    : fallback;
}
