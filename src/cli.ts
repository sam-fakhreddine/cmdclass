#!/usr/bin/env node
import { readFile, stat } from "node:fs/promises";
import { parseArgs } from "node:util";
import { formatReport, oneLine, reportExitCode } from "./report.ts";
import { analyzeFile, inputErrorMessage } from "./input.ts";
import { folderExitCode, formatFolderReport, scanFolder } from "./folder.ts";
import { readSnapshot, updateSnapshot } from "./aws-data.ts";

const help = `Usage: cmdclass [--json] [--] FILE_OR_DIRECTORY
Statically reports command effects; it never runs the script or certifies safety.
Sensitive detection does not infer that arbitrary files or variables hold secrets.
Directory scans recurse over .sh, .bash, .py and supported extensionless scripts.
Hidden entries, dependency/cache directories, secrets/credentials directories,
and symbolic links inside a directory scan are skipped.
  -h, --help         Show this help
  --json             Print a JSON report
  --update-aws-data   Refresh the local AWS Service Reference snapshot
  --version           Print the package version and AWS snapshot metadata

Exit codes: 0 read-only or no findings, 1 dangerous/unknown/local, 3 sensitive
only (or with reads), 2 usage or scan error (takes precedence in a folder scan).
`;

async function packageVersion(): Promise<string> {
  const manifest: unknown = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  if (!manifest || typeof manifest !== "object" || !("version" in manifest) ||
      typeof manifest.version !== "string" || !manifest.version) {
    throw new Error("package version is missing or invalid");
  }
  return manifest.version;
}

async function main(args: string[]): Promise<number> {
  if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
    process.stdout.write(help);
    return 0;
  }
  if (args.length === 1 && (args[0] === "--update-aws-data" || args[0] === "--version")) {
    try {
      const version = await packageVersion();
      if (args[0] === "--update-aws-data") await updateSnapshot();
      const snapshot = await readSnapshot();
      process.stdout.write(`cmdclass ${oneLine(version)}; AWS snapshot ${snapshot.date} sha256 ${snapshot.sha256}\n`);
      return 0;
    } catch (error) {
      process.stderr.write(`cmdclass: version or AWS data operation failed${error instanceof Error ? `: ${error.message}` : ""}\n`);
      return 2;
    }
  }
  let path: string;
  let json: boolean;
  try {
    const { values, positionals } = parseArgs({
      args, options: { json: { type: "boolean" } }, allowPositionals: true,
    });
    if (positionals.length !== 1) throw new Error("expected one input path");
    [path] = positionals;
    json = values.json === true;
  } catch {
    process.stderr.write("cmdclass: expected one file or directory; see --help\n");
    return 2;
  }
  let version: string;
  try {
    version = await packageVersion();
  } catch (error) {
    process.stderr.write(`cmdclass: could not read package version${error instanceof Error ? `: ${oneLine(error.message)}` : ""}\n`);
    return 2;
  }
  try {
    if ((await stat(path)).isDirectory()) {
      const result = await scanFolder(path);
      process.stdout.write(json ? `${JSON.stringify({ ...result, tool_version: version })}\n`
        : `cmdclass ${oneLine(version)}\n${formatFolderReport(result, false)}`);
      if (!json) {
        for (const error of result.errors) {
          process.stderr.write(`cmdclass: ${oneLine(error.path)}: ${oneLine(error.message)}\n`);
        }
      }
      return folderExitCode(result);
    }
    const report = await analyzeFile(path);
    if (!report) throw new Error("explicit input was skipped");
    process.stdout.write(json ? `${JSON.stringify({ ...report, tool_version: version })}\n`
      : `cmdclass ${oneLine(version)}\n${formatReport(report, false)}`);
    return reportExitCode(report);
  } catch (error) {
    process.stderr.write(`cmdclass: ${inputErrorMessage(error, "could not read or analyse the input")}\n`);
    return 2;
  }
}

process.exitCode = await main(process.argv.slice(2));
