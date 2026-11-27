import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { analyzeFile, inputErrorMessage } from "./input.ts";
import { type Report, emptySummary, formatReport, formatSummary, oneLine, reportExitCode, classes } from "./report.ts";

// cdk.out is CDK build output: bundled assets carry vendored copies of dependencies such as the AWS SDK.
const excludedDirectories = new Set(["node_modules", "__pycache__", "cdk.out", "secrets", "credentials"]);
type FileReport = { path: string; report: Report };
type ScanError = { path: string; message: string };

export async function scanFolder(root: string) {
  const files: FileReport[] = [];
  const errors: ScanError[] = [];
  const summary = emptySummary();
  // Use an explicit stack instead of holding a directory handle open at every depth.
  const work = [{ relative: "", directory: true }];
  while (work.length) {
    const { relative, directory } = work.pop()!;
    const path = join(root, relative);
    if (directory) {
      try {
        const entries = await readdir(path, { withFileTypes: true });
        entries.sort((a, b) => a.name < b.name ? 1 : a.name === b.name ? 0 : -1);
        for (const entry of entries) {
          if (entry.name.startsWith(".")) continue;
          if (entry.isFile() || (entry.isDirectory() && !excludedDirectories.has(entry.name))) {
            work.push({
              relative: relative ? `${relative}/${entry.name}` : entry.name,
              directory: entry.isDirectory(),
            });
          }
        }
      } catch {
        errors.push({ path: relative || ".", message: "could not read directory" });
      }
    } else {
      try {
        const report = await analyzeFile(path, true);
        if (!report) continue;
        files.push({ path: relative, report });
        for (const classification of classes) summary[classification] += report.summary[classification];
      } catch (error) {
        errors.push({ path: relative, message: inputErrorMessage(error, "could not read or analyse the input") });
      }
    }
  }
  return { schema_version: 2 as const, files, errors, summary };
}

type FolderReport = Awaited<ReturnType<typeof scanFolder>>;

export function formatFolderReport(result: FolderReport, json: boolean): string {
  if (json) return `${JSON.stringify(result)}\n`;
  const files = result.files.map(({ path, report }) => `== ${oneLine(path)} ==\n${formatReport(report, false)}\n`);
  return `${files.join("")}scanned: ${result.files.length} file(s), ${result.errors.length} error(s)\n${
    formatSummary(result.summary)}\n`;
}

export function folderExitCode(result: FolderReport): number {
  return result.errors.length ? 2 : reportExitCode(result);
}
