// Checks the shell rules against the GTFOBins catalogue of binaries that can be abused to run
// commands or write files. Every example for those abuses must come out as something other than
// READ-ONLY, and must produce at least one finding.
//
// Usage: node scripts/crosscheck-gtfobins.ts <path-to-api.json>
// Get the data from https://gtfobins.org/api.json. It is GPL-3.0, so it is not bundled here.
// The file is read as JSON only; nothing in it is executed.
import { readFileSync } from "node:fs";
import { analyzeShell } from "../src/shell.ts";
import { InputError } from "../src/syntax.ts";

interface Example { code?: unknown }
interface Executable { alias?: string; functions?: Record<string, Example[]> }

const writesOrRuns = new Set([
  "shell", "command", "reverse-shell", "bind-shell", "file-write", "upload", "download", "library-load",
]);
const runsCode = new Set(["shell", "command", "reverse-shell", "bind-shell", "library-load"]);
const maxAliasHops = 5;

const [path] = process.argv.slice(2);
if (!path) {
  process.stderr.write("usage: node scripts/crosscheck-gtfobins.ts <path-to-api.json>\n");
  process.exit(2);
}
const executables: Record<string, Executable> = JSON.parse(readFileSync(path, "utf8")).executables;
if (!executables || typeof executables !== "object") throw new Error("api.json has no executables map");

const totals = { executables: 0, examples: 0, unparsable: 0 };
const problems: string[] = [];
for (const name of Object.keys(executables).sort()) {
  let entry: Executable | undefined = executables[name];
  for (let hop = 0; entry?.alias && hop < maxAliasHops; hop++) entry = executables[entry.alias];
  if (!entry?.functions) continue;
  totals.executables++;
  for (const [abuse, examples] of Object.entries(entry.functions)) {
    if (!writesOrRuns.has(abuse)) continue;
    for (const example of examples) {
      const code = String(example.code ?? "");
      totals.examples++;
      let classes: string[];
      try {
        classes = (await analyzeShell(code)).map((finding) => finding.class);
      } catch (error) {
        // A snippet that is not valid shell would be a scan error in a real run, not a missed effect.
        if (!(error instanceof InputError)) throw error;
        totals.unparsable++;
        continue;
      }
      const shown = `${name} [${abuse}] ${code.replace(/\s+/g, " ").slice(0, 100)}`;
      if (!classes.length) problems.push(`no finding   ${shown}`);
      else if (classes.every((value) => value === "READ-ONLY")) problems.push(`READ-ONLY    ${shown}`);
      else if (runsCode.has(abuse) && classes.every((value) => value === "READ-ONLY" || value === "LOCAL")) {
        problems.push(`only LOCAL   ${shown}`);
      }
    }
  }
}
process.stdout.write(`${JSON.stringify({ ...totals, problems: problems.length })}\n${problems.join("\n")}${
  problems.length ? "\n" : ""}`);
process.exit(problems.length ? 1 : 0);
