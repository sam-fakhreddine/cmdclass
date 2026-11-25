import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { test } from "node:test";

test("targeted regression tests reject four deliberate faults in a disposable copy", () => {
  const project = process.cwd();
  const temp = mkdtempSync(resolve("dist", ".mutations-"));
  const { NODE_TEST_CONTEXT: _runnerContext, ...env } = process.env;
  const cases = [
    { file: "src/shell.ts", before: "for (const [index, child] of children.entries())",
      after: "for (const [index, child] of children.entries()) if (index === 0)",
      suite: "shell", name: "finds modeled commands" },
    { file: "src/aws/operations.ts", before: "return unknownAws(`not in AWS data snapshot ${snapshot.date}`);",
      after: 'return { class: "READ-ONLY", source: "mutation", reason: "mutation" };',
      suite: "aws", name: "preserves the worst effect" },
    { file: "src/redact.ts", before: "return output + source.slice(cursor);",
      after: "return source;",
      suite: "redact", name: "keeps credential markers out" },
    { file: "src/syntax.ts", before: "if (root.hasError) {", after: "if (false) {",
      suite: "shell", name: "missing syntax suppresses all findings" },
  ];
  try {
    for (const name of ["src", "tests", "data", "package.json"]) {
      cpSync(join(project, name), join(temp, name), { recursive: true });
    }
    symlinkSync(join(project, "node_modules"), join(temp, "node_modules"), "dir");
    for (const fault of cases) {
      const path = join(temp, fault.file);
      const original = readFileSync(path, "utf8");
      assert.equal(original.split(fault.before).length, 2, `Mutation target changed: ${fault.file}`);
      writeFileSync(path, original.replace(fault.before, fault.after));
      try {
        const run = spawnSync(process.execPath, ["--test", "--test-name-pattern", fault.name,
          `tests/${fault.suite}.test.ts`], { cwd: temp, encoding: "utf8", env });
        if (run.error) throw run.error;
        assert.equal(run.status, 1, `${fault.file}\n${run.stdout}\n${run.stderr}`);
        const failure = run.stdout.split("\n").find((line) => line.startsWith("✖") && line.includes(fault.name));
        assert.ok(failure, `${fault.file} did not fail the intended test:\n${run.stdout}\n${run.stderr}`);
        assert.match(run.stdout, /AssertionError/);
      } finally {
        writeFileSync(path, original);
      }
    }
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});
