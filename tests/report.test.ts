import assert from "node:assert/strict";
import { describe, test } from "node:test";
import fc from "fast-check";
import { propertyOptions } from "./property-options.ts";
import { buildReport, formatReport, reportExitCode } from "../src/report.ts";
import type { Classification, Finding } from "../src/report.ts";

function finding(line: number, column: number, name: string, classification: Classification): Finding {
  return { line, column, command: name, class: classification, reason: "fixture", source: "fixture" };
}

test("formats one report, grouped by severity, with stable source ordering", () => {
  const report = buildReport([
    finding(1, 1, "echo ok", "READ-ONLY"),
    finding(2, 7, "rm later", "MUTATING"),
    finding(2, 1, "rm first", "MUTATING"),
    finding(2, 1, "rm inner", "MUTATING"),
  ]);
  assert.equal(formatReport(report, false), [
    "MUTATING   2:1  rm first  fixture",
    "MUTATING   2:1  rm inner  fixture",
    "MUTATING   2:7  rm later  fixture",
    "READ-ONLY  1:1  echo ok  fixture",
    "summary: 1 read-only, 0 local, 0 unknown, 0 sensitive, 3 mutating",
    "",
  ].join("\n"));
  assert.deepEqual(JSON.parse(formatReport(report, true)), report);
});

test("does not print raw control characters from the script to the terminal", () => {
  const report = buildReport([finding(1, 1, "echo '\n\u001b\u202e'", "READ-ONLY")]);
  assert.match(formatReport(report, false), /\\n\\u001b\\u\{202e\}/);
});

describe("TestProperties", () => {
  // Catches: Determinism (INVARIANT) - the input order changes findings at distinct positions.
  test("order is independent of collection order at distinct positions", () => {
    fc.assert(fc.property(
      fc.array(fc.constantFrom<Classification>("READ-ONLY", "LOCAL", "UNKNOWN", "SENSITIVE", "MUTATING"),
        { maxLength: 40 }),
      (states) => {
        const findings = states.map((classification, index) =>
          finding(index + 1, 1, "example", classification));
        for (const json of [true, false]) {
          assert.equal(formatReport(buildReport(findings), json),
            formatReport(buildReport([...findings].reverse()), json));
        }
      },
    ), propertyOptions);
  });

  // Catches: Integrity (SAFETY) - a finding mix yields the wrong exit code.
  test("computes exit codes for all subsets of the five classes", () => {
    const example: [Classification, number][] = [
      ["READ-ONLY", 0], ["LOCAL", 1], ["UNKNOWN", 1], ["SENSITIVE", 3], ["MUTATING", 1],
    ];
    for (let mask = 0; mask < 2 ** example.length; mask++) {
      const selected = example.filter((_, index) => mask & (1 << index));
      const report = buildReport(selected.map(([classification], index) =>
        finding(index + 1, 1, "example", classification)));
      const codes = selected.map(([, code]) => code);
      assert.equal(reportExitCode(report), codes.includes(1) ? 1 : codes.includes(3) ? 3 : 0);
    }
  });
});
