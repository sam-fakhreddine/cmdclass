import assert from "node:assert/strict";
import { describe, test } from "node:test";
import fc from "fast-check";
import { propertyOptions } from "./property-options.ts";
import { classifyLocal } from "../src/local.ts";

test("classifies only constrained return, shift and date forms", () => {
  const rows = [
    [["return"], "READ-ONLY"],
    [["return", "1"], "READ-ONLY"],
    [["return", null], "UNKNOWN"],
    [["return", "1", "2"], "UNKNOWN"],
    [["/usr/bin/return", "0"], "UNKNOWN"],
    [["shift"], "LOCAL"],
    [["shift", "2"], "LOCAL"],
    [["shift", null], "UNKNOWN"],
    [["shift", "-1"], "UNKNOWN"],
    [["date"], "READ-ONLY"],
    [["date", "-u", "+%Y-%m-%d"], "READ-ONLY"],
    [["date", "--utc"], "READ-ONLY"],
    [["date", "-s", "example"], "UNKNOWN"],
    [["date", "--set=example"], "UNKNOWN"],
    [["date", "01011234"], "UNKNOWN"],
    [["date", null], "UNKNOWN"],
    [["/usr/bin/date"], "UNKNOWN"],
  ] as const;
  for (const [words, expected] of rows) assert.equal(classifyLocal(words, []).class, expected, JSON.stringify(words));
  assert.equal(classifyLocal(["date"], [{ destination: "output", duplicatesDescriptor: false }]).class, "LOCAL");
  assert.equal(classifyLocal(["return"], [{ destination: null, duplicatesDescriptor: false }]).class, "UNKNOWN");
  assert.equal(classifyLocal(["shift"], [
    { destination: "/dev/tcp/example.invalid/123", duplicatesDescriptor: false },
  ]).class, "DANGEROUS");
});

test("classifies output-only shell utilities while guarding sort file output", () => {
  for (const command of ["grep", "cat", "dirname", "basename", "cut", "tr", "jq", "sleep"]) {
    assert.equal(classifyLocal([command, "--dynamic", null], []).class, "READ-ONLY", command);
    assert.equal(classifyLocal([command], [
      { destination: "output.txt", duplicatesDescriptor: false },
    ]).class, "LOCAL", command);
  }
  for (const words of [
    ["sort", "input.txt"],
    ["sort", "-r", "input.txt"],
    ["sort", "--unique", "input.txt"],
  ] as const) assert.equal(classifyLocal(words, []).class, "READ-ONLY", words.join(" "));

  for (const words of [
    ["sort", "-o", "output.txt", "input.txt"],
    ["sort", "-ooutput.txt", "input.txt"],
    ["sort", "-ruo", "output.txt", "input.txt"],
    ["sort", "--output=output.txt", "input.txt"],
    ["sort", "--output", "output.txt", "input.txt"],
    ["sort", null, "input.txt"],
  ] as const) assert.equal(classifyLocal(words, []).class, "UNKNOWN", JSON.stringify(words));

  for (const command of ["awk", "sed", "custom"]) {
    assert.equal(classifyLocal([command, "script"], []).class, "UNKNOWN", command);
  }
});

test("classifies explicit writes and preserves destructive commands through redirects", () => {
  const file = { destination: "out.txt", duplicatesDescriptor: false };
  assert.equal(classifyLocal(["echo", "ok"], [file]).class, "LOCAL");
  assert.equal(classifyLocal(["/bin/rm", "out.txt"], [file]).class, "DANGEROUS");
  assert.equal(classifyLocal(["find", ".", "-delete"], []).class, "DANGEROUS");
  assert.equal(classifyLocal(["printf", "-v", "out", "%s", "ok"], []).class, "LOCAL");
  assert.equal(classifyLocal([null], [
    { destination: "/dev/tcp/example.invalid/123", duplicatesDescriptor: false },
  ]).class, "DANGEROUS");
  assert.equal(classifyLocal(["echo", "ok"], [
    { destination: "/dev/null", duplicatesDescriptor: false },
    { destination: "1", duplicatesDescriptor: true },
  ]).class, "READ-ONLY");
});

describe("TestProperties", () => {
  // Catches: Integrity (SAFETY) - arbitrary date options are mistaken for harmless reads.
  test("does not grant read-only status to unrecognized date options", () => {
    fc.assert(fc.property(fc.string({ minLength: 1, maxLength: 24 }), (suffix) => {
      const option = `--set=${suffix}`;
      assert.equal(classifyLocal(["date", option], []).class, "UNKNOWN");
    }), propertyOptions);
  });

  // Catches: Integrity (SAFETY) - unsupported executables are mistaken for known builtins.
  test("never infers read-only from unknown command spelling or argument content", () => {
    for (const command of [null, "tool", "./echo", "source", "."]) {
      for (const arg of ["echo", "rm", "--help", null]) {
        assert.equal(classifyLocal([command, arg], []).class, "UNKNOWN");
      }
    }
  });

  // Catches: Integrity (SAFETY) - a sort output option is overlooked.
  test("keeps all sort output-file spellings UNKNOWN", () => {
    fc.assert(fc.property(fc.string({ minLength: 1, maxLength: 30 }), (file) => {
      assert.equal(classifyLocal(["sort", "-o", file], []).class, "UNKNOWN");
      assert.equal(classifyLocal(["sort", `-o${file}`], []).class, "UNKNOWN");
      assert.equal(classifyLocal(["sort", `--output=${file}`], []).class, "UNKNOWN");
    }), propertyOptions);
  });
});
