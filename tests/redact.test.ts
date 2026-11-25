import assert from "node:assert/strict";
import { describe, test } from "node:test";
import fc from "fast-check";
import { propertyOptions } from "./property-options.ts";
import { redactCommand } from "../src/redact.ts";
import { buildReport, formatReport } from "../src/report.ts";

function commandFrom(words: readonly [raw: string, prefix: string][]) {
  let next = 0;
  return redactCommand(words.map(([raw]) => raw).join(" "), words.map(([raw, prefix]) => {
    const start = next;
    next += raw.length + 1;
    return { start, end: start + raw.length, prefix };
  }));
}

test("redacts separate, joined, and assignment values without losing argument names", () => {
  assert.equal(commandFrom([
    ["AWS_SECRET_ACCESS_KEY=$VALUE", "AWS_SECRET_ACCESS_KEY="],
    ["example", "example"],
    ["'--password'", "--password"],
    ["'example value'", "example value"],
    ['--client-secret="example value"', "--client-secret=example value"],
    ["https://example.invalid", "https://example.invalid"],
  ]), "AWS_SECRET_ACCESS_KEY=<redacted> example '--password' <redacted> --client-secret=<redacted> https://example.invalid");
});

describe("TestProperties", () => {
  // Catches: Confidentiality (SAFETY) - command rendering exposes a synthetic credential.
  test("keeps credential markers out of both report formats across token shapes", () => {
    const suffix = fc.array(fc.constantFrom(..."-_0123456789abcdefghijklmnopqrstuvwxyz"), { minLength: 1, maxLength: 24 });
    fc.assert(fc.property(
      suffix,
      fc.constantFrom("--password", "--token", "--secret", "--client-secret", "--access-key", "--secret-access-key"),
      fc.boolean(),
      (characters, flag, joined) => {
        const secret = `synthetic-fixture-${characters.join("")}`;
        const args: [string, string][] = joined
          ? [[`${flag}=${secret}`, `${flag}=${secret}`]]
          : [[flag, flag], [`'${secret}'`, secret]];
        const command = commandFrom([
          ["tool", "tool"],
          ...args,
          [`https://example:${secret}@example.invalid`, `https://example:${secret}@example.invalid`],
        ]);
        const report = buildReport([{
          line: 1, column: 1, command, class: "UNKNOWN", reason: "test example", source: "fixture",
        }]);
        for (const json of [true, false]) {
          assert.ok(!formatReport(report, json).includes(secret));
        }
      }
    ), propertyOptions);
  });
});
