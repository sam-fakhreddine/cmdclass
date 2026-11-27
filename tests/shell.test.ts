import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";
import fc from "fast-check";
import { propertyOptions } from "./property-options.ts";
import { analyzeShell, InputError } from "../src/shell.ts";

const { version } = JSON.parse(readFileSync("package.json", "utf8"));

function cli(path: string, json = false) {
  const result = spawnSync(process.execPath, ["src/cli.ts", ...(json ? ["--json"] : []), `tests/fixtures/shell/${path}`], {
    encoding: "utf8",
  });
  if (result.error) throw result.error;
  return result;
}

test("shell CLI matches the local-effects golden and agrees with JSON", () => {
  const text = cli("local-effects.sh");
  assert.equal(text.status, 1);
  assert.equal(text.stderr, "");
  assert.equal(text.stdout, [
    `cmdclass ${version}`,
    "MUTATING   4:1  rm -- example-output.txt  can delete or destroy local data",
    "LOCAL      3:1  printf '%s\\n' \"synthetic output\" > example-output.txt  writes to a local output redirect",
    "READ-ONLY  2:1  echo \"read-only text\"  no filesystem or remote write identified",
    "summary: 1 read-only, 1 local, 0 unknown, 0 sensitive, 1 mutating", "",
  ].join("\n"));
  const json = cli("local-effects.sh", true);
  assert.equal(json.status, text.status);
  assert.equal(JSON.parse(json.stdout).schema_version, 2);
  assert.deepEqual(JSON.parse(json.stdout).entries.map((x: { line: number }) => x.line), [4, 3, 2]);
});

test("empty scripts pass and missing syntax suppresses all findings in both modes", () => {
  for (const json of [true, false]) {
    const empty = cli("empty.sh", json);
    assert.equal(empty.status, 0);
    const malformed = cli("missing-substitution-end.sh", json);
    assert.equal(malformed.status, 2);
    assert.equal(malformed.stdout, "");
    assert.match(malformed.stderr, /^cmdclass: line \d+, column \d+: invalid shell syntax\n$/);
  }
});

test("the CLI rejects explicitly unsupported shells without emitting findings", () => {
  for (const script of ["unsupported.zsh", "unsupported.ps1"]) {
    for (const json of [true, false]) {
      const result = cli(script, json);
      assert.equal(result.status, 2);
      assert.equal(result.stdout, "");
      assert.equal(result.stderr, "cmdclass: line 1, column 1: unsupported shell\n");
    }
  }
});

test("shell CLI redacts synthetic values, including those in embedded code", () => {
  for (const json of [true, false]) {
    const result = cli("redaction.sh", json);
    assert.equal(result.status, 1);
    assert.equal(result.stderr, "");
    assert.doesNotMatch(result.stdout, /example-fixture-/);
    assert.match(result.stdout, /redacted/);
    assert.match(result.stdout, /custom --token <redacted>/);
  }
});

test("nested commands and literal shell bodies map findings to original positions", async () => {
  const findings = await analyzeShell([
    "echo $(/bin/rm example)",
    "bash -c 'echo ok; mkdir example'",
    "bash <<EOF",
    "rm example",
    "EOF",
  ].join("\n"));
  assert.deepEqual(findings.map(({ line, column, class: classification }) => [line, column, classification]), [
    [1, 1, "READ-ONLY"], [1, 8, "MUTATING"], [2, 10, "READ-ONLY"], [2, 19, "LOCAL"], [4, 1, "MUTATING"],
  ]);
  await assert.rejects(() => analyzeShell("echo ok\nbash -c 'echo $(pwd'"), (error) =>
    error instanceof InputError && error.line === 2);
});

test("nested execution wrappers and download pipelines do not hide mutating findings", async () => {
  const findings = await analyzeShell([
    "printf '%s\\n' sample | xargs rm",
    "find . -exec rm {} \\;",
    "find . -delete",
    "parallel rm ::: example",
    "curl https://example.invalid/script | bash",
  ].join("\n"));
  assert.deepEqual(findings.filter((entry) => entry.class === "MUTATING").map((entry) => entry.line), [1, 2, 3, 4, 5]);
  assert.equal(findings.at(-1)?.reason, "runs downloaded code");
});

test("the first find action cannot make an uninspected later action read-only", async () => {
  for (const source of ["find . -exec echo {} \\; -exec rm {} \\;", "find . -fprint output -exec echo {} \\;"]) {
    const findings = await analyzeShell(source);
    assert.deepEqual(findings.map(({ class: classification, reason }) => [classification, reason]), [
      ["UNKNOWN", "additional find actions are not analysed"],
    ], source);
  }
});

test("xargs supports fixed options without treating runtime arguments as read-only", async () => {
  const findings = await analyzeShell([
    "xargs -0 -n 1 rm",
    "env xargs --max-args=2 aws ssm get-parameter",
    "xargs -I ITEM ITEM",
    "xargs bash -c 'echo ok'",
  ].join("\n"));
  assert.deepEqual(findings.map(({ class: classification, reason }) => [classification, reason]), [
    ["MUTATING", "can delete or destroy local data"],
    ["UNKNOWN", "nested arguments are supplied at runtime"],
    ["UNKNOWN", "command is not supported by the local rules"],
    ["UNKNOWN", "nested arguments are supplied at runtime"],
  ]);
});

test("known wrapper options preserve the inner effect and unknown options stay opaque", async () => {
  const rows = [
    ["sudo -u example -E aws s3 ls", "READ-ONLY"],
    ["sudo --user=example -- /bin/rm example", "MUTATING"],
    ["timeout --signal=TERM --kill-after 2s 0.5s rm example", "MUTATING"],
    ["env -- FOO=bar /bin/rm example", "MUTATING"],
    ["env --ignore-environment aws s3 ls", "UNKNOWN"],
    ["env FOO=bar -- /bin/rm example", "UNKNOWN"],
    ["env -S 'echo example' rm example", "UNKNOWN"],
    ["sudo --unknown echo example", "UNKNOWN"],
    ["sudo -u -- echo example", "UNKNOWN"],
    ["command -v rm", "READ-ONLY"],
    ["command -x rm", "UNKNOWN"],
  ] as const;
  for (const [source, expected] of rows) {
    assert.deepEqual((await analyzeShell(source)).map((item) => item.class), [expected], source);
  }
  const [terraform] = await analyzeShell("sudo -u example -E terraform plan");
  assert.equal(terraform.reason, "unrecognized or ambiguous terraform operation");
});

test("DeployShield normalization scenarios use cmdclass context and failure rules", async () => {
  const rows = [
    ["AWS_PROFILE=example aws s3 ls", "READ-ONLY", "example"],
    ["env AWS_PROFILE=example aws s3 ls", "READ-ONLY", "example"],
    ["sudo aws s3 ls", "READ-ONLY"],
    ["/usr/local/bin/aws ec2 describe-instances", "READ-ONLY"],
    ["FOO=bar BAZ=qux kubectl get pods", "READ-ONLY"],
    ["FOO=bar", "LOCAL"],
    ['psql -c "SELECT * FROM example"', "UNKNOWN"],
    ["kubectl --namespace default get pods", "UNKNOWN"],
    ["kubectl --unknown get pods", "UNKNOWN"],
    ["aws --debug ec2 describe-instances", "READ-ONLY"],
  ] as const;
  for (const [source, expected, profile] of rows) {
    const findings = await analyzeShell(source);
    assert.deepEqual(findings.map((item) => item.class), [expected], source);
    if (profile) assert.equal(findings[0].context?.profile, profile, source);
  }
  await assert.rejects(() => analyzeShell('echo "unterminated'), InputError);
});

test("shell function bodies and calls expose known destructive effects", async () => {
  const findings = await analyzeShell("wipe() { rm -- \"$1\"; }\nwipe example");
  assert.deepEqual(findings.map(({ line, class: classification }) => [line, classification]),
    [[1, "MUTATING"], [2, "MUTATING"]]);
  assert.equal(findings[1].reason, "calls wipe (MUTATING)");
});

test("function calls inherit only effects proven by their analyzed bodies", async () => {
  const rows = [
    ["fn() { echo ok; }; fn", ["READ-ONLY", "READ-ONLY"]],
    ["fn() { printf ok > output; }; fn", ["LOCAL", "LOCAL"]],
    ["fn() { out=example; }; fn", ["LOCAL", "LOCAL"]],
    ["fn() { custom; }; fn", ["UNKNOWN", "UNKNOWN"]],
    ["fn() { }; fn", ["UNKNOWN"]],
    ["fn() { ((count++)); }; fn", ["LOCAL", "LOCAL"]],
    ["fn() { echo $((count++)); }; fn", ["LOCAL", "LOCAL"]],
    ["fn() { fn; }; fn", ["UNKNOWN", "UNKNOWN"]],
    ["fn() { rm example; custom; }; fn", ["MUTATING", "UNKNOWN", "MUTATING"]],
  ] as const;
  for (const [source, expected] of rows) {
    assert.deepEqual((await analyzeShell(source)).map(({ class: classification }) => classification), expected, source);
  }
});

test("arithmetic shell commands and expansions are local effects, never read-only", async () => {
  for (const source of ["((count++))", "echo $((count++))", "echo $(( $(rm example) ))"]) {
    const findings = await analyzeShell(source);
    assert.equal(findings[0].class, "LOCAL", source);
    assert.equal(findings[0].reason, "evaluates shell arithmetic", source);
  }
  const nested = await analyzeShell("(( $(rm example) ))");
  assert.ok(nested.some(({ class: classification }) => classification === "MUTATING"));
});

test("loops, conditional bodies, continued lines, and local redirects retain positions", async () => {
  const source = [
    "# rm example",
    "if true; then cd example && echo 'rm example'; fi",
    "for key in $KEYS; do aws s3 rm \\",
    "  s3://example/item; done",
    "echo ok >/dev/null",
    "echo ok 2>&1",
    ". ./example.sh",
    "node -e 'example()'",
    "echo ok >> example",
    "echo ok | tee example",
    "source ./example.sh",
  ].join("\n");
  const findings = await analyzeShell(source);
  assert.deepEqual(findings.map(({ line, class: classification }) => [line, classification]), [
    [2, "READ-ONLY"], [2, "READ-ONLY"], [2, "READ-ONLY"], [3, "MUTATING"],
    [5, "READ-ONLY"], [6, "READ-ONLY"], [7, "UNKNOWN"], [8, "UNKNOWN"],
    [9, "LOCAL"], [10, "READ-ONLY"], [10, "LOCAL"], [11, "UNKNOWN"],
  ]);
  assert.equal(findings.at(-1)?.reason, "runs another file");
});

test("shell syntax fixtures distinguish substitution bodies, literal eval, and dynamic commands", async () => {
  const rows = [
    ["ID=$(aws ec2 run-instances)", ["LOCAL", "MUTATING"]],
    ["echo `pwd`", ["READ-ONLY", "READ-ONLY"]],
    ["echo <(pwd) >(mkdir example)", ["READ-ONLY", "READ-ONLY", "LOCAL"]],
    ["eval 'mkdir example'", ["LOCAL"]],
    ['eval "$PAYLOAD"', ["UNKNOWN"]],
    ["$CMD --force", ["UNKNOWN"]],
    ["aws $OP", ["UNKNOWN"]],
    ["aws s3 ls s3://$BUCKET", ["READ-ONLY"]],
  ] as const;
  for (const [source, expected] of rows) {
    const findings = await analyzeShell(source);
    assert.deepEqual(findings.map((item) => item.class), expected, source);
    if (source === "$CMD --force" || source === "aws $OP") {
      assert.equal(findings[0]?.reason, "command is in a variable", source);
    }
  }
  const chain = await analyzeShell("cd repo && aws s3 ls | aws s3 rm s3://example");
  assert.deepEqual(chain.map(({ line, column, class: classification }) => [line, column, classification]), [
    [1, 1, "READ-ONLY"], [1, 12, "READ-ONLY"], [1, 24, "MUTATING"],
  ]);
});

test("classifies a known outer command separately from nested command effects", async () => {
  for (const [source, expected] of [
    ["echo $(pwd)", ["READ-ONLY", "READ-ONLY"]],
    ['echo "$(pwd; echo ok)"', ["READ-ONLY", "READ-ONLY", "READ-ONLY"]],
    ["echo $(pwd) > output", ["LOCAL", "READ-ONLY"]],
    ["echo $(rm example)", ["READ-ONLY", "MUTATING"]],
    ["echo $(custom)", ["READ-ONLY", "UNKNOWN"]],
    ["echo $(pwd; rm example)", ["READ-ONLY", "READ-ONLY", "MUTATING"]],
    ["echo $(echo $(pwd))", ["READ-ONLY", "READ-ONLY", "READ-ONLY"]],
    ["echo <(pwd)", ["READ-ONLY", "READ-ONLY"]],
    ["echo $(printf example)", ["READ-ONLY", "READ-ONLY"]],
    ['echo "$(pwd)" "$value"', ["READ-ONLY", "READ-ONLY"]],
    ['echo "$(pwd)" $((value++))', ["LOCAL", "READ-ONLY"]],
    ["echo $(pwd > output)", ["READ-ONLY", "LOCAL"]],
    ["echo $(pwd) > $output", ["UNKNOWN", "READ-ONLY"]],
    ["pwd() { rm example; }\necho $(pwd)", ["MUTATING", "READ-ONLY", "MUTATING"]],
  ] as const) {
    const findings = await analyzeShell(source);
    assert.deepEqual(findings.map(({ class: classification }) => classification), expected, source);
  }
});

test("classifies a known outer command separately from nested command effects", async () => {
  const rows = [
    ["cat \"$(pwd)\"", ["READ-ONLY", "READ-ONLY"]],
    ["cat \"$(rm example)\"", ["READ-ONLY", "MUTATING"]],
    ["grep pattern \"$(custom)\" input.txt", ["READ-ONLY", "UNKNOWN"]],
    ["mkdir \"$(pwd)\"", ["LOCAL", "READ-ONLY"]],
    ["echo \"$(custom)\"", ["READ-ONLY", "UNKNOWN"]],
    ["echo \"$(rm example)\" > output", ["LOCAL", "MUTATING"]],
    ["sort \"$(pwd)\"", ["UNKNOWN", "READ-ONLY"]],
    ["curl \"$(pwd)\"", ["UNKNOWN", "READ-ONLY"]],
    ["echo \"$((count++))\"", ["LOCAL"]],
  ] as const;
  for (const [source, expected] of rows) {
    assert.deepEqual((await analyzeShell(source)).map(({ class: classification }) => classification), expected, source);
  }
});

test("redirect substitutions do not hide effects and unknown script runners explain why", async () => {
  const findings = await analyzeShell([
    'echo example > "$(rm sample)"',
    'aws secretsmanager get-secret-value --secret-id "$(printf example)"',
    '[[ -n "$(rm sample)" ]]',
    "python example.py",
    "./example.sh",
    "node -e 'example()'",
  ].join("\n"));
  assert.deepEqual(findings.map(({ line, class: classification }) => [line, classification]), [
    [1, "UNKNOWN"], [1, "MUTATING"], [2, "SENSITIVE"], [2, "READ-ONLY"],
    [3, "UNKNOWN"], [3, "MUTATING"], [4, "UNKNOWN"], [5, "UNKNOWN"], [6, "UNKNOWN"],
  ]);
  assert.deepEqual(findings.slice(-3).map(({ reason }) => reason),
    ["runs another file", "runs another file", "inline code not analysed"]);
});

test("new local rules do not hide nested destructive effects", async () => {
  for (const source of ["return $(rm example)", "shift $(rm example)", "date +$(rm example)"]) {
    const findings = await analyzeShell(source);
    assert.ok(findings.some(({ class: classification, command }) =>
      classification === "MUTATING" && command === "rm example"), source);
    assert.notEqual(findings[0].class, "READ-ONLY", source);
  }
});

test("known text filters remain UNKNOWN when a command can write a file", async () => {
  for (const [source, expected] of [
    ["grep -E pattern input.txt", ["READ-ONLY"]],
    ["cat -- input.txt", ["READ-ONLY"]],
    ["jq -r '.items[]' input.json", ["READ-ONLY"]],
    ["sort -r input.txt", ["READ-ONLY"]],
    ["sort -o output.txt input.txt", ["UNKNOWN"]],
    ["sort -ro output.txt input.txt", ["UNKNOWN"]],
    ["sort --output=output.txt input.txt", ["UNKNOWN"]],
    ["cat input.txt > output.txt", ["LOCAL"]],
    ["awk '{ system(\"rm example\") }' input.txt", ["UNKNOWN"]],
    ["sed -i 's/a/b/' input.txt", ["UNKNOWN"]],
  ] as const) {
    assert.deepEqual((await analyzeShell(source)).map(({ class: classification }) => classification), expected, source);
  }
});

test("declarations are local effects and expose the commands nested in them", async () => {
  const rows = [
    ["export item=$(rm example)", ["rm example"]],
    ["function run() { local item=$(rm example); }", ["rm example"]],
    ["declare item=`rm example`", ["rm example"]],
    ["readonly item=$(echo $(rm example))", ["rm example"]],
    ["local one=$(rm first) two=$(rm second)", ["rm first", "rm second"]],
    ['unset "items[$(rm example)]"', ["rm example"]],
    ["unset 'items[$(rm example)]'", []],
    ['export item=$(rm example) > "$(rm other)"', ["rm example", "rm other"]],
    ['export item="literal $(rm example)"', ["rm example"]],
    ["export item='literal $(rm example)'", []],
    ["export item=<(rm example)", ["rm example"]],
  ] as const;
  for (const [source, mutatingCommands] of rows) {
    const findings = await analyzeShell(source);
    assert.equal(findings[0]?.class, "LOCAL", source);
    assert.match(findings[0]?.reason ?? "", /^(?:declares|unsets) a shell variable$/, source);
    assert.equal(findings[0]?.command, "<shell text omitted>", source);
    assert.deepEqual(findings.filter((entry) => entry.class === "MUTATING")
      .map(({ command, line, column }) => [command, line, column]), mutatingCommands.map((command) =>
      [command, 1, source.indexOf(command) + 1]), source);
  }
  const findings = await analyzeShell("function wipe() { local value=$(rm example); }\nwipe");
  assert.deepEqual(findings.map(({ line, class: classification }) => [line, classification]),
    [[1, "LOCAL"], [1, "MUTATING"], [2, "MUTATING"]]);
});

test("literal interpreter bodies do not swallow outer substitutions or mistake script arguments for code", async () => {
  const findings = await analyzeShell([
    `env bash -c 'echo ok' "$(rm example)"`,
    `bash example.sh -c 'echo not-the-script'`,
    "python example.py <<'PY'",
    "this is not Python source",
    "PY",
  ].join("\n"));
  assert.deepEqual(findings.map(({ line, column, class: classification, reason }) =>
    [line, column, classification, reason]), [
    [1, 14, "READ-ONLY", "no filesystem or remote write identified"],
    [1, 26, "MUTATING", "can delete or destroy local data"],
    [2, 1, "UNKNOWN", "runs another file"],
    [3, 1, "UNKNOWN", "runs another file"],
  ]);
});

test("DeployShield segmentation corpus preserves quoted operators and nested effects", async () => {
  const rows = [
    ["echo hello", ["READ-ONLY"]],
    ["echo a && echo b", ["READ-ONLY", "READ-ONLY"]],
    ["echo a || echo b", ["READ-ONLY", "READ-ONLY"]],
    ["echo a; echo b", ["READ-ONLY", "READ-ONLY"]],
    ["echo a | grep a", ["READ-ONLY", "READ-ONLY"]],
    ["echo a && echo b || echo c; echo d", ["READ-ONLY", "READ-ONLY", "READ-ONLY", "READ-ONLY"]],
    ['echo "hello && world"', ["READ-ONLY"]],
    ["echo 'hello && world'", ["READ-ONLY"]],
    ["echo $(echo a && echo b)", ["READ-ONLY", "READ-ONLY", "READ-ONLY"]],
    ["echo `echo a && echo b`", ["READ-ONLY", "READ-ONLY", "READ-ONLY"]],
    ["echo a \\&& echo b", ["READ-ONLY", "READ-ONLY"]],
    ["", []],
    ["   ", []],
    ["echo $(echo $(echo inner)) && echo outer", ["READ-ONLY", "READ-ONLY", "READ-ONLY", "READ-ONLY"]],
    ["diff <(echo a && echo b) file.txt", ["UNKNOWN", "READ-ONLY", "READ-ONLY"]],
    [`echo "hello" && echo 'world' | grep w`, ["READ-ONLY", "READ-ONLY", "READ-ONLY"]],
  ] as const;
  for (const [source, expected] of rows) {
    assert.deepEqual((await analyzeShell(source)).map((finding) => finding.class), expected, source);
  }
});

test("oversized and excessively nested sources fail with a bounded diagnostic", async () => {
  await assert.rejects(() => analyzeShell("x".repeat(1024 * 1024 + 1)), /1 MiB analysis limit/);
  const deep = `${"echo $(".repeat(140)}pwd${")".repeat(140)}`;
  await assert.rejects(() => analyzeShell(deep), /syntax nesting exceeds/);
});
test("the full shell sample matches its five-class golden", () => {
  const result = cli("copilot-sample.sh");
  assert.equal(result.status, 1);
  assert.equal(result.stderr, "");
  const expected = readFileSync(new URL("./fixtures/shell/copilot-sample.expected.txt", import.meta.url), "utf8");
  assert.equal(result.stdout, `cmdclass ${version}\n${expected}`);
});

describe("TestProperties", () => {
  // Catches: Integrity (SAFETY) - a function containing an unknown effect is promoted to a known class.
  test("function calls match the least-safe analyzed body effect", async () => {
    await fc.assert(fc.asyncProperty(
      fc.array(fc.constantFrom("echo sample", "pwd", "jq -r . input.json", "date -u", "sleep 1"),
        { minLength: 1, maxLength: 8 }),
      async (commands) => {
        const findings = await analyzeShell(`fn() { ${commands.join("; ")}; }; fn`);
        assert.deepEqual(findings.map(({ class: classification }) => classification),
          [...commands.map(() => "READ-ONLY"), "READ-ONLY"]);
        const unsafe = await analyzeShell(`fn() { ${commands.join("; ")}; custom; }; fn`);
        assert.equal(unsafe.find(({ reason }) => reason === "calls fn (UNKNOWN)")?.class, "UNKNOWN");
      },
    ), propertyOptions);
  });

  // Catches: Integrity (SAFETY) - an inner uncertainty is hidden or contaminates a known outer read.
  test("preserves nested uncertainty independently of a known outer read", async () => {
    await fc.assert(fc.asyncProperty(
      fc.array(fc.constantFrom("pwd", "echo sample", "true", "false", ":"), { minLength: 1, maxLength: 6 }),
      fc.constantFrom("rm example", "custom", "date --set=example"),
      async (safe, unsafe) => {
        const valid = await analyzeShell(`echo $(${safe.join("; ")})`);
        assert.deepEqual(valid.map(({ class: classification }) => classification),
          Array(safe.length + 1).fill("READ-ONLY"));
        const uncertain = await analyzeShell(`echo $(${safe.join("; ")}; ${unsafe})`);
        assert.equal(uncertain[0].class, "READ-ONLY");
        assert.deepEqual(uncertain.slice(1).map(({ class: classification }) => classification),
          [...Array(safe.length).fill("READ-ONLY"), unsafe === "rm example" ? "MUTATING" : "UNKNOWN"]);
      },
    ), propertyOptions);
  });

  // Catches: Integrity (SAFETY) - an outer command hides or inherits an inner command effect incorrectly.
  test("preserves outer and inner effects independently for known commands", async () => {
    await fc.assert(fc.asyncProperty(
      fc.constantFrom("echo", "cat", "grep", "jq", "cut", "tr"),
      fc.constantFrom(["pwd", "READ-ONLY"], ["rm example", "MUTATING"], ["custom", "UNKNOWN"]),
      async (outer, [inner, innerClass]) => {
        const findings = await analyzeShell(`${outer} "$(${inner})"`);
        const classes = findings.map(({ class: classification }) => classification);
        const expected = ["READ-ONLY", innerClass];
        assert.deepEqual(classes, expected);
      },
    ), propertyOptions);
  });

  // Catches: Integrity (SAFETY) - a declaration hides a nested command or duplicates its finding.
  test("retains each nested declaration effect and its source position", async () => {
    await fc.assert(fc.asyncProperty(
      fc.constantFrom("export", "local", "declare", "readonly"),
      fc.constantFrom(["pwd", "READ-ONLY"], ["rm example", "MUTATING"], ["mkdir example", "LOCAL"]),
      fc.integer({ min: 1, max: 8 }),
      async (declaration, [command, classification], count) => {
        const source = `${declaration} ${Array.from({ length: count }, (_, i) => `v${i}=$(${command})`).join(" ")}`;
        const findings = await analyzeShell(source);
        assert.equal(findings[0]?.class, "LOCAL");
        const positions = [...source.matchAll(new RegExp(command.replaceAll(" ", "\\s+"), "g"))]
          .map((match) => match.index + 1);
        assert.deepEqual(findings.slice(1).map(({ line, column, class: actual }) => [line, column, actual]),
          positions.map((column) => [1, column, classification]));
      },
    ), propertyOptions);
  });

  // Catches: Integrity (SAFETY) - nesting moves or drops an inner effect.
  test("retains a labeled command at its original position inside substitutions", async () => {
    await fc.assert(fc.asyncProperty(fc.integer({ min: 1, max: 12 }),
      fc.constantFrom(["pwd", "READ-ONLY"], ["rm example", "MUTATING"], ["mkdir example", "LOCAL"]),
      async (depth, [code, classification]) => {
        const prefix = "echo $(".repeat(depth);
        const findings = await analyzeShell(`${prefix}${code}${")".repeat(depth)}`);
        assert.equal(findings.length, depth + 1);
        const inner = findings.at(-1);
        assert.deepEqual([inner?.line, inner?.column, inner?.class], [1, prefix.length + 1, classification]);
      }), propertyOptions);
  });

  // Catches: Integrity (SAFETY) - a valid labeled compound script drops, invents or changes a command.
  test("finds modeled commands across separators, wrappers, and harmless whitespace", async () => {
    const action = fc.constantFrom(
      { code: "echo 'hi; rm example'", label: "READ-ONLY" },
      { code: "mkdir example", label: "LOCAL" },
      { code: "/bin/rm -- example", label: "MUTATING" },
      { code: "custom --quiet", label: "UNKNOWN" },
    );
    const command = fc.tuple(fc.constantFrom("", "env ", "command -- ", "timeout 1 ",
      "sudo --user=example -n ", "timeout --signal=TERM 0.5s "), action);
    await fc.assert(fc.asyncProperty(
      fc.array(command, { minLength: 1, maxLength: 12 }),
      fc.constantFrom("; ", " && ", " || ", "\n", " | "),
      fc.constantFrom("", "  "),
      async (commands, separator, indent) => {
        const source = commands.map(([wrapper, { code }]) => `${indent}${wrapper}${code}`).join(separator);
        const actual = await analyzeShell(source);
        assert.deepEqual(actual.map(({ class: classification }) => classification),
          commands.map(([, { label }]) => label));
      },
    ), propertyOptions);
  });

  // Catches: Integrity (SAFETY) - malformed shell is accepted or returns findings.
  test("rejects deliberately unclosed constructs following valid commands", async () => {
    await fc.assert(fc.asyncProperty(
      fc.integer({ min: 0, max: 10 }),
      fc.constantFrom("echo '", "echo $(pwd", "if true; then echo value"),
      async (validLines, invalid) => {
        await assert.rejects(() => analyzeShell(`${"echo ok\n".repeat(validLines)}${invalid}`), InputError);
      },
    ), propertyOptions);
  });
});
