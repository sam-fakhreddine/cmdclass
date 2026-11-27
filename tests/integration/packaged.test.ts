import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync, existsSync } from "node:fs";
import { delimiter, dirname, resolve, join } from "node:path";
import { test } from "node:test";
import fc from "fast-check";
import { propertyOptions } from "../property-options.ts";

const compatibility = process.env.CMDCLASS_COMPATIBILITY === "1";
const packagedTestName = compatibility
  ? "installed CLI matches goldens on the minimum Node runtime"
  : "installed CLI reproduces goldens without permission to write, launch children, or use the network";

test(packagedTestName, () => {
  if (compatibility) {
    assert.notEqual(process.env.CMDCLASS_PROOF, "1", "compatibility mode cannot replace the full proof");
    const manifest = JSON.parse(readFileSync("package.json", "utf8"));
    assert.equal(process.version, `v${manifest.engines.node.replace(/^>=/, "")}`);
  }
  const project = process.cwd();
  const manifest = JSON.parse(readFileSync("package.json", "utf8"));
  const temp = mkdtempSync(resolve("dist", ".proof-"));
  const npm = (args: string[], cwd: string) => execFileSync("npm", args, { cwd, encoding: "utf8" });
  try {
    const [{ filename }] = JSON.parse(npm(["pack", "--ignore-scripts", "--json", "--pack-destination", temp], project));
    writeFileSync(join(temp, "package.json"), '{"name":"cmdclass-proof","private":true}\n');
    npm(["install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", join(temp, filename)], temp);
    const bin = join(temp, "node_modules", ".bin", "cmdclass");
    const permissions = compatibility ? [] : ["--permission", `--allow-fs-read=${project}`];
    const run = (...args: string[]) => spawnSync(process.execPath, [
      ...permissions, bin, ...args,
    ], { cwd: project, encoding: "utf8" });
    if (!compatibility) {
      const denied = spawnSync(process.execPath, [...permissions, "--input-type=module", "-e", `
      import assert from "node:assert/strict";
      import { spawnSync } from "node:child_process";
      import { writeFileSync } from "node:fs";
      import { connect } from "node:net";
      import { join } from "node:path";
      const dir = process.argv[1];
      const denied = { code: "ERR_ACCESS_DENIED" };
      assert.throws(() => writeFileSync(join(dir, "permission-probe"), ""), denied);
      assert.throws(() => spawnSync(process.execPath, ["--version"]), denied);
      await assert.rejects(async () => {
        await new Promise((resolve, reject) => {
          connect(join(dir, "unbound.sock")).once("error", reject).once("connect", resolve);
        });
      }, denied);
      `, temp], { cwd: project, encoding: "utf8", timeout: 5_000 });
      assert.equal(denied.status, 0, denied.stderr || denied.error?.message);
    }
    const goldens = [
      ["shell/copilot-sample.sh", "shell/copilot-sample.expected.txt"],
      ["python/aws.py", "python/aws.expected.txt"],
      ["shell/embedded-python.sh", "shell/embedded-python.expected.txt"],
      ["python/s3-resource-deletes.py", "python/s3-resource-deletes.expected.txt"],
    ];
    const canary = "fixture-only-synthetic-canary";
    for (const [file, golden] of goldens) {
      const actual = run(`tests/fixtures/${file}`);
      assert.equal(actual.status, 1, actual.stderr);
      assert.equal(actual.stderr, "");
      const expected = readFileSync(`tests/fixtures/${golden}`, "utf8");
      assert.equal(actual.stdout, `cmdclass ${manifest.version}\n${expected}`);
      assert.equal(run(`tests/fixtures/${file}`).stdout, actual.stdout);
      const json = run("--json", `tests/fixtures/${file}`);
      assert.equal(json.status, actual.status, json.stderr);
      assert.equal(json.stderr, "");
      const report = JSON.parse(json.stdout);
      assert.equal(report.schema_version, 2);
      assert.equal(report.tool_version, manifest.version);
      const counts: Record<string, number> = {};
      const expectedLines = expected.trimEnd().split("\n");
      const summary = expectedLines.pop();
      assert.ok(summary && summary.startsWith("summary: "));
      for (const item of summary.slice("summary: ".length).split(", ")) {
        const [count, classification] = item.split(" ");
        counts[classification.toUpperCase()] = Number(count);
      }
      assert.deepEqual(report.summary, counts);
      assert.equal(report.entries.length, expectedLines.length);
      for (const [i, expectedLine] of expectedLines.entries()) {
        const { class: classification, line, column, command, reason, source } = report.entries[i];
        assert.match(source, /\S/);
        if (file === "python/s3-resource-deletes.py") assert.equal(source, reason);
        assert.equal(`${classification.padEnd(10)} ${line}:${column}  ${command}  ${reason}`, expectedLine,
          `${file} finding ${i + 1}`);
      }
    }
    for (const file of ["docs/proof-of-working.md", ...goldens.map(([, golden]) => `tests/fixtures/${golden}`)]) {
      const evidence = readFileSync(file, "utf8");
      for (const marker of [canary, "example-fixture-", "synthetic-fixture-", "fixture-sensitive-arg"]) {
        assert.ok(!evidence.includes(marker), `synthetic credential marker present in retained evidence: ${file}`);
      }
    }
    const version = run("--version");
    assert.equal(version.status, 0, version.stderr);
    const lockfile = JSON.parse(readFileSync("package-lock.json", "utf8"));
    assert.equal(lockfile.version, manifest.version);
    assert.equal(lockfile.packages[""].version, manifest.version);
    const snapshot = JSON.parse(readFileSync("data/aws.json", "utf8"));
    assert.equal(version.stdout, `cmdclass ${manifest.version}; AWS snapshot ${snapshot.date} sha256 ${snapshot.sha256}\n`);
    const reportVersion = run("--json", "tests/fixtures/shell/local-effects.sh");
    assert.equal(reportVersion.status, 1, reportVersion.stderr);
    assert.equal(JSON.parse(reportVersion.stdout).tool_version, manifest.version);
    assert.match(run("tests/fixtures/shell/local-effects.sh").stdout, new RegExp(`^cmdclass ${manifest.version.replaceAll(".", "\\.")}\\n`));

    const tree = join(temp, "-folder");
    const put = (path: string, source: string) => {
      mkdirSync(dirname(join(tree, path)), { recursive: true });
      writeFileSync(join(tree, path), source);
    };
    for (const [file, content] of [
      ["z.BASH", "echo sample\n"],
      ["sub/write.sh", "mkdir example\n"],
      ["python-tool", "#!/usr/bin/env python3\npass\n"],
      ["bash-tool", "#!/usr/bin/env -S bash -eu\npwd\n"],
      ["empty/.keep", ""],
      ...["README.md", "plain", "other-tool", ".hidden/bad.sh", "node_modules/bad.sh",
        "__pycache__/bad.py", "cdk.out/asset.example/bad.py", "secrets/bad.py", "credentials/bad.sh", ".hidden.sh"]
        .map((file) => [file, "#!/usr/bin/env ruby bash\ninvalid '\n"]),
    ]) put(file, content);
    symlinkSync(tree, join(tree, "cycle"), "dir");
    symlinkSync(join(tree, "z.BASH"), join(tree, "link.sh"), "file");
    const fromPath = spawnSync("cmdclass", ["--json", "--", "-folder"], {
      cwd: temp,
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: [dirname(bin), dirname(process.execPath), process.env.PATH ?? ""].join(delimiter),
      },
    });
    const scanned = run("--json", tree);
    assert.equal(fromPath.status, 1, fromPath.stderr || fromPath.error?.message);
    assert.equal(fromPath.stdout, scanned.stdout);
    assert.equal(scanned.status, 1, scanned.stderr);
    assert.equal(scanned.stderr, "");
    const clean = JSON.parse(scanned.stdout);
    assert.equal(clean.schema_version, 2);
    assert.equal(clean.tool_version, manifest.version);
    assert.deepEqual(clean.errors, []);
    assert.deepEqual(clean.files.map(({ path }: { path: string }) => path),
      ["bash-tool", "python-tool", "sub/write.sh", "z.BASH"]);
    assert.deepEqual(clean.summary, { MUTATING: 0, SENSITIVE: 0, UNKNOWN: 0, LOCAL: 1, "READ-ONLY": 2 });
    const emptyFolder = run("--json", join(tree, "empty"));
    assert.equal(emptyFolder.status, 0);
    assert.equal(JSON.parse(emptyFolder.stdout).tool_version, manifest.version);

    put("bad\nfile.sh", "echo 'unclosed\n");
    put("too-big.sh", " ".repeat(1024 * 1024 + 1));
    const partial = run(tree, "--json");
    assert.equal(partial.status, 2, partial.stderr);
    assert.equal(partial.stderr, "");
    assert.deepEqual(JSON.parse(partial.stdout), {
      ...clean,
      errors: [
        { path: "bad\nfile.sh", message: "line 1, column 5: invalid shell syntax" },
        { path: "too-big.sh", message: "line 1, column 1: input exceeds the 1 MiB analysis limit" },
      ],
    });
    const text = run(tree);
    assert.equal(text.status, 2);
    assert.ok(text.stdout.startsWith(`cmdclass ${manifest.version}\n`));
    assert.match(text.stdout, /== sub\/write\.sh ==\nLOCAL/);
    assert.match(text.stdout, /scanned: 4 file\(s\), 2 error\(s\)/);
    assert.match(text.stderr, /bad\\nfile\.sh/);
    assert.ok(!text.stderr.includes("bad\nfile.sh"));

    const resourceInput = join(temp, "resource.py");
    writeFileSync(resourceInput, "import boto3\nboto3.resource('sns').Topic('example').publish(Message='example')\n");
    const resource = run("--json", resourceInput);
    assert.equal(resource.status, 1, resource.stderr);
    assert.deepEqual(JSON.parse(resource.stdout).entries.map(({ source }: { source: string }) => source),
      ["IAM sns:Publish (Write)"]);

    const processWrapper = run("--json", "tests/fixtures/python/subprocess-wrapper.py");
    assert.equal(processWrapper.status, 1, processWrapper.stderr);
    const processReport = JSON.parse(processWrapper.stdout);
    assert.equal(processReport.summary.UNKNOWN, 1);
    assert.equal(processReport.summary.MUTATING, 1);
    assert.match(processWrapper.stdout, /ec2:CreateTags/);
    assert.doesNotMatch(processWrapper.stdout + processWrapper.stderr, /fixture-secret/);

    const declarationInput = join(temp, "declaration.sh");
    writeFileSync(declarationInput, "export item=$(rm example)\n");
    for (const flag of [[], ["--json"]]) {
      const declaration = run(...flag, declarationInput);
      assert.equal(declaration.status, 1, declaration.stderr);
      assert.equal(declaration.stderr, "");
      assert.match(declaration.stdout, /MUTATING/);
      assert.match(declaration.stdout, /rm example/);
      assert.match(declaration.stdout, /declares a shell variable/);
    }

    const functionCases = [
      ["fn() { echo ok; }; fn", ["READ-ONLY", "READ-ONLY"]],
      ["fn() { echo ok; }; fn > output", ["LOCAL", "READ-ONLY"]],
      ["fn() { out=example; }; fn", ["LOCAL", "LOCAL"]],
      ["fn() { custom; }; fn", ["UNKNOWN", "UNKNOWN"]],
      ["fn() { ((count++)); }; fn", ["LOCAL", "LOCAL"]],
    ] as const;
    for (const [source, expected] of functionCases) {
      writeFileSync(declarationInput, `${source}\n`);
      const actual = run("--json", declarationInput);
      assert.equal(actual.status, expected.some((classification) => classification === "UNKNOWN" ||
        classification === "LOCAL") ? 1 : 0);
      assert.equal(actual.stderr, "");
      assert.deepEqual(JSON.parse(actual.stdout).entries.map(({ class: classification }: { class: string }) =>
        classification), expected, source);
    }

    const input = join(temp, "canary.sh");
    const marker = join(temp, "not-created");
    const upstreamCases = [
      ["aws ec2 describe-instances", 0, ["READ-ONLY"]],
      ["kubectl get pods", 0, ["READ-ONLY"]],
      ["terraform plan", 1, ["UNKNOWN"]],
      ["git push origin main", 1, ["UNKNOWN"]],
      ["npm test", 1, ["UNKNOWN"]],
      ["aws s3 ls && kubectl get pods", 0, ["READ-ONLY", "READ-ONLY"]],
      ["terraform apply", 1, ["MUTATING"]],
      ["kubectl apply -f deploy.yaml", 1, ["MUTATING"]],
      ["npm publish", 1, ["MUTATING"]],
      ["echo ok && terraform apply", 1, ["MUTATING", "READ-ONLY"]],
      ["", 0, []],
      ["return 0", 0, ["READ-ONLY"]],
      ["shift", 1, ["LOCAL"]],
      ["date -u +%Y", 0, ["READ-ONLY"]],
      ["date --set=example", 1, ["UNKNOWN"]],
      ["echo $(pwd)", 0, ["READ-ONLY", "READ-ONLY"]],
      ["echo $(rm example)", 1, ["MUTATING", "READ-ONLY"]],
      ["echo $(custom)", 1, ["UNKNOWN", "READ-ONLY"]],
      ["jq -r '.items[]' input.json", 0, ["READ-ONLY"]],
      ["sort -o output.txt input.txt", 1, ["UNKNOWN"]],
      ["cat input.txt > output.txt", 1, ["LOCAL"]],
      ["AWS_PROFILE=example aws ec2 run-instances", 1, ["MUTATING"]],
      ["/usr/local/bin/terraform apply", 1, ["MUTATING"]],
      ['bash -c "terraform apply"', 1, ["MUTATING"]],
      ['sudo bash -c "kubectl delete pods --all"', 1, ["MUTATING"]],
      ['sudo bash -c "echo $(terraform destroy)"', 1, ["MUTATING", "UNKNOWN"]],
      ["echo example | xargs terraform apply", 1, ["MUTATING", "READ-ONLY"]],
    ] as const;
    for (const [script, status, expected] of upstreamCases) {
      writeFileSync(input, script);
      const actual = run("--json", input);
      assert.equal(actual.status, status, script);
      assert.equal(actual.stderr, "", script);
      assert.deepEqual(JSON.parse(actual.stdout).entries.map((item: { class: string }) => item.class), expected, script);
    }
    writeFileSync(input, "aws secretsmanager get-secret-value --secret-id example\nprintf '%s\\n' sample\n");
    for (const flag of [[], ["--json"]]) {
      const actual = run(...flag, input);
      assert.equal(actual.status, 3, actual.stderr);
      assert.equal(actual.stderr, "");
      assert.match(actual.stdout, /SENSITIVE/);
      assert.match(actual.stdout, /READ-ONLY/);
    }
    const source = `printf '%s\\n' sample > '${marker}'\n/bin/echo --token ${canary}\n`;
    writeFileSync(input, source);
    for (const flag of [[], ["--json"]]) {
      const actual = run(...flag, input);
      assert.equal(actual.status, 1, actual.stderr);
      assert.ok(!(actual.stdout + actual.stderr).includes(canary));
      assert.equal(readFileSync(input, "utf8"), source);
      assert.equal(existsSync(marker), false);
    }
    const invalidSource = `echo example\ncustom-example --password ${canary} '`;
    writeFileSync(input, invalidSource);
    for (const flag of [[], ["--json"]]) {
      const actual = run(...flag, input);
      assert.equal(actual.status, 2);
      assert.equal(actual.stdout, "");
      assert.match(actual.stderr, /invalid shell syntax/);
      assert.ok(!actual.stderr.includes(canary));
      assert.equal(readFileSync(input, "utf8"), invalidSource);
    }
    for (const file of ["shell/missing-substitution-end.sh", "python/invalid.py"]) {
      for (const flag of [[], ["--json"]]) {
        const actual = run(...flag, `tests/fixtures/${file}`);
        assert.equal(actual.status, 2);
        assert.equal(actual.stdout, "");
        assert.match(actual.stderr, /invalid .*syntax/);
      }
    }
    // Catches: Integrity (SAFETY) - the installed CLI loses findings or reports the wrong exit status.
    fc.assert(fc.property(
      fc.array(fc.constantFrom(
        ["echo example", "READ-ONLY"] as const,
        ["mkdir example", "LOCAL"] as const,
        ["rm example", "MUTATING"] as const,
        ["custom-example", "UNKNOWN"] as const,
      ), { minLength: 1, maxLength: 6 }),
      fc.constantFrom(" && ", "; ", " | "),
      (commands, separator) => {
        writeFileSync(input, commands.map(([code]) => code).join(separator));
        const actual = run("--json", input);
        assert.equal(actual.stderr, "");
        assert.equal(actual.status, commands.every(([, classification]) => classification === "READ-ONLY") ? 0 : 1);
        const { entries, schema_version } = JSON.parse(actual.stdout);
        assert.equal(schema_version, 2);
        assert.deepEqual(entries.sort((a: { column: number }, b: { column: number }) => a.column - b.column)
          .map(({ command, class: classification }: { command: string; class: string }) => [command, classification]),
        commands);
      },
    ), { ...propertyOptions, numRuns: 20 });

    // Catches: Integrity (INVARIANT) - folder totals or exit status disagree with the individual findings.
    fc.assert(fc.property(
      fc.array(fc.constantFrom(
        ["echo example", "READ-ONLY", 0] as const,
        ["aws secretsmanager get-secret-value --secret-id example", "SENSITIVE", 3] as const,
        ["mkdir example", "LOCAL", 1] as const,
        ["rm example", "MUTATING", 1] as const,
        ["custom-example", "UNKNOWN", 1] as const,
      ), { maxLength: 5 }),
      (scripts) => {
        const generated = mkdtempSync(join(temp, "generated-"));
        try {
          for (const [i, [source]] of scripts.entries()) writeFileSync(join(generated, `${i}.sh`), source);
          const actual = run("--json", generated);
          const codes = scripts.map(([, , code]) => code);
          assert.equal(actual.status, codes.includes(1) ? 1 : codes.includes(3) ? 3 : 0);
          assert.equal(actual.stderr, "");
          const { files, errors, summary } = JSON.parse(actual.stdout);
          assert.deepEqual(errors, []);
          assert.equal(files.length, scripts.length);
          for (const classification of ["READ-ONLY", "SENSITIVE", "LOCAL", "MUTATING", "UNKNOWN"]) {
            assert.equal(summary[classification], scripts.filter(([, expected]) => expected === classification).length);
          }
        } finally {
          rmSync(generated, { recursive: true, force: true });
        }
      },
    ), { ...propertyOptions, numRuns: 15 });

    const installedManifest = join(temp, "node_modules", "cmdclass", "package.json");
    const originalManifest = readFileSync(installedManifest, "utf8");
    try {
      const invalid = JSON.parse(originalManifest);
      delete invalid.version;
      writeFileSync(installedManifest, JSON.stringify(invalid));
      for (const args of [["--version"], ["--json", input], [tree]]) {
        const result = run(...args);
        assert.equal(result.status, 2);
        assert.equal(result.stdout, "");
        assert.match(result.stderr, /package version is missing or invalid/);
      }
    } finally {
      writeFileSync(installedManifest, originalManifest);
    }
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});
