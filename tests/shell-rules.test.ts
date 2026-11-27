import assert from "node:assert/strict";
import { test } from "node:test";
import { classifyLocal } from "../src/local.ts";
import { analyzeShell } from "../src/shell.ts";

const classesOf = async (source: string) => (await analyzeShell(source)).map(({ class: classification }) => classification);

// Catches: Integrity (SAFETY) - a command inside a construct the walker does not model is dropped from the report.
test("commands inside any shell construct are reported", async () => {
  const rows: [string, string[]][] = [
    ["for ((i=0; i<3; i++)); do aws sns publish --topic-arn example --message example & done",
      ["LOCAL", "LOCAL", "MUTATING"]],
    ["for ((i=0; i<$(rm example); i++)); do :; done", ["LOCAL", "LOCAL", "MUTATING", "READ-ONLY"]],
    ["a=$(rm first) b=2", ["LOCAL", "MUTATING", "LOCAL"]],
    ["for id in $(aws ec2 describe-instances --output text); do echo \"$id\"; done", ["READ-ONLY", "READ-ONLY"]],
    ["case $(rm example) in a) : ;; esac", ["MUTATING", "READ-ONLY"]],
  ];
  for (const [source, expected] of rows) assert.deepEqual(await classesOf(source), expected, source);
  const reasons = (await analyzeShell(rows[0][0])).map(({ reason }) => reason);
  assert.deepEqual(reasons, ["evaluates shell arithmetic", "sets a shell variable", "IAM sns:Publish (Write)"]);
  assert.equal((await analyzeShell(rows[3][0]))[0].reason, "IAM ec2:DescribeInstances (List)");
});

// Catches: Integrity (SAFETY) - an AWS call loses its AWS identity behind a redirect or a wrapper command.
test("AWS calls stay visible behind output redirects and unknown wrappers", async () => {
  const rows: [string, string, string][] = [
    ["aws ssm list-command-invocations --command-id example > /tmp/out.txt", "LOCAL",
      "IAM ssm:ListCommandInvocations (List); writes to a local output redirect"],
    ["retry_with_backoff 3 2 aws cloudwatch put-metric-data --namespace example", "MUTATING",
      "IAM cloudwatch:PutMetricData (Write); passed as arguments to another command"],
    ["retry_with_backoff 3 2 aws ec2 describe-instances", "UNKNOWN", "command is not supported by the local rules"],
    ["echo aws s3 rm s3://example/key", "READ-ONLY", "no filesystem or remote write identified"],
  ];
  for (const [source, classification, reason] of rows) {
    const findings = await analyzeShell(source);
    assert.deepEqual(findings.map((finding) => [finding.class, finding.reason]), [[classification, reason]], source);
  }
});

// Catches: Integrity (SAFETY) - a declaration or arithmetic stays UNKNOWN, or hides a command nested inside it.
test("declarations and arithmetic are local effects and still expose nested commands", async () => {
  const rows: [string, [string, string][]][] = [
    ["local name=value", [["LOCAL", "declares a shell variable"]]],
    ["export PATH=\"$HOME/bin:$PATH\"", [["LOCAL", "declares a shell variable"]]],
    ["unset name", [["LOCAL", "unsets a shell variable"]]],
    ["((count++))", [["LOCAL", "evaluates shell arithmetic"]]],
    ["echo $((count + 1))", [["LOCAL", "evaluates shell arithmetic"]]],
    ["total=$((total + 1))", [["LOCAL", "sets a shell variable"]]],
    ["readonly item=$(rm example)", [["LOCAL", "declares a shell variable"], ["MUTATING", "can delete or destroy local data"]]],
    ["echo $(( $(rm example) ))", [["LOCAL", "evaluates shell arithmetic"], ["MUTATING", "can delete or destroy local data"]]],
  ];
  for (const [source, expected] of rows) {
    const findings = await analyzeShell(source);
    assert.deepEqual(findings.map((finding) => [finding.class, finding.reason]), expected, source);
  }
  const [declaration] = await analyzeShell("export TOKEN=fixture-secret");
  assert.equal(declaration.command, "<shell text omitted>");
  assert.deepEqual(await classesOf("log() { local message=$1; echo \"$message\"; }\nlog started"),
    ["LOCAL", "READ-ONLY", "LOCAL"]);
});

// Catches: Integrity (SAFETY) - a builtin or filter is called read-only in a form that can write a file or run code.
test("builtins and filters are classified only in forms whose effect is certain", () => {
  const rows: [(string | null)[], string][] = [
    [["exit", "1"], "READ-ONLY"], [["exit", null], "READ-ONLY"], [["exit", "1", "2"], "UNKNOWN"],
    [["break"], "READ-ONLY"], [["continue", "2"], "READ-ONLY"], [["wait"], "READ-ONLY"],
    [["set", "-euo", "pipefail"], "LOCAL"], [["read", "-r", "line"], "LOCAL"], [["mktemp", "-d"], "LOCAL"],
    [["command", "-v", "aws"], "READ-ONLY"], [["command", "-v", null], "READ-ONLY"], [["command", "rm", "example"], "UNKNOWN"],
    [["head", "-1"], "READ-ONLY"], [["tail", "-n", null], "READ-ONLY"], [["wc", "-l"], "READ-ONLY"], [["bc"], "READ-ONLY"],
    [["df", null], "READ-ONLY"], [["/usr/bin/head", "-1"], "UNKNOWN"],
    [["hostname"], "READ-ONLY"], [["hostname", "-f"], "READ-ONLY"], [["hostname", "example"], "UNKNOWN"],
    [["uniq"], "READ-ONLY"], [["uniq", "-c", "input.txt"], "READ-ONLY"], [["uniq", "input.txt", "output.txt"], "UNKNOWN"],
    [["kill", "-0", null], "READ-ONLY"], [["kill", null], "UNKNOWN"], [["kill", "-9", "1"], "UNKNOWN"],
    [["find", ".", "-name", "*.log"], "READ-ONLY"], [["find", ".", null], "UNKNOWN"], [["find", ".", "-fprint", "out"], "UNKNOWN"],
    [["awk", "-F", ":", "{print $1}", "input.txt"], "READ-ONLY"], [["awk", "-v", null, "$2 == mp {print $1}"], "READ-ONLY"],
    [["awk", "{ system(\"rm example\") }"], "UNKNOWN"], [["awk", "{print > \"out.txt\"}"], "UNKNOWN"],
    [["awk", "{print | \"sh\"}"], "UNKNOWN"], [["awk", "-f", "program.awk"], "UNKNOWN"], [["awk", null], "UNKNOWN"],
    [["sed", "s/[KMG]$//"], "READ-ONLY"], [["sed", "-n", "-e", "s|a|b|gp", "input.txt"], "READ-ONLY"],
    [["sed", "-i", "s/a/b/", "input.txt"], "UNKNOWN"], [["sed", "s/a/b/w out.txt"], "UNKNOWN"],
    [["sed", "s/a/b/e"], "UNKNOWN"], [["sed", "1e rm example"], "UNKNOWN"], [["sed", null], "UNKNOWN"],
    [["sed", "--in-place=.bak", "s/a/b/", "input.txt"], "UNKNOWN"],
    // Cross-checked against GTFOBins: these have no listed way to write a file or run a command.
    [["diff", "-u", "a.txt", "b.txt"], "READ-ONLY"], [["md5sum", null], "READ-ONLY"], [["comm", "-12", "a", "b"], "READ-ONLY"],
    [["column", "-t"], "READ-ONLY"], [["printenv", "HOME"], "READ-ONLY"], [["strings", "binary"], "READ-ONLY"],
    // These can: a pager shell escape, a preprocessor command, a compiled magic file, socket kill.
    [["less", "file.txt"], "UNKNOWN"], [["more", "file.txt"], "UNKNOWN"], [["rg", "pattern"], "UNKNOWN"],
    [["file", "input"], "UNKNOWN"], [["ss", "-K"], "UNKNOWN"], [["top"], "UNKNOWN"],
  ];
  for (const [words, expected] of rows) assert.equal(classifyLocal(words, []).class, expected, JSON.stringify(words));
});

// Catches: Integrity (SAFETY) - an AWS command that only exists as text (a string run later, a heredoc) goes unreported.
test("a text scan flags AWS commands the parser did not attribute to a command", async () => {
  const scanned = (source: string) => analyzeShell(source).then((findings) => findings
    .filter(({ source: origin }) => origin === "text scan").map(({ line, column, class: classification, command, reason }) =>
      [line, column, classification, command, reason]));
  const prefix = "AWS command in script text, not confirmed as executed: ";
  assert.deepEqual(await scanned('cmd="aws organizations list-accounts --max-items 10"\n$cmd'), [
    [1, 6, "UNKNOWN", "aws organizations list-accounts", `${prefix}IAM organizations:ListAccounts (List)`],
  ]);
  assert.deepEqual(await scanned('ssh example "aws --region us-east-1 ec2 terminate-instances --instance-ids fixture-secret"'), [
    [1, 14, "UNKNOWN", "aws ec2 terminate-instances", `${prefix}IAM ec2:TerminateInstances (Write)`],
  ]);
  assert.deepEqual(await scanned("cat <<EOF > run.sh\naws s3 ls\nEOF"), [
    [2, 1, "UNKNOWN", "aws s3 ls", `${prefix}lists S3 objects or buckets`],
  ]);
  assert.deepEqual(await scanned('echo "aws s3 rm s3://example/key" | bash'), [
    [1, 7, "UNKNOWN", "aws s3 rm", `${prefix}changes S3 resources`],
  ]);
  for (const source of [
    "aws s3 ls",
    'echo "run: aws s3 rm s3://example/key"',
    "sudo aws ec2 describe-instances | aws s3 cp - s3://example/key",
    "bash -c 'aws s3 ls'",
    "retry 3 aws ec2 describe-instances",
    "# aws s3 rm s3://example/key",
    "echo done # then run aws s3 rm s3://example/key",
    'echo "see the aws cli to assume role docs"',
  ]) assert.deepEqual(await scanned(source), [], source);
  const [flagged] = (await analyzeShell('cmd="aws ec2 terminate-instances"')).filter(({ source }) => source === "text scan");
  assert.equal(flagged.unknown_kind, "INLINE");
  const tagged = await analyzeShell('ssh example "aws ec2 create-tags --tags fixture-secret"');
  assert.doesNotMatch(JSON.stringify(tagged.filter(({ source }) => source === "text scan")), /fixture-secret/);
});

// Catches: Integrity (SAFETY) - a shell line that runs inline Python leaves no finding when the code is not an AWS call.
test("inline Python never disappears from a shell report", async () => {
  const rows: [string, [string, string][]][] = [
    [`python -c 'import os; os.execl("/bin/sh", "sh")'`, [["UNKNOWN", "Python subprocess command is not analysed"]]],
    [`python3 -c 'import pty; pty.spawn("/bin/sh")'`, [["UNKNOWN", "Python subprocess command is not analysed"]]],
    [`python3 -c 'open("out.txt", "w").write("fixture")'`,
      [["UNKNOWN", "inline Python is analysed only for AWS calls and process launches"]]],
    [`python3 -c 'import boto3; boto3.client("s3").list_buckets()'`, [["READ-ONLY", "IAM s3:ListAllMyBuckets (List)"]]],
  ];
  for (const [source, expected] of rows) {
    const findings = await analyzeShell(source);
    assert.deepEqual(findings.map((finding) => [finding.class, finding.reason]), expected, source);
  }
});
