import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { analyzePython } from "../src/python.ts";

const rows = async (source: string) => (await analyzePython(source))
  .map(({ line, class: classification, command, reason }) => [line, classification, command, reason]);
const inferredFromCallers = "client inferred from call sites in this file";

// Catches: Integrity (SAFETY) - an SDK call on a receiver the analyzer cannot trace is dropped from the report.
test("SDK calls on untraceable receivers stay visible as UNKNOWN", async () => {
  const cases: [string, string, unknown[][]][] = [
    ["instance attribute set from an untyped constructor parameter", `
import boto3
class Scanner:
    def __init__(self, ec2_client):
        self.ec2 = ec2_client
    def scan(self):
        self.ec2.get_paginator("describe_volumes")
        self.ec2.delete_volume(VolumeId="fixture-secret")
`, [
      [7, "UNKNOWN", "get_paginator(...)", "client type not known (untyped function parameter)"],
      [8, "UNKNOWN", "delete_volume(...)", "client type not known (untyped function parameter)"],
    ]],
    ["tuple unpacked from an unknown callable", `
import boto3
from helpers import connect
ec2, region = connect(profile)
ec2.describe_volumes()
`, [[5, "UNKNOWN", "describe_volumes(...)", "client type not known (unresolved assignment)"]]],
    ["chained call result", `
import boto3
registry.lookup(name).terminate_instances(InstanceIds=ids)
`, [[3, "UNKNOWN", "terminate_instances(...)", "client type not known (unresolved call result)"]]],
    ["loop variable that shadows a client, and a waiter", `
import boto3
client = boto3.client("s3")
for client in clients:
    client.get_waiter("instance_running")
`, [[5, "UNKNOWN", "get_waiter(...)", "client type not known (unresolved assignment)"]]],
    ["name that is never bound in the file", `
import boto3
def cleanup():
    ec2_client.delete_volume(VolumeId="fixture-secret")
`, [[4, "UNKNOWN", "delete_volume(...)", "client type not known (unresolved name)"]]],
    ["bound method handed to an executor", `
import boto3
def run(pool, client):
    pool.submit(client.delete_volume, VolumeId="fixture-secret")
`, [[4, "UNKNOWN", "delete_volume(...)", "client type not known (untyped function parameter)"]]],
    ["a long call chain is resolved once per link", `
import boto3
value = frame${".step()".repeat(40)}.describe_volumes()
`, [[3, "UNKNOWN", "describe_volumes(...)", "client type not known (unresolved call result)"]]],
    ["a distinctive SDK method is reported even when the file never imports the SDK", `
def run(client):
    client.delete_volume()
`, [[3, "UNKNOWN", "delete_volume(...)", "client type not known (untyped function parameter)"]]],
    ["a one-word method needs AWS evidence in the file", `
def run(index):
    index.search("fixture-secret")
`, []],
    ["a method defined on the same class is not an SDK call", `
import boto3
class Table:
    def scan(self):
        return []
    def load(self):
        return self.scan()
`, []],
  ];
  for (const [name, source, expected] of cases) {
    const findings = await analyzePython(source);
    assert.deepEqual(findings.map(({ line, class: classification, command, reason }) =>
      [line, classification, command, reason]), expected, name);
    assert.doesNotMatch(JSON.stringify(findings), /fixture-secret/, name);
  }
});

// Catches: Integrity (SAFETY) - a client passed through functions, constructors and methods loses its service.
test("clients are followed from call sites into public functions, constructors and methods", async () => {
  const findings = await rows(`
import boto3
def run_command(ssm_client, instance_id, timeout=300):
    response = ssm_client.send_command(InstanceIds=[instance_id])
    return response
def collect(ssm_client, instance_id):
    return run_command(ssm_client, instance_id)
class Scanner:
    def __init__(self, ec2_client, days: int):
        self.ec2 = ec2_client
        self.days = days
    def scan(self):
        self.ec2.get_paginator("describe_volumes")
        self._remove("example")
    def _remove(self, volume_id):
        self.ec2.delete_volume(VolumeId=volume_id)
def main():
    session = boto3.Session(profile_name="example")
    collect(session.client("ssm"), "example")
    Scanner(session.client("ec2"), 7).scan()
`);
  assert.deepEqual(findings.map(([line, classification, command]) => [line, classification, command]), [
    [4, "MUTATING", "send_command(...)"],
    [13, "READ-ONLY", "get_paginator(...)"],
    [16, "MUTATING", "delete_volume(...)"],
  ]);
  assert.equal(findings[1][3], `IAM ec2:DescribeVolumes (List); ${inferredFromCallers}`);
  assert.equal(findings[2][3], `IAM ec2:DeleteVolume (Write); ${inferredFromCallers}`);
  assert.ok(String(findings[0][3]).endsWith(inferredFromCallers));
  const injected = await rows(`
import boto3
class Pipelines:
    def __init__(self, region, boto_client=None):
        self.client = boto_client or boto3.client("codepipeline", region_name=region)
    def names(self):
        return self.client.get_paginator("list_pipelines")
Pipelines("us-east-1").names()
`);
  assert.deepEqual(injected, [[7, "READ-ONLY", "get_paginator(...)",
    `IAM codepipeline:ListPipelines (List); ${inferredFromCallers}`]]);
});

// Catches: Integrity (SAFETY) - disagreeing or unseen callers still yield a single guessed service.
test("call-site inference stops when callers disagree or the function escapes", async () => {
  const body = "def inspect(client):\n    client.describe_volumes()\n    client.delete_volume()\n";
  const cases = [
    `import boto3\n${body}inspect(boto3.client("ec2"))\ninspect(boto3.client("s3"))`,
    `import boto3\n${body}handlers = [inspect]\ninspect(boto3.client("ec2"))`,
    `import boto3\n${body}inspect(boto3.client("ec2"))\ninspect(*clients)`,
  ];
  for (const source of cases) {
    const findings = await rows(source);
    assert.deepEqual(findings.map(([line, classification, , reason]) => [line, classification, reason]), [
      [3, "UNKNOWN", "client type not known (untyped function parameter)"],
      [4, "UNKNOWN", "client type not known (untyped function parameter)"],
    ], source);
  }
  const agreed = await rows(`import boto3\n${body}inspect(boto3.client("ec2"))\ninspect(client=boto3.client("ec2"))`);
  assert.deepEqual(agreed.map(([line, classification]) => [line, classification]),
    [[3, "READ-ONLY"], [4, "MUTATING"]]);
  assert.ok(agreed.every(([, , , reason]) => String(reason).endsWith(inferredFromCallers)));
  for (const call of ["pool.submit(inspect, boto3.client(\"ec2\"))", "Thread(target=inspect, args=(boto3.client(\"ec2\"),))"]) {
    const deferred = await rows(`import boto3\n${body}${call}`);
    assert.deepEqual(deferred.map(([line, classification]) => [line, classification]),
      [[3, "READ-ONLY"], [4, "MUTATING"]], call);
  }
  const maybeExported = await rows(`__all__ = build_exports()\nimport boto3\n${body.replaceAll("inspect", "_inspect")}_inspect(boto3.client("ec2"))`);
  assert.deepEqual(maybeExported.map(([line, classification, , reason]) => [line, classification, String(reason).endsWith(inferredFromCallers)]),
    [[4, "READ-ONLY", true], [5, "MUTATING", true]]);
});

// Catches: Integrity (SAFETY) - a wrapper factory hides the service, or an untraceable factory is guessed.
test("client factories are followed through service parameters, tuples and lazy properties", async () => {
  const findings = await rows(`
import boto3
class Manager:
    def __init__(self, profile):
        self._session = None
        self._clients = {}
        self.profile = profile
    @property
    def session(self):
        if not self._session:
            self._session = boto3.Session(profile_name=self.profile)
        return self._session
    def get_client(self, service):
        if service not in self._clients:
            self._clients[service] = self.session.client(service)
        return self._clients[service]
def create_client(service, profile):
    session = boto3.Session(profile_name=profile)
    return session.client(service), profile
def main(profile):
    manager = Manager(profile)
    manager.get_client("sts").get_caller_identity()
    ec2, _ = create_client("ec2", profile)
    ec2.describe_volumes()
    other = lookup("ec2")
    other.describe_volumes()
    dynamic = manager.get_client(pick())
    dynamic.describe_volumes()
`);
  assert.deepEqual(findings, [
    [22, "READ-ONLY", "get_caller_identity(...)", "IAM sts:GetCallerIdentity (Read)"],
    [24, "READ-ONLY", "describe_volumes(...)", "IAM ec2:DescribeVolumes (List)"],
    [26, "UNKNOWN", "describe_volumes(...)", "client type not known (unresolved assignment)"],
    [28, "UNKNOWN", "describe_volumes(...)", "service is in a variable"],
  ]);
});

// Catches: Integrity (SAFETY) - calls behind an imported project helper or base class are dropped.
test("imports of project modules are followed for factories, helpers and base classes", () => {
  const result = spawnSync(process.execPath, ["--permission", "--allow-fs-read=.", "src/cli.ts", "--json",
    "tests/fixtures/python/imports/scripts/report.py"], { encoding: "utf8" });
  assert.equal(result.status, 1, result.stderr);
  const entries = JSON.parse(result.stdout).entries.map((entry: { line: number; class: string; command: string; reason: string }) =>
    [entry.line, entry.class, entry.command, entry.reason]);
  assert.deepEqual(entries, [
    [21, "UNKNOWN", "describe_volumes(...)", "client type not known (unresolved assignment)"],
    [13, "READ-ONLY", "describe_domain(...)", "IAM es:DescribeDomain (Read)"],
    [18, "READ-ONLY", "describe_volumes(...)", "IAM ec2:DescribeVolumes (List)"],
    [19, "READ-ONLY", "get_caller_identity(...)", "IAM sts:GetCallerIdentity (Read); in an imported function"],
  ]);
});

// Catches: Integrity (SAFETY) - an SDK method passed as a callback, or a session credential read, is not reported.
test("bound SDK methods passed as callbacks and session credential reads are reported", async () => {
  const findings = await rows(`
import asyncio
import boto3
cloudwatch = boto3.client("cloudwatch")
def throttle(operation, **kwargs):
    return operation(**kwargs)
throttle(cloudwatch.put_metric_alarm, AlarmName="example")
async def main():
    sts = boto3.client("sts")
    await asyncio.to_thread(sts.get_caller_identity)
session = boto3.Session()
session.get_credentials()
`);
  assert.deepEqual(findings.map(([line, classification, command]) => [line, classification, command]), [
    [7, "MUTATING", "put_metric_alarm(...)"],
    [10, "READ-ONLY", "get_caller_identity(...)"],
    [12, "SENSITIVE", "get_credentials(...)"],
  ]);
  assert.equal(findings[0][3], "IAM cloudwatch:PutMetricAlarm (Write); method reference, call site not analysed");
  assert.equal(findings[2][3], "returns AWS credentials from the session");
});

// Catches: Integrity (SAFETY) - the permissions report omits wrapped calls or hides calls it could not resolve.
test("permissions mode lists wrapped calls and gives candidates for unresolved ones", () => {
  const run = (...args: string[]) => spawnSync(process.execPath, ["--permission", "--allow-fs-read=.",
    "src/cli.ts", ...args, "tests/fixtures/python/aws-wrappers.py"], { encoding: "utf8" });
  const result = run("--permissions", "--json");
  assert.equal(result.status, 1, result.stderr);
  const report = JSON.parse(result.stdout);
  const actions = report.actions.map((entry: { action: string }) => entry.action);
  for (const action of ["cloudwatch:DescribeAlarms", "cloudwatch:PutMetricAlarm", "ec2:DescribeVolumes",
    "ec2:DeleteVolume", "ssm:SendCommand", "sts:GetCallerIdentity"]) {
    assert.ok(actions.includes(action), action);
  }
  assert.ok(!actions.includes("ssm:GetCommandInvocation"));
  const unresolved = report.unknown.filter((entry: { line: number }) => entry.line === 48);
  assert.equal(unresolved.length, 1);
  assert.equal(unresolved[0].reason, "client type not known (untyped function parameter); " +
    "if this is an AWS client call, candidate actions: ssm:GetCommandInvocation");
  const assumed = report.unknown.filter((entry: { line: number }) => entry.line === 70);
  assert.equal(assumed[0]?.reason, "client type not known (unresolved assignment); " +
    "if the receiver is a boto3 session, candidate actions: rds:DescribeDBInstances");
  const text = run("--permissions");
  assert.match(text.stdout, /not a proven minimum/);
  assert.match(text.stdout, /cannot be traced is listed as UNKNOWN/);
});

// Catches: Integrity (SAFETY) - an UNKNOWN is labelled as decided inside the file when it depends on code outside it, or the reverse.
test("UNKNOWN findings say whether the uncertainty is inline or an external call", async () => {
  const cases: [string, string, (string | undefined)[]][] = [
    ["client handed in by a caller that is not in the file",
      `import boto3\ndef run(client):\n    client.delete_volume()`, ["EXTERNAL CALL"]],
    ["object imported from a module that is not followed",
      `import boto3\nfrom custom_wrapper import client\nclient.delete_bucket()`, ["EXTERNAL CALL"]],
    ["result of a call into a module that is not followed",
      `import boto3\nfrom helpers import connect\nec2 = connect()\nec2.describe_volumes()`, ["EXTERNAL CALL"]],
    ["in-file function that returns the result of an outside call",
      `import boto3\nfrom helpers import connect\ndef make():\n    return connect()\nec2 = make()\nec2.describe_volumes()`,
      ["EXTERNAL CALL"]],
    ["service name passed in by a caller",
      `import boto3\ndef run(service):\n    boto3.client(service).describe_volumes()`, ["EXTERNAL CALL"]],
    ["process launch", `import subprocess\nsubprocess.run(command)`, ["EXTERNAL CALL"]],
    ["private helper whose callers in the file disagree",
      `import boto3\ndef _inspect(client):\n    client.describe_volumes()\n    client.delete_volume()\n` +
      `_inspect(boto3.client("ec2"))\n_inspect(boto3.client("s3"))`, ["INLINE", "INLINE"]],
    ["service name computed in the file",
      `import boto3\nfor service in ["ec2", "s3"]:\n    boto3.client(service).describe_volumes()`, ["INLINE"]],
    ["client taken from a container built in the file",
      `import boto3\nclients = {}\nclients["ec2"].describe_volumes()`, ["INLINE"]],
    ["method name built at runtime",
      `import boto3\nc = boto3.client("ec2")\ngetattr(c, "describe_" + "volumes")()`, ["INLINE"]],
    ["a call the snapshot does not know has no sub-label",
      `import boto3\nboto3.client("s3").fixture_unmapped()`, [undefined]],
    ["a resolved call has no sub-label", `import boto3\nboto3.client("s3").list_buckets()`, [undefined]],
  ];
  for (const [name, source, expected] of cases) {
    const findings = await analyzePython(source);
    assert.deepEqual(findings.map((finding) => finding.unknown_kind), expected, name);
    assert.ok(findings.every((finding) => finding.class === "UNKNOWN" || finding.unknown_kind === undefined), name);
  }
});

// Catches: Integrity (SAFETY) - the sub-label is computed but never reaches the text, JSON or permissions output.
test("the unknown sub-label is shown in text, JSON and permissions output", () => {
  const run = (...args: string[]) => spawnSync(process.execPath, ["--permission", "--allow-fs-read=.",
    "src/cli.ts", ...args, "tests/fixtures/python/aws-wrappers.py"], { encoding: "utf8" });
  assert.match(run().stdout,
    /^UNKNOWN +48:12 +get_command_invocation\(\.\.\.\) +EXTERNAL CALL: client type not known \(untyped function parameter\)$/m);
  const report = JSON.parse(run("--json").stdout);
  assert.equal(report.schema_version, 2);
  const unknown = report.entries.filter((entry: { class: string }) => entry.class === "UNKNOWN");
  assert.deepEqual(unknown.map((entry: { line: number; unknown_kind: string }) => [entry.line, entry.unknown_kind]),
    [[48, "EXTERNAL CALL"], [70, "EXTERNAL CALL"]]);
  const permissions = JSON.parse(run("--permissions", "--json").stdout);
  assert.deepEqual(permissions.unknown.filter((entry: { line: number }) => entry.line === 48)
    .map((entry: { unknown_kind: string }) => entry.unknown_kind), ["EXTERNAL CALL"]);
  assert.match(run("--permissions").stdout, /^UNKNOWN .*:48:12: EXTERNAL CALL: client type not known/m);
});
