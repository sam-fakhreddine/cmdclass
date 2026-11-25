import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { describe, test } from "node:test";
import fc from "fast-check";
import { classifySdkMethod } from "../src/aws/python.ts";
import { classifyOperation, loadOfflineSnapshot } from "../src/aws/operations.ts";
import { loadResources, resourceShape } from "../src/aws/resources.ts";
import { propertyOptions } from "./property-options.ts";
import { analyzePython } from "../src/python.ts";
import { analyzeShell, InputError } from "../src/shell.ts";

test("classifies imported clients, sessions, resources and overrides without rendering arguments", async () => {
  const findings = await analyzePython(`
import boto3 as aws
from boto3 import Session as AWSSession
session = AWSSession(profile_name="example")
service = "ec2"
c = session.client(service)
c.describe_instances()
c.terminate_instances(DryRun=True)
getattr(c, name)()
s3 = aws.resource("s3")
s3.Bucket("example").objects.all().delete()
sts = aws.client("sts")
sts.assume_role(RoleArn="synthetic-fixture-argument")
ssm = aws.client("ssm")
ssm.get_parameter(Name="example", WithDecryption=True)
ssm.get_parameter(Name="example", **options)
`);
  assert.deepEqual(findings.map(({ class: classification }) => classification),
    ["READ-ONLY", "DANGEROUS", "UNKNOWN", "DANGEROUS", "SENSITIVE", "SENSITIVE", "UNKNOWN"]);
  assert.deepEqual(findings[0].context, { profile: "example" });
  assert.match(findings[1].reason, /DryRun present/);
  assert.doesNotMatch(JSON.stringify(findings), /synthetic-fixture-argument/);
});

test("real CLI applies Python rules offline and rejects a malformed file without partial JSON", () => {
  for (const [fixture, status] of [["aws.py", 1], ["invalid.py", 2], ["empty-suite.py", 2]] as const) {
    const result = spawnSync(process.execPath, ["--permission", "--allow-fs-read=.",
      "src/cli.ts", "--json", `tests/fixtures/python/${fixture}`], { encoding: "utf8" });
    assert.equal(result.status, status, result.stderr);
    if (status === 2) {
      assert.equal(result.stdout, "");
      assert.match(result.stderr, /invalid Python syntax/);
    } else {
      assert.equal(result.stderr, "");
      assert.deepEqual(JSON.parse(result.stdout).entries.map((x: { class: string }) => x.class),
        ["DANGEROUS", "READ-ONLY"]);
    }
  }
});

test("resolves simple factories and instance attributes; unresolved receivers stay visible", async () => {
  const findings = await analyzePython(`
import boto3
def make_client():
    handle = boto3.client("s3")
    return handle
class Example:
    def __init__(self):
        self.ec2 = boto3.client("ec2")
    def inspect(self):
        self.ec2.describe_instances()
def operate(client):
    client.delete_bucket(Bucket="example")
make_client().list_buckets()
`);
  assert.deepEqual(findings.map(({ class: classification, command }) => [classification, command]),
    [["READ-ONLY", "describe_instances(...)"], ["UNKNOWN", "delete_bucket(...)"], ["READ-ONLY", "list_buckets(...)"]]);
  assert.equal(findings[1].reason, "client type not known (untyped function parameter)");
});

test("unknown client findings identify provenance without exposing source values", async () => {
  const rows = [
    [`import boto3\ndef operate(client):\n    client.delete_bucket(Bucket="fixture-secret")`, "untyped function parameter"],
    [`import boto3\ndef operate(client: object):\n    client.delete_bucket(Bucket="fixture-secret")`, "unsupported parameter annotation"],
    [`import boto3\nfrom custom_wrapper import client\nclient.delete_bucket(Bucket="fixture-secret")`, "untracked import"],
    [`import boto3\nclass Client:\n    pass\nClient.delete_bucket(Bucket="fixture-secret")`, "function or class binding"],
    [`import boto3\nclient = make_client()\nclient.delete_bucket(Bucket="fixture-secret")`, "unresolved assignment"],
    [`import boto3\nif condition:\n    client = make_client()\nelse:\n    client = make_client()\nclient.delete_bucket(Bucket="fixture-secret")`, "control-flow merge"],
  ] as const;
  for (const [source, origin] of rows) {
    const findings = await analyzePython(source);
    assert.equal(findings.at(-1)?.class, "UNKNOWN", origin);
    assert.equal(findings.at(-1)?.reason, `client type not known (${origin})`, origin);
    assert.doesNotMatch(JSON.stringify(findings), /fixture-secret|custom_wrapper|make_client/);
  }
});

test("reports Python process launches and proven AWS wrapper calls", async () => {
  const findings = await analyzePython(`
import subprocess
from subprocess import run as invoke
import os as operating_system
import asyncio

def aws(profile, *args):
    command = ["aws", "--profile", profile, *args]
    return subprocess.run(command, capture_output=True)

aws("example", "ec2", "create-tags", "--resources", "fixture-secret")
invoke(["aws", "sts", "get-caller-identity"])
operating_system.system("fixture-secret")
asyncio.create_subprocess_exec("aws", "ec2", "create-tags")
`);
  assert.deepEqual(findings.map(({ line, class: classification, reason }) =>
    [line, classification, reason]), [
    [9, "UNKNOWN", "Python subprocess command is not analysed"],
    [11, "DANGEROUS", "IAM ec2:CreateTags (Write); via Python subprocess"],
    [12, "UNKNOWN", "Python subprocess command is not analysed"],
    [12, "READ-ONLY", "IAM sts:GetCallerIdentity (Read); via Python subprocess"],
    [13, "UNKNOWN", "Python subprocess command is not analysed"],
    [14, "UNKNOWN", "Python subprocess command is not analysed"],
  ]);
  assert.doesNotMatch(JSON.stringify(findings), /fixture-secret/);
});

test("traces AWS wrapper arguments through profile, global options and dynamic trailing arguments", async () => {
  const findings = await analyzePython(`
import subprocess
REGION = "us-east-1"
def aws(profile, *args):
    command = ["aws", "--profile", profile, "--region", REGION, "--no-cli-pager", *args, "--output", "json"]
    result = subprocess.run(command, capture_output=True, timeout=90)
    return result
def main(profile, ids, desired):
    aws(profile, "sts", "get-caller-identity")
    aws(profile, "ec2", "describe-instances", "--instance-ids", *ids)
    aws(profile, "ec2", "create-tags", "--resources", *ids, "--tags", desired)
`);
  assert.deepEqual(findings.map(({ line, class: classification }) => [line, classification]), [
    [6, "UNKNOWN"], [9, "READ-ONLY"], [10, "READ-ONLY"], [11, "DANGEROUS"],
  ]);
  assert.match(findings[3].reason, /ec2:CreateTags/);
});

test("does not infer subprocess effects through dynamic commands or altered execution", async () => {
  const cases = [
    `import subprocess\ndef aws(profile, *args):\n command = ["aws", *args]\n return subprocess.run(command)\naws("p", *dynamic, "ec2", "create-tags")`,
    `import subprocess\ndef aws(profile, *args):\n command = ["aws", *args]\n command.insert(0, "echo")\n return subprocess.run(command)\naws("p", "ec2", "create-tags")`,
    `import subprocess\ndef aws(profile, *args):\n command = ["aws", *args]\n return subprocess.run(command, shell=True)\naws("p", "ec2", "create-tags")`,
    `import subprocess\ndef aws(profile, *args):\n command = ["aws", *args]\n return subprocess.run(command, shell=maybe)\naws("p", "ec2", "create-tags")`,
    `import subprocess\ndef aws(profile, *args):\n command = ["aws", *args]\n return subprocess.run(command, executable=program)\naws("p", "ec2", "create-tags")`,
    `import subprocess\ndef aws(profile, *args):\n command = ["aws", *args]\n return subprocess.run(command, **options)\naws("p", "ec2", "create-tags")`,
    `import subprocess\ndef aws(profile, *args):\n command = ["aws", *args]\n return subprocess.run(command)\naws("p", dynamic_service, "create-tags")`,
    `import subprocess\ndef aws(profile, *args):\n command = ["aws", *args]\n return subprocess.run(command)\naws("p", "ec2", dynamic_operation)`,
    `import subprocess\ndef aws(profile, *args):\n command = [program, *args]\n return subprocess.run(command)\naws("p", "ec2", "create-tags")`,
    `import subprocess\ndef aws(profile, *args):\n command = ["aws", *args]\n return subprocess.run(command)\naws = other\naws("p", "ec2", "create-tags")`,
  ];
  for (const source of cases) {
    const findings = await analyzePython(source);
    assert.deepEqual(findings.map(({ class: classification }) => classification), ["UNKNOWN"], source);
  }
});

test("classifies literal subprocess argv without suppressing process uncertainty", async () => {
  const findings = await analyzePython(`
import subprocess
subprocess.run(["aws", "ec2", "terminate-instances", "--instance-ids", dynamic])
subprocess.run(["aws", "ec2", "create-tags"], shell=True)
subprocess.run(["aws", "ec2", "create-tags"], executable=dynamic)
subprocess.run(["aws", *get_args(), "ec2", "describe-instances"])
`);
  assert.deepEqual(findings.map(({ line, class: classification }) => [line, classification]), [
    [3, "UNKNOWN"], [3, "DANGEROUS"], [4, "UNKNOWN"], [5, "UNKNOWN"], [6, "UNKNOWN"],
  ]);
});

test("process detection follows imports and respects reassignment", async () => {
  const findings = await analyzePython(`
import subprocess as sp
from subprocess import Popen
sp.run(["example"])
Popen("example", shell=True)
sp = other
sp.run(["example"])
`);
  assert.deepEqual(findings.map(({ line, class: classification }) => [line, classification]),
    [[4, "UNKNOWN"], [5, "UNKNOWN"]]);
});

test("CLI flags a subprocess wrapper instead of reporting an all-clear", () => {
  for (const json of [false, true]) {
    const result = spawnSync(process.execPath, ["--permission", "--allow-fs-read=.",
      "src/cli.ts", ...(json ? ["--json"] : []), "tests/fixtures/python/subprocess-wrapper.py"],
    { encoding: "utf8" });
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stdout, /Python subprocess command is not analysed/);
    assert.doesNotMatch(result.stdout + result.stderr, /fixture-secret/);
    assert.match(result.stdout, /ec2:CreateTags/);
    if (json) {
      assert.equal(JSON.parse(result.stdout).summary.UNKNOWN, 1);
      assert.equal(JSON.parse(result.stdout).summary.DANGEROUS, 1);
    }
  }
});

test("resolves annotated Boto3 sessions and preserves unsupported annotation uncertainty", async () => {
  const findings = await analyzePython(`
import boto3
from boto3 import Session as BotoSession

def qualified(session: boto3.Session):
    s3 = session.client("s3")
    s3.delete_bucket(Bucket="fixture-secret")

def imported(session: BotoSession):
    sts = session.client("sts")
    sts.get_caller_identity()

def unsupported(session: object):
    s3 = session.client("s3")
    s3.delete_bucket(Bucket="fixture-secret")
`);
  assert.deepEqual(findings.map(({ class: classification, command, reason }) =>
    [classification, command, reason]), [
    ["DANGEROUS", "delete_bucket(...)", "IAM s3:DeleteBucket (Write)"],
    ["READ-ONLY", "get_caller_identity(...)", "IAM sts:GetCallerIdentity (Read)"],
    ["UNKNOWN", "delete_bucket(...)", "client type not known (unresolved assignment)"],
  ]);
  assert.doesNotMatch(JSON.stringify(findings), /fixture-secret/);
});

test("SDK credential reads match shared AWS effects and keep arguments out of reports", async () => {
  const findings = await analyzePython(`
import boto3
boto3.client("secretsmanager").get_secret_value(SecretId="fixture-sensitive-arg")
boto3.client("kms").decrypt()
boto3.client("ecr").get_authorization_token()
boto3.client("rds").generate_db_auth_token()
boto3.client("iam").create_access_key()
boto3.client("ssm").get_parameters(WithDecryption=False)
boto3.client("ssm").get_parameters(**options)
boto3.client("ssm").start_session()
`);
  assert.deepEqual(findings.map(({ class: classification, reason }) => [classification, reason]), [
    ["SENSITIVE", "returns an existing secret value"],
    ["SENSITIVE", "returns decrypted plaintext"],
    ["SENSITIVE", "returns a registry authorization token"],
    ["SENSITIVE", "creates a short-lived database token"],
    ["DANGEROUS", "creates a long-lived AWS access key"],
    ["READ-ONLY", "reads parameters without decryption"],
    ["UNKNOWN", "SSM decryption option is dynamic"],
    ["DANGEROUS", "opens a session on a remote host"],
  ]);
  assert.doesNotMatch(JSON.stringify(findings), /fixture-sensitive-arg/);
});

test("direct calls to a simple untyped forwarder resolve the supplied SDK client", async () => {
  const findings = await analyzePython(`
import boto3
def operate(client):
    client.terminate_instances(DryRun=True)
ec2 = boto3.client("ec2")
operate(ec2)
operate(client=ec2)
operate(*dynamic_clients)
operate = another_callable
operate(ec2)
`);
  assert.deepEqual(findings.map(({ line, class: classification }) => [line, classification]), [
    [4, "UNKNOWN"], [6, "DANGEROUS"], [7, "DANGEROUS"],
  ]);
  assert.match(findings[1].reason, /DryRun present; via operate\(\)$/);
});

test("private helpers resolve untyped client parameters only when all direct callers agree", async () => {
  const findings = await analyzePython(`
import boto3
def _inspect(client):
    client.delete_bucket()
    client.list_buckets()
s3 = boto3.client("s3")
_inspect(s3)
_inspect(client=s3)
`);
  assert.deepEqual(findings.map(({ line, class: classification }) => [line, classification]), [
    [4, "DANGEROUS"], [5, "READ-ONLY"],
  ]);
});

test("public, escaping, mixed-service, and unknown-call helpers remain UNKNOWN", async () => {
  const cases = [
    [`import boto3\ndef inspect(client):\n    client.delete_bucket()\n    client.list_buckets()\ns3 = boto3.client("s3")\ninspect(s3)`, 2],
    [`import boto3\ndef _inspect(client):\n    client.delete_bucket()\n    client.list_buckets()\ns3 = boto3.client("s3")\nalias = _inspect\n_inspect(s3)`, 2],
    [`import boto3\ndef _inspect(client):\n    client.delete_bucket()\n    client.list_buckets()\ns3 = boto3.client("s3")\nec2 = boto3.client("ec2")\n_inspect(s3)\n_inspect(ec2)`, 2],
    [`import boto3\ndef _inspect(client):\n    client.delete_bucket()\n    client.list_buckets()\ndef caller(client):\n    _inspect(client)\ns3 = boto3.client("s3")\n_inspect(s3)\ncaller(dynamic_client)`, 2],
    [`import boto3\ndef _inspect(client):\n    client.delete_bucket()\n    client.list_buckets()\ns3 = boto3.client("s3")\n_inspect(s3)\n_inspect(*clients)`, 2],
    [`__all__ = build_exports()\nimport boto3\ndef _inspect(client):\n    client.delete_bucket()\n    client.list_buckets()\ns3 = boto3.client("s3")\n_inspect(s3)`, 2],
  ] as const;
  for (const [source, unknownCount] of cases) {
    const findings = await analyzePython(source);
    assert.equal(findings.filter(({ class: classification }) => classification === "UNKNOWN").length,
      unknownCount);
  }
});

test("SDK-only transfer helpers classify local downloads and remote writes", () => {
  for (const [method, expected] of [
    ["upload_fileobj", "DANGEROUS"], ["copy", "DANGEROUS"], ["download_fileobj", "LOCAL"],
  ]) {
    assert.equal(classifySdkMethod(undefined, "s3", method, {}).class, expected, method);
  }
});

test("SDK helpers, typed clients, and low-level sessions use the shared AWS policy", async () => {
  const findings = await analyzePython(`
import boto3
import botocore.session
c = boto3.client("s3")
c.get_paginator("list_objects_v2")
c.upload_file("example", "example", "example")
c.download_file("example", "example", "example")
c.generate_presigned_url("get_object")
c.generate_presigned_post("example", "example")
ec2 = botocore.session.get_session().create_client("ec2")
ec2.get_waiter("instance_running")
def never_called(client: S3Client):
    client.delete_bucket(Bucket="example")
`);
  assert.deepEqual(findings.map(({ class: classification }) => classification),
    ["READ-ONLY", "DANGEROUS", "LOCAL", "DANGEROUS", "DANGEROUS", "READ-ONLY", "DANGEROUS"]);
});

test("vendored resource models resolve actions and returned resource types across services", async () => {
  const findings = await analyzePython(`
import boto3
ec2 = boto3.resource("ec2")
ec2.Instance("example").terminate()
ec2.instances.filter(Filters=[]).terminate()
sqs = boto3.resource("sqs")
queue = sqs.create_queue(QueueName="example")
queue.send_message(MessageBody="example")
queue.fixture_unmapped()
sns = boto3.resource("sns")
sns.Topic("example").publish(Message="example")
`);
  assert.deepEqual(findings.map(({ class: classification, source }) => [classification, source]), [
    ["DANGEROUS", "IAM ec2:TerminateInstances (Write)"],
    ["DANGEROUS", "IAM ec2:TerminateInstances (Write)"],
    ["DANGEROUS", "IAM sqs:CreateQueue (Write)"],
    ["DANGEROUS", "IAM sqs:SendMessage (Write)"],
    ["UNKNOWN", "AWS"],
    ["DANGEROUS", "IAM sns:Publish (Write)"],
  ]);
});

test("client coverage is independent of the high-level resource catalog", async () => {
  const findings = await analyzePython(`
import boto3
client = boto3.client("lambda")
client.list_functions()
service = boto3.resource("lambda")
service.list_functions()
`);
  assert.deepEqual(findings.map(({ class: classification, source }) => [classification, source]), [
    ["READ-ONLY", "IAM lambda:ListFunctions (List)"],
    ["UNKNOWN", "AWS"],
  ]);
});

test("the packaged S3 model resolves object deletes and collection deletes to different IAM operations", async () => {
  const [catalog, snapshot] = await Promise.all([loadResources(), loadOfflineSnapshot()]);
  assert.ok(snapshot);
  const service = resourceShape(catalog, "s3", undefined);
  const bucket = resourceShape(catalog, "s3", service?.constructors.Bucket);
  assert.equal(service?.constructors.Object, "Object");
  assert.equal(bucket?.constructors.Object, service.constructors.Object);
  const object = resourceShape(catalog, "s3", service.constructors.Object);
  const objects = resourceShape(catalog, "s3", bucket?.collections.objects);
  for (const [action, operation] of [
    [object?.actions.delete, "DeleteObject"],
    [objects?.batch.delete, "DeleteObjects"],
  ] as const) {
    assert.ok(action);
    assert.equal(action.operation, operation);
    assert.equal(classifyOperation(snapshot, "s3", action.operation).class, "DANGEROUS");
  }
});

test("alternative Python branches resolve clients separately, then merge conservatively", async () => {
  const findings = await analyzePython(`
import boto3
client = boto3.client("s3")
if condition:
    client = boto3.client("ec2")
    client.terminate_instances(InstanceIds=["example"])
else:
    client.list_buckets()
client.list_buckets()
`);
  assert.deepEqual(findings.map(({ line, class: classification }) => [line, classification]),
    [[6, "DANGEROUS"], [8, "READ-ONLY"], [9, "UNKNOWN"]]);
});

test("mock scopes annotate rather than suppress effects, and dynamic API lookup stays UNKNOWN", async () => {
  const findings = await analyzePython(`
import boto3
from botocore.stub import Stubber
from moto import mock_aws as mock
first = boto3.client("s3")
other = boto3.client("s3")
@mock
def test_delete():
    first.delete_bucket(Bucket="example")
with Stubber(first) as stub:
    first.delete_bucket(Bucket="example")
    other.delete_bucket(Bucket="example")
first.delete_bucket(Bucket="example")
first.meta.method_to_api_mapping
`);
  assert.deepEqual(findings.map(({ line, class: classification, reason }) =>
    [line, classification, reason.includes("inside a test")]), [
    [9, "DANGEROUS", true], [11, "DANGEROUS", true], [12, "DANGEROUS", false],
    [13, "DANGEROUS", false], [14, "UNKNOWN", false],
  ]);
  assert.equal(findings.at(-1)?.reason, "method name is dynamic");
});

test("shell maps inline Python and heredoc findings and errors to the original script", async () => {
  const findings = await analyzeShell(`python3 -c 'import boto3; boto3.client("s3").list_buckets()'
python <<'PY'
import boto3
boto3.client("s3").delete_bucket(Bucket="example")
PY
`);
  assert.deepEqual(findings.map(({ line, class: classification }) => [line, classification]),
    [[1, "READ-ONLY"], [4, "DANGEROUS"]]);
  await assert.rejects(() => analyzeShell("echo ok\npython -c 'import boto3; boto3.client('"),
    (error) => error instanceof InputError && error.line === 2);
});

describe("TestProperties", () => {
  // Catches: Integrity (SAFETY) - dynamic executable or operation is classified as a known AWS call.
  test("AWS subprocess classification requires a known executable, service, and operation", async () => {
    await fc.assert(fc.asyncProperty(
      fc.constantFrom(
        ["ec2", "create-tags", "DANGEROUS"],
        ["s3api", "delete-bucket", "DANGEROUS"],
        ["sts", "get-caller-identity", "READ-ONLY"],
      ),
      fc.integer({ min: 0, max: 2 }),
      fc.stringMatching(/^[A-Za-z0-9_]{1,20}$/),
      async ([service, operation, classification], dynamicPosition, marker) => {
        const secret = `fixture_process_${marker}`;
        const words = ['"aws"', `"${service}"`, `"${operation}"`];
        const source = (prefix: string[]) =>
          `import subprocess\nsubprocess.run([${prefix.join(", ")}, "${secret}"])`;
        const known = await analyzePython(source(words));
        assert.deepEqual(known.map(({ class: result }) => result), ["UNKNOWN", classification]);
        assert.doesNotMatch(JSON.stringify(known), new RegExp(secret));
        words[dynamicPosition] = "unknown_value";
        const unknown = await analyzePython(source(words));
        assert.deepEqual(unknown.map(({ class: result }) => result), ["UNKNOWN"]);
      },
    ), propertyOptions);
  });

  // Catches: Integrity (SAFETY) - a Python process launch yields an empty or safe report.
  test("dynamic process arguments stay UNKNOWN without leaking source values", async () => {
    await fc.assert(fc.asyncProperty(
      fc.constantFrom("run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput"),
      fc.stringMatching(/^[A-Za-z0-9_]{1,20}$/),
      async (method, marker) => {
        const secret = `fixture_secret_${marker}`;
        const findings = await analyzePython(
          `import subprocess as sp\nsp.${method}(["${secret}"], shell=dynamic_option)`);
        assert.deepEqual(findings.map(({ class: classification }) => classification), ["UNKNOWN"]);
        assert.doesNotMatch(JSON.stringify(findings), new RegExp(secret));
      },
    ), propertyOptions);
  });

  // Catches: Integrity (SAFETY) - malformed Python yields findings after a valid prefix.
  test("rejects malformed Python after generated valid prefixes", async () => {
    await fc.assert(fc.asyncProperty(fc.integer({ min: 0, max: 12 }),
      fc.constantFrom("boto3.client(", "if True:\n", "value = '"),
      async (count, invalid) => {
        await assert.rejects(() => analyzePython(`import boto3\n${"boto3.client('s3').list_buckets()\n".repeat(count)}${invalid}`),
          InputError);
      }), propertyOptions);
  });

  // Catches: Integrity (SAFETY) - a dynamic service or unrecognized method is labeled READ-ONLY.
  test("unknown service and method combinations stay UNKNOWN", async () => {
    await fc.assert(fc.asyncProperty(fc.nat(), fc.boolean(), async (id, dynamic) => {
      const service = dynamic ? "external_service" : "'s3'";
      const findings = await analyzePython(`import boto3\nclient = boto3.client(${service})\nclient.fixture_${id}()\n`);
      assert.equal(findings.length, 1);
      assert.equal(findings[0].class, "UNKNOWN");
      assert.match(findings[0].reason, dynamic ? /^service is in a variable$/ :
        /^method not in AWS data snapshot \d{4}-\d\d-\d\d$/);
    }), propertyOptions);
  });

  // Catches: Confidentiality (SAFETY) - client provenance diagnostics leak source-level values.
  test("client provenance reasons do not expose parameter names or arguments", async () => {
    await fc.assert(fc.asyncProperty(
      fc.stringMatching(/^[A-Za-z][A-Za-z0-9_]{0,15}$/),
      fc.stringMatching(/^[A-Za-z0-9_-]{1,24}$/),
      async (parameter, marker) => {
        const parameterName = `user_${parameter}_arg`;
        const argument = `secret_${marker}_value`;
        const findings = await analyzePython(
          `import boto3\ndef operate(${parameterName}):\n    ${parameterName}.delete_bucket(Bucket="${argument}")`);
        assert.equal(findings.length, 1);
        assert.equal(findings[0].class, "UNKNOWN");
        assert.equal(findings[0].reason, "client type not known (untyped function parameter)");
        assert.doesNotMatch(JSON.stringify(findings), new RegExp(parameterName));
        assert.doesNotMatch(JSON.stringify(findings), new RegExp(argument));
      },
    ), propertyOptions);
  });

  // Catches: Integrity (SAFETY) - an unsupported parameter annotation is treated as a Boto3 session.
  test("only imported Boto3 Session types establish session provenance", async () => {
    await fc.assert(fc.asyncProperty(
      fc.constantFrom(
        ["import boto3", "boto3.Session"],
        ["from boto3 import Session as BotoSession", "BotoSession"],
        ["from boto3.session import Session", "Session"],
      ),
      async ([importLine, annotation]) => {
        const valid = await analyzePython(
          `${importLine}\ndef inspect(session: ${annotation}):\n` +
          `    client = session.client("s3")\n    client.delete_bucket(Bucket="fixture")`);
        assert.deepEqual(valid.map(({ class: classification }) => classification), ["DANGEROUS"]);

        const unsupported = await analyzePython(
          `import boto3\ndef inspect(session: object):\n` +
          `    client = session.client("s3")\n    client.delete_bucket(Bucket="fixture")`);
        assert.deepEqual(unsupported.map(({ class: classification }) => classification), ["UNKNOWN"]);
        assert.equal(unsupported[0].reason, "client type not known (unresolved assignment)");
      },
    ), propertyOptions);
  });

  // Catches: Integrity (SAFETY) - only matching proven callers establish private-helper client provenance.
  test("private helper provenance requires all direct callers to agree", async () => {
    await fc.assert(fc.asyncProperty(
      fc.constantFrom(
        ["s3", "delete_bucket", "list_buckets", "DANGEROUS"],
        ["ec2", "terminate_instances", "describe_instances", "DANGEROUS"],
        ["kms", "create_key", "describe_key", "DANGEROUS"],
      ),
      fc.integer({ min: 1, max: 4 }),
      fc.stringMatching(/^[A-Za-z][A-Za-z0-9_]{0,15}$/),
      async ([service, writeMethod, readMethod, classification], callerCount, parameter) => {
        const parameterName = `client_${parameter}`;
        const calls = Array.from({ length: callerCount }, () => `_inspect(client)`).join("\n");
        const findings = await analyzePython(
          `import boto3\ndef _inspect(${parameterName}):\n` +
          `    ${parameterName}.${writeMethod}()\n    ${parameterName}.${readMethod}()\n` +
          `client = boto3.client("${service}")\n${calls}`);
        assert.deepEqual(findings.map(({ class: result }) => result), [classification, "READ-ONLY"]);
        assert.doesNotMatch(JSON.stringify(findings), new RegExp(parameterName));

        const conflicting = await analyzePython(
          `import boto3\ndef _inspect(${parameterName}):\n` +
          `    ${parameterName}.${writeMethod}()\n    ${parameterName}.${readMethod}()\n` +
          `client = boto3.client("${service}")\nother = boto3.client("lambda")\n` +
          `_inspect(client)\n_inspect(other)`);
        assert.deepEqual(conflicting.map(({ class: result }) => result), ["UNKNOWN", "UNKNOWN"]);
      },
    ), propertyOptions);
  });
});
