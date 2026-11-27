import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rmdir, unlink, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { test } from "node:test";
import fc from "fast-check";
import { propertyOptions } from "./property-options.ts";
import { classifyCliOperation, classifyOperation } from "../src/aws/operations.ts";
import { projectReference, readSnapshot, updateSnapshot } from "../src/aws-data.ts";
import type { Snapshot } from "../src/aws-data.ts";
import { analyzeShell } from "../src/shell.ts";
import { analyzePython } from "../src/python.ts";

test("provider rules distinguish context, sensitive output, mutations and unknown commands", async () => {
  const findings = await analyzeShell([
    "kubectl --context example get pods > output",
    "kubectl get secrets -o json",
    "kubectl get pod,secrets -o json",
    "vault kv get example",
    "gcloud auth print-access-token",
    "helm upgrade example ./chart",
    "npm install",
    "git example",
  ].join("\n"));
  assert.deepEqual(findings.map(({ class: classification }) => classification),
    ["LOCAL", "SENSITIVE", "UNKNOWN", "SENSITIVE", "SENSITIVE", "MUTATING", "UNKNOWN", "UNKNOWN"]);
  assert.deepEqual(findings[0].context, { kube_context: "example" });
});

test("registered providers and aliases have independently labeled representative cases", async () => {
  const rows = [
    ["helm list", "READ-ONLY"], ["terraform workspace select example", "LOCAL"],
    ["pulumi destroy --stack example", "MUTATING"], ["gcloud compute instances list", "READ-ONLY"],
    ["az account get-access-token", "SENSITIVE"], ["vault kv put example key=value", "MUTATING"],
    ["gh auth token", "SENSITIVE"], ["docker push example.invalid/image", "MUTATING"],
    ["podman ps", "READ-ONLY"], ["cdk synth", "LOCAL"], ["sam build", "LOCAL"],
    ["serverless deploy", "MUTATING"], ["sls remove", "MUTATING"],
    ["ansible-playbook example.yml", "MUTATING"], ["npm view example", "READ-ONLY"],
    ["yarn install", "UNKNOWN"], ["pnpm publish", "MUTATING"], ["twine upload example", "MUTATING"],
    ["gem install example", "LOCAL"], ["cargo check", "LOCAL"], ["psql -X -c 'SELECT 1'", "READ-ONLY"],
    ["mysql --no-defaults -e 'SELECT 1'", "READ-ONLY"], ["mongosh --eval '1'", "UNKNOWN"],
    ["mongo --eval '1'", "UNKNOWN"], ["redis-cli GET example", "UNKNOWN"],
  ] as const;
  const findings = await analyzeShell(rows.map(([command]) => command).join("\n"));
  assert.equal(findings.length, rows.length);
  for (const [index, [command, classification]] of rows.entries()) {
    assert.equal(findings[index].class, classification, command);
  }
});

test("context flags override command assignments, while dynamic values and ordinary arguments do not invent context", () => {
  const source = [
    "TF_WORKSPACE=assigned terraform apply",
    "TF_WORKSPACE=assigned terraform apply --workspace explicit",
    "env CLOUDSDK_CORE_PROJECT=assigned gcloud compute instances delete example",
    "AWS_PROFILE=$PROFILE aws s3 ls",
    "aws s3 ls AWS_PROFILE=argument",
    "sudo -u TF_WORKSPACE=argument terraform apply",
  ].join("\n");
  const run = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import { analyzeShell } from "./src/shell.ts";
    console.log(JSON.stringify((await analyzeShell(process.argv[1])).map(item => item.context ?? null)));
  `, source], { encoding: "utf8", env: { ...process.env, TF_WORKSPACE: "inherited", AWS_PROFILE: "inherited" } });
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), [
    { terraform_workspace: "assigned" }, { terraform_workspace: "explicit" },
    { gcloud_project: "assigned" }, null, { profile: "inherited" }, { terraform_workspace: "inherited" },
  ]);
});

test("database rules distinguish isolated reads, mutations, and ambiguous SQL without rendering queries", async () => {
  const findings = await analyzeShell([
    "psql -X -c 'SELECT 42;'",
    "psql -c 'SELECT 42;'",
    "psql -X -c 'SELECT example_function()'",
    "mysql --no-defaults -e 'SELECT 1; DELETE FROM example'",
    "mysql -e 'UPDATE example SET value=1'",
    "redis-cli EXISTS example",
    "redis-cli DEL example",
    "redis-cli -h example.invalid DEL example",
  ].join("\n"));
  assert.deepEqual(findings.map(({ class: classification }) => classification),
    ["READ-ONLY", "UNKNOWN", "UNKNOWN", "UNKNOWN", "MUTATING", "READ-ONLY", "MUTATING", "UNKNOWN"]);
  assert.ok(findings.every(({ command }) => command === "<shell text omitted>"));
});

test("CLI classifies mapped AWS calls and applies credential and profile overrides offline", () => {
  const result = spawnSync(process.execPath, [
    "--permission", "--allow-fs-read=.", "src/cli.ts", "--json", "tests/fixtures/shell/aws.sh",
  ], { encoding: "utf8", env: { ...process.env, AWS_PROFILE: "" } });
  assert.equal(result.status, 1, result.stderr);
  const { entries } = JSON.parse(result.stdout);
  assert.deepEqual(entries.map((x: { line: number; class: string }) => [x.line, x.class]),
    [[3, "MUTATING"], [5, "MUTATING"], [4, "SENSITIVE"], [6, "UNKNOWN"], [2, "READ-ONLY"]]);
  assert.equal(entries[0].context.profile, "example");
  assert.match(entries[1].reason, /--dry-run present/);
  assert.match(entries[3].reason, /not in AWS data snapshot \d{4}-\d\d-\d\d/);
});

test("permissions mode reports shell and Python candidates and retains scan uncertainty", async () => {
  const dir = await mkdtemp(resolve(".cmdclass-permissions-"));
  const shell = join(dir, "calls.sh");
  const python = join(dir, "calls.py");
  const invalid = join(dir, "invalid.py");
  try {
    await writeFile(shell, "aws ec2 describe-instances\naws s3 cp ./file s3://example/file\n");
    await writeFile(python, [
      "import boto3",
      "import subprocess",
      'boto3.client("s3").get_object(Bucket="example", Key="file")',
      'subprocess.run(["aws", "ec2", "describe-instances"])',
      "",
    ].join("\n"));
    await writeFile(invalid, "def broken(\n");
    const run = (...args: string[]) => spawnSync(process.execPath, ["src/cli.ts", ...args], { encoding: "utf8" });
    const result = run("--permissions", "--json", dir);
    assert.equal(result.status, 2, result.stderr);
    const report = JSON.parse(result.stdout);
    const actions = report.actions.map((entry: { action: string }) => entry.action);
    assert.ok(actions.includes("ec2:DescribeInstances"));
    assert.ok(actions.includes("s3:GetObject"));
    assert.ok(actions.includes("s3:GetObjectVersion"));
    assert.equal(report.resources, "UNKNOWN");
    assert.ok(report.unknown.some((entry: { path: string }) => entry.path === "invalid.py"));
    assert.ok(report.unknown.some((entry: { path: string }) => entry.path === "calls.sh"));
    assert.ok(report.unknown.some((entry: { path: string }) => entry.path === "calls.py"));
    const text = run("--permissions", shell);
    assert.match(text.stdout, /ec2:DescribeInstances/);
    assert.match(text.stdout, /resources: UNKNOWN/);
    assert.match(text.stdout, /not a proven minimum/);
    const regular = run("--json", shell);
    assert.ok(Array.isArray(JSON.parse(regular.stdout).entries));
    assert.equal(JSON.parse(regular.stdout).actions, undefined);
  } finally {
    await unlink(shell);
    await unlink(python);
    await unlink(invalid);
    await rmdir(dir);
  }
});

test("AWS aliases, high-level operations, custom CLI commands and overrides", async () => {
  const rows = [
    ["aws elbv2 describe-load-balancers", "READ-ONLY"],
    ["aws configservice describe-configuration-recorders", "READ-ONLY"],
    ["aws s3 ls", "READ-ONLY"],
    ["aws s3 cp ./artifact s3://example/artifact", "MUTATING"],
    ["aws s3 cp s3://example/artifact ./download", "LOCAL"],
    ["aws s3 sync ./artifact s3://example/artifact", "MUTATING"],
    ["aws s3 sync s3://example ./downloads", "LOCAL"],
    ["aws s3 cp $SRC $DEST", "UNKNOWN"],
    ["aws s3 mv s3://example/a ./download", "MUTATING"],
    ["aws s3 rb s3://example", "MUTATING"],
    ["aws s3 mb s3://example", "MUTATING"],
    ["aws s3 website s3://example", "MUTATING"],
    ["aws s3 presign s3://example/artifact", "MUTATING"],
    ["aws sso login", "LOCAL"],
    ["aws configure set region us-east-1", "LOCAL"],
    ["aws configure list", "READ-ONLY"],
    ["aws eks update-kubeconfig --name example", "LOCAL"],
    ["aws iam create-access-key --user-name example", "MUTATING"],
    ["aws cloudformation deploy", "MUTATING"],
    ["aws cloudformation package", "MUTATING"],
    ["aws logs tail example", "READ-ONLY"],
    ["aws ssm start-session", "MUTATING"],
    ["aws ssm get-parameter --name example", "READ-ONLY"],
    ["aws ssm get-parameter --name example --with-decryption", "SENSITIVE"],
    ["aws ec2 wait instance-running", "READ-ONLY"],
    ["aws ec2 help", "READ-ONLY"],
    ["aws --version", "READ-ONLY"],
    ["/usr/local/bin/aws ec2 describe-instances", "READ-ONLY"],
  ];
  const findings = await analyzeShell(rows.map(([command]) => command).join("\n"));
  assert.equal(findings.length, rows.length);
  for (const [index, [command, classification]] of rows.entries()) {
    assert.equal(findings[index].class, classification, command);
  }
});

test("documented AWS secret and short-lived credential reads are SENSITIVE", async () => {
  const rows = [
    ["secretsmanager get-secret-value --secret-id example", /secret value/],
    ["ssm get-parameters --names example --with-decryption", /decrypted parameter/],
    ["kms decrypt --ciphertext-blob example", /plaintext/],
    ["sts assume-role", /temporary AWS credentials/],
    ["sts get-session-token", /temporary AWS credentials/],
    ["sts get-federation-token", /temporary AWS credentials/],
    ["ecr get-login-password", /registry login password/],
    ["rds generate-db-auth-token", /short-lived database token/],
    ["codeartifact get-authorization-token", /short-lived authorization token/],
  ] as const;
  const findings = await analyzeShell(rows.map(([command]) => `aws ${command}`).join("\n"));
  assert.equal(findings.length, rows.length);
  for (const [index, [command, reason]] of rows.entries()) {
    assert.equal(findings[index].class, "SENSITIVE", command);
    assert.match(findings[index].reason, reason, command);
  }
});

test("failed refresh leaves the previous snapshot unchanged", async () => {
  const dir = await mkdtemp(resolve(".cmdclass-test-"));
  const path = join(dir, "aws.json");
  const blocked = join(dir, "blocked");
  const marker = join(blocked, "marker");
  const service = {
    Name: "demo",
    Actions: [{ Name: "ListThings", Annotations: { Properties: {
      IsList: true, IsWrite: false, IsPermissionManagement: false, IsTaggingOnly: false,
    } } }],
    Operations: [{ Name: "ListThings", AuthorizedActions: [{ Name: "ListThings", Service: "demo" }] }],
  };
  try {
    await updateSnapshot(path, async (part) => part === "service-list.json" ? [{ service: "demo" }] : service);
    const before = await readFile(path, "utf8");
    await assert.rejects(() => updateSnapshot(path, async (part) =>
      part === "service-list.json" ? [{ service: "demo" }] : { Name: "demo" }), /invalid AWS service/);
    await assert.rejects(() => updateSnapshot(path, async () => { throw new Error("simulated download failure"); }),
      /simulated download failure/);
    assert.equal(await readFile(path, "utf8"), before);
    assert.equal((await readSnapshot(path)).actions["demo:ListThings"], "List");
    await mkdir(blocked);
    await writeFile(marker, "previous destination");
    await assert.rejects(() => updateSnapshot(blocked, async (part) =>
      part === "service-list.json" ? [{ service: "demo" }] : service));
    assert.equal(await readFile(marker, "utf8"), "previous destination");
    await writeFile(path, before.replace('"List"', '"Read"'));
    await assert.rejects(() => readSnapshot(path), /invalid AWS data snapshot/);
  } finally {
    await unlink(path).catch((error: NodeJS.ErrnoException) => { if (error.code !== "ENOENT") throw error; });
    await unlink(marker).catch((error: NodeJS.ErrnoException) => { if (error.code !== "ENOENT") throw error; });
    await rmdir(blocked).catch((error: NodeJS.ErrnoException) => { if (error.code !== "ENOENT") throw error; });
    await rmdir(dir);
  }
});

test("SDK mappings resolve new CLI service names without adding IAM aliases", () => {
  const snapshot: Snapshot = {
    date: "2026-11-18",
    sha256: "",
    actions: { "namespace:ListThings": "List", "namespace:DeleteThing": "Write" },
    operations: {},
    methods: {
      "sdk-name:list_things": ["namespace", "ListThings"],
      "shared:list_things": ["namespace", "ListThings"],
      "shared:unrelated": ["other", "Unrelated"],
    },
  };
  assert.equal(classifyCliOperation(snapshot, "sdk-name", "list-things").class, "READ-ONLY");
  assert.equal(classifyCliOperation(snapshot, "sdk-name", "delete-thing").class, "MUTATING");
  assert.equal(classifyCliOperation(snapshot, "shared", "list-things").class, "READ-ONLY");
  assert.equal(classifyCliOperation(snapshot, "shared", "delete-thing").class, "UNKNOWN");
});

test("unmapped AWS verb prefixes never stand in for operation data", async () => {
  const findings = await analyzeShell([
    "aws ec2 get-fixture-unmapped",
    "aws ec2 list-fixture-unmapped",
    "aws ec2 describe-fixture-unmapped",
    "aws ec2 put-fixture-unmapped",
  ].join("\n"));
  assert.equal(findings.length, 4);
  for (const item of findings) {
    assert.equal(item.class, "UNKNOWN");
    assert.match(item.reason, /not in AWS data snapshot/);
  }
});

test("a known operation with no usable action mapping cannot fall back to a read action", () => {
  const reference = projectReference([{
    Name: "demo",
    Actions: [{ Name: "GetThing", Annotations: { Properties: {
      IsList: false, IsWrite: false, IsPermissionManagement: false, IsTaggingOnly: false,
    } } }],
    Operations: [{ Name: "GetThing" }],
  }]);
  const snapshot = { ...reference, date: "2026-11-18", sha256: "" };
  assert.equal(classifyOperation(snapshot, "demo", "GetThing").class, "UNKNOWN");
});

test("the CLI and SDK classify access-issuing operations by effect, not IAM read labels or verbs", async () => {
  const [shell, python] = await Promise.all([
    analyzeShell([
      "aws sagemaker create-hub-content-presigned-urls",
      "aws emr get-on-cluster-app-ui-presigned-url",
      "aws signin create-oauth2-token",
      "aws sagemaker describe-endpoint --endpoint-name example",
    ].join("\n")),
    analyzePython([
      "import boto3",
      'boto3.client("sagemaker").create_hub_content_presigned_urls()',
      'boto3.client("emr").get_on_cluster_app_ui_presigned_url()',
      'boto3.client("signin").create_oauth2_token()',
      'boto3.client("sagemaker").describe_endpoint(EndpointName="example")',
    ].join("\n")),
  ]);
  for (const entries of [shell, python]) {
    assert.deepEqual(entries.map(({ class: classification }) => classification),
      ["MUTATING", "MUTATING", "SENSITIVE", "READ-ONLY"]);
    assert.deepEqual(entries.slice(0, 3).map(({ source }) => source), Array(3).fill("AWS operation override"));
  }
});

// Catches: Determinism (INVARIANT) - AWS action order changes the reported operation effect.
test("AWS operation classification is independent of action order and preserves the worst effect", () => {
  fc.assert(fc.property(
    fc.array(fc.constantFrom("Read", "Write", "Tagging", "Permissions management", null),
      { minLength: 1, maxLength: 15 }),
    (levels) => {
      const actions: Snapshot["actions"] = {};
      const keys = levels.map((level, index) => {
        const key = `svc:Action${index}`;
        if (level) actions[key] = level;
        return key;
      });
      const snapshot: Snapshot = { date: "2026-11-18", sha256: "", actions, methods: {}, operations: { "svc:Operation": keys } };
      const first = classifyOperation(snapshot, "svc", "Operation");
      keys.reverse();
      assert.deepEqual(classifyOperation(snapshot, "svc", "Operation"), first);
      assert.equal(first.class, levels.some((l) => l && l !== "Read") ? "MUTATING" :
        levels.includes(null) ? "UNKNOWN" : "READ-ONLY");
    },
  ), propertyOptions);
});
