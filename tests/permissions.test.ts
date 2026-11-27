import assert from "node:assert/strict";
import { test } from "node:test";
import { classifyAws } from "../src/aws/cli.ts";
import { classifyOperation, operationPermissions } from "../src/aws/operations.ts";
import { classifySdkMethod } from "../src/aws/python.ts";
import { readSnapshot } from "../src/aws-data.ts";
import type { Snapshot } from "../src/aws-data.ts";
import { buildPermissionsReport, formatPermissionsReport } from "../src/permissions.ts";
import { awsPermissions, buildReport } from "../src/report.ts";

const snapshot: Snapshot = {
  date: "2026-11-18", sha256: "",
  actions: { "demo:Read": "Read", "demo:Extra": "Write", "demo:Orphan": "Read" },
  operations: { "demo:Get": ["demo:Read", "demo:Extra", "demo:Missing", "demo:Read"] },
  methods: { "demo:get": ["demo", "Get"] },
};

test("operation mappings retain all known actions and flag missing mappings without guessing", () => {
  assert.deepEqual(operationPermissions(snapshot, "demo", "Get"), {
    actions: ["demo:Extra", "demo:Read"],
    unknown: "operation has incomplete IAM action mappings in the snapshot",
  });
  assert.deepEqual(operationPermissions(snapshot, "demo", "Orphan"), {
    actions: [], unknown: "operation has no IAM action mapping in the snapshot",
  });
  assert.deepEqual(classifySdkMethod(snapshot, "demo", "get", {})[awsPermissions],
    operationPermissions(snapshot, "demo", "Get"));
});

test("permission reports merge actions with locations and retain unknowns and errors", () => {
  const effect = classifyOperation(snapshot, "demo", "Get");
  const report = buildReport([
    { line: 2, column: 3, command: "call", ...effect },
    { line: 4, column: 1, command: "dynamic", class: "UNKNOWN", reason: "dynamic command", source: "shell" },
  ]);
  const result = buildPermissionsReport([{ path: "a.py", report }, { path: "b.py", report }],
    [{ path: "bad.py", message: "parse error" }], snapshot.date);
  assert.deepEqual(result.actions.map(({ action }) => action), ["demo:Extra", "demo:Read"]);
  assert.deepEqual(result.actions[0].locations, [
    { path: "a.py", line: 2, column: 3 }, { path: "b.py", line: 2, column: 3 },
  ]);
  assert.equal(result.unknown.length, 5);
  assert.equal(result.resources, "UNKNOWN");
  assert.match(formatPermissionsReport(result), /UNKNOWN bad\.py: parse error/);
  assert.doesNotMatch(JSON.stringify(report), /awsPermissions|incomplete IAM action mappings/);
});

test("offline CLI overrides and SDK helpers do not invent IAM actions", async () => {
  const override = await classifyAws(["aws", "s3", "cp", "a", "s3://bucket/a"], null);
  assert.deepEqual(override[awsPermissions]?.actions, []);
  assert.match(override[awsPermissions]?.unknown ?? "", /not mapped/);
  const helper = classifySdkMethod(snapshot, "s3", "upload_file", {});
  assert.deepEqual(helper[awsPermissions]?.actions, []);
  assert.match(helper[awsPermissions]?.unknown ?? "", /not mapped/);
  const mapped = await classifyAws(["aws", "ec2", "describe-instances"], null);
  assert.deepEqual(mapped[awsPermissions]?.actions, ["ec2:DescribeInstances"]);
  const dynamic = await classifyAws(["aws", "ssm", "get-parameter", null], null);
  assert.ok(dynamic[awsPermissions]?.actions.includes("ssm:GetParameter"));
  assert.match(dynamic[awsPermissions]?.unknown ?? "", /dynamic/);
});

test("SDK effect overrides retain the snapshot's conditional action candidates", async () => {
  const data = await readSnapshot();
  const getObject = classifySdkMethod(data, "s3", "get_object", {})[awsPermissions];
  assert.ok(getObject);
  assert.ok(getObject.actions.includes("s3:GetObject"));
  assert.ok(getObject.actions.includes("s3:GetObjectVersion"));
  const secret = classifySdkMethod(data, "secretsmanager", "get_secret_value", {});
  assert.equal(secret.class, "SENSITIVE");
  assert.ok(secret[awsPermissions]?.actions.includes("secretsmanager:GetSecretValue"));
  const missing = classifySdkMethod(undefined, "ec2", "describe_instances", {});
  assert.deepEqual(missing[awsPermissions]?.actions, []);
  assert.match(missing[awsPermissions]?.unknown ?? "", /unavailable/);
});
