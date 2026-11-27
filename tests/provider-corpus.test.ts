import assert from "node:assert/strict";
import { test } from "node:test";
import type { Classification } from "../src/report.ts";
import { analyzeShell } from "../src/shell.ts";

type Groups = Partial<Record<Classification, readonly string[]>>;

const cloud: Record<string, Groups> = {
  aws: {
    "READ-ONLY": ["ec2 describe-instances", "s3api get-object", "help", "ec2 help", "s3 ls",
      "sts get-caller-identity", "configure list", "--profile example ec2 describe-instances",
      "ec2 wait instance-running"],
    MUTATING: ["s3 cp ./local s3://example/key", "s3 rm s3://example/key", "ec2 run-instances", "ec2 terminate-instances"],
    LOCAL: ["s3 cp s3://example/key ./local", "sso login"],
    UNKNOWN: ["ec2 list-snapshots", ""],
  },
  gcloud: {
    "READ-ONLY": ["compute instances describe example", "compute instances list"],
    MUTATING: ["compute instances create example", "compute instances delete example"],
    SENSITIVE: ["auth print-access-token"],
    UNKNOWN: ["config list", "auth list", ""],
  },
  az: {
    "READ-ONLY": ["vm show --name example", "vm list"],
    MUTATING: ["vm create", "vm delete"],
    UNKNOWN: ["account show", "account list", ""],
  },
  kubectl: {
    "READ-ONLY": ["get pods", "describe pod example", "logs example"],
    MUTATING: ["apply -f deploy.yaml", "delete pod example", "apply -f deploy.yaml --dry-run=client",
      "apply -f deploy.yaml --dry-run=server", "apply -f deploy.yaml --dry-run=none",
      "scale --replicas=3 deployment/example"],
    UNKNOWN: ["config view", "config current-context", "config get-contexts", "auth can-i get pods",
      "diff -f deploy.yaml", "top nodes", "-n default get pods", ""],
  },
  helm: {
    "READ-ONLY": ["list", "show chart example", "status example"],
    MUTATING: ["install example chart", "upgrade example chart", "uninstall example", "install example chart --dry-run"],
    LOCAL: ["repo add example https://example.invalid"],
    UNKNOWN: ["ls", "get values example", "template example chart", "repo list", ""],
  },
};

const tools: Record<string, Groups> = {
  vault: {
    SENSITIVE: ["read secret/data/example", "kv get secret/example"],
    MUTATING: ["write secret/data/example key=value", "delete secret/data/example", "kv put secret/example key=value"],
    UNKNOWN: ["list secret/", "status", "login", "kv list secret/", "kv metadata get secret/example", "seal",
      "token lookup", "token revoke", "policy read default", "policy write example policy.hcl",
      "secrets list", "secrets enable kv", ""],
  },
  gh: {
    "READ-ONLY": ["pr view 123", "pr list", "issue list"],
    MUTATING: ["pr merge 123", "repo delete example/example"],
    UNKNOWN: ["pr close 123", "issue view 456", "issue close 456", "api repos/example/example",
      "api -X GET repos/example/example", "api -X PUT repos/example/example", "auth status", "repo view",
      "repo clone example/example", "release create v1.0", "search repos example", ""],
  },
  docker: {
    "READ-ONLY": ["ps", "images"],
    LOCAL: ["build ."],
    UNKNOWN: ["logs example", "inspect example", "info", "version", "rm example", "rmi example",
      "system prune", "system df", "compose ps", "compose logs", "compose up", "container ls", "container rm example", ""],
  },
  npm: { MUTATING: ["publish", "unpublish"], UNKNOWN: ["test", "install", ""] },
  yarn: { MUTATING: ["publish"] },
  pnpm: { MUTATING: ["publish"] },
  twine: { MUTATING: ["upload 'dist/*'"], UNKNOWN: ["check 'dist/*'", ""] },
  gem: { MUTATING: ["push example.gem", "yank example"], UNKNOWN: ["list", ""] },
  cargo: { MUTATING: ["publish"], LOCAL: ["build"], UNKNOWN: ["test", ""] },
};

for (const [area, corpus] of [["cloud", cloud], ["miscellaneous", tools]] as const) {
  test(`DeployShield ${area} provider scenarios use independent cmdclass labels`, async () => {
    for (const [provider, groups] of Object.entries(corpus)) {
      for (const [expected, args] of Object.entries(groups)) {
        for (const invocation of args) {
          const command = invocation ? `${provider} ${invocation}` : provider;
          assert.deepEqual((await analyzeShell(command)).map((item) => item.class), [expected], command);
        }
      }
    }
  });
}

test("DeployShield context scenarios report targets without permitting or blocking them", async () => {
  const rows = [
    ["kubectl --context example delete pod example", "MUTATING", { kube_context: "example" }],
    ["kubectl --context=example get pods", "READ-ONLY", { kube_context: "example" }],
    ["helm upgrade example chart --kube-context example", "MUTATING", { kube_context: "example" }],
    ["AWS_PROFILE=assigned aws --profile=explicit ec2 terminate-instances", "MUTATING", { profile: "explicit" }],
    ["aws ec2 terminate-instances --profile", "UNKNOWN", undefined],
    ["aws --profile= ec2 describe-instances", "READ-ONLY", undefined],
    ["TF_WORKSPACE=example terraform apply", "MUTATING", { terraform_workspace: "example" }],
    ["gcloud --project=example compute instances delete example", "MUTATING", { gcloud_project: "example" }],
    ["az --subscription example vm delete", "MUTATING", { az_subscription: "example" }],
    ["pulumi destroy --stack example", "MUTATING", { pulumi_stack: "example" }],
    ["pulumi destroy -s example", "MUTATING", { pulumi_stack: "example" }],
    ["podman push example.invalid/image", "MUTATING", undefined],
    ["sls deploy", "MUTATING", undefined],
  ] as const;
  for (const [command, classification, context] of rows) {
    const findings = await analyzeShell(command);
    assert.deepEqual(findings.map((item) => [item.class, item.context]), [[classification, context]], command);
  }
});
