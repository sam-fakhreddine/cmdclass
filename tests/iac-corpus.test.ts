import assert from "node:assert/strict";
import { test } from "node:test";
import { classifyProvider } from "../src/providers.ts";
import type { Classification } from "../src/report.ts";

const cases: Record<string, Partial<Record<Classification, readonly string[]>>> = {
  terraform: {
    "READ-ONLY": ["version", "workspace list", "workspace show"],
    LOCAL: ["fmt", "init"],
    DANGEROUS: ["apply", "destroy"],
    UNKNOWN: ["plan", "show", "output", "validate", "state list", "state show aws_instance.example",
      "state pull", "import aws_instance.example example", "state rm aws_instance.example",
      "workspace new example", "-chdir=./infra plan", ""],
  },
  pulumi: {
    "READ-ONLY": ["version", "stack ls"],
    LOCAL: ["stack select example"],
    DANGEROUS: ["up", "destroy"],
    UNKNOWN: ["preview", "whoami", "config get example:region", ""],
  },
  cdk: {
    LOCAL: ["synth"],
    DANGEROUS: ["deploy", "destroy"],
    UNKNOWN: ["diff", "synthesize", "list", "ls", "doctor", "bootstrap", ""],
  },
  sam: {
    LOCAL: ["build"],
    DANGEROUS: ["deploy", "delete"],
    UNKNOWN: ["validate", "local invoke", "logs", ""],
  },
  serverless: {
    DANGEROUS: ["deploy", "remove"],
    UNKNOWN: ["info", "print", "package", "invoke local -f example", "invoke -f example", ""],
  },
  "ansible-playbook": {
    DANGEROUS: ["example.yml", "example.yml --check", "example.yml -C", "example.yml --syntax-check",
      "example.yml --list-hosts", "example.yml --list-tasks", "example.yml --list-tags", ""],
  },
};

test("DeployShield IaC scenarios distinguish recognized changes from unmodeled execution", () => {
  for (const [provider, groups] of Object.entries(cases)) {
    for (const [expected, commands] of Object.entries(groups)) {
      for (const command of commands) {
        assert.equal(classifyProvider(provider, command ? command.split(" ") : [])?.class, expected,
          `${provider} ${command}`);
      }
    }
  }
});
