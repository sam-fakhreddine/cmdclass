# MEGA PROOF OF WORKING

**Result:** Installable proof of concept verified; the full v1 release gate remains open. The passing suite demonstrates behavior on the documented inputs, not that an arbitrary script is safe.

## Reproduce the checks

```sh
npm ci --ignore-scripts
npm run test:proof
node dist/cli.js --version
```

For the package compatibility check, build with `npm run build`, then run:

```sh
CMDCLASS_COMPATIBILITY=1 /path/to/node-22.18.0 --test tests/integration/packaged.test.ts
```

The test checks the runtime against the manifest's minimum. On macOS ARM64, the run used `package/bin/node` from `npm pack node-bin-darwin-arm64@22.18.0 --ignore-scripts`, verified against the registry's SHA-512 integrity before extraction. No project dependency changed. Compatibility mode does not test permission denial and cannot substitute for `npm run test:proof`.

The proof command builds and type-checks, runs seeded properties, packs and installs into an isolated test directory, and runs the installed CLI. The installed-CLI test requires cached runtime dependencies after `npm ci`; it installs offline. To reproduce the tested source and fixture digest:

```sh
LC_ALL=C find src tests scripts -type f | LC_ALL=C sort |
  while IFS= read -r path; do shasum -a 256 "$path"; done |
  shasum -a 256
```

- Environment: Node `v26.12.1`, Darwin arm64.
- Package version: `0.9.0`.
- Source and fixture SHA-256: `7a74de56407d85d188dfd433c4e3c8b793d3f81c540006855d7bb63c9d3d89c0`.
- Lockfile SHA-256: `1b0cd2df4874a05071884366552a973732ba272bdd06dbd7bee00587badc06ef`.
- AWS snapshot: `2026-11-19` (UTC); payload SHA-256 `125626785bb575e55f1cc62125261e02ec2c9b8cb04a2382fc414d5f969e10b0`.
- Boto3 resource catalog: all 10 services that ship high-level `resource()` models in [Boto3 1.40.0](https://github.com/boto/boto3/tree/4a91d785ac613b42bbc7528b176f8cc8d9307319/boto3/data); payload SHA-256 `55f79e9cfe8aa78004a6e87fbd92f12494055b9f696bfbe3e4a8d805573be99a`. The separate AWS snapshot contains 19,813 `client()` method mappings across 438 SDK service names. Mapping counts are not end-to-end coverage claims.

## Observed results

| Check | Result and evidence |
|---|---|
| Strict build and proof suite | Node `v26.12.1`: 86 passed, 0 failed, 0 skipped; test runner took about 16.6 seconds. |
| Minimum Node compatibility | The 0.5.0 CLI passed on Node `v22.18.0`, Darwin ARM64. The 0.9.0 check was not rerun because the cached Node 22 runtime is not present in this workspace; rerun it before release. |
| Boto3 resource model | [Python tests](../tests/python.test.ts) exercise a collection batch action, resource-returning actions and an unresolved action. The installed-CLI test verifies that the bundled resource catalog resolves an SNS topic action offline. |
| Installed CLI | After the package-version header, byte-for-byte text matches for [shell](../tests/fixtures/shell/copilot-sample.expected.txt), [standalone Python](../tests/fixtures/python/aws.expected.txt), [embedded Python](../tests/fixtures/shell/embedded-python.expected.txt), and [S3 resource deletes](../tests/fixtures/python/s3-resource-deletes.expected.txt). JSON matched the goldens' ordered findings and counts, with zero mismatches across all five classes. The [packaged test](../tests/integration/packaged.test.ts) checks version and snapshot metadata, repeated output, and redaction on valid and malformed inputs. The full proof denies network, subprocess launch, and writes. The input did not change and the marker was not created. The test scans this report and all four goldens for synthetic credential markers. |
| Directory scan | The installed command reports nested scripts, relative paths and aggregate totals. Fixtures check file extensions, extensionless shebangs, skipped directories and symbolic links, empty input, escaped text diagnostics and a partial report after syntax and size failures. The user-provided [0.5.0 report](../wow-slice5.json) scanned 2,588 files with 8 errors and reported 424 dangerous, 13 sensitive, 4,511 unknown, 929 local, and 3,640 read-only findings. The [0.6.0 report](../wow-slice6.json) scanned the same number of files and reported 424 dangerous, 13 sensitive, 4,179 unknown, 1,089 local, and 3,812 read-only findings. At matching file/line/column/command locations, 172 findings moved UNKNOWN to READ-ONLY and 160 moved UNKNOWN to LOCAL, with no added or removed findings. All eight error records were identical. The nested-code UNKNOWN reason count fell from 1,021 to 836; unsupported commands (1,177) and unanalyzed shell constructs (792) are now larger targets. Reports do not carry input hashes, so identical source inputs cannot be proven from these reports alone. |
| Python report slice | The 0.6.0 and 0.7.0 reports share 2,490 `.py` files; the 0.7.0 scan adds one Python file with 10 UNKNOWN and 1 READ-ONLY findings. All 2,490 common-file class counts are unchanged; the 575 prior `client type not known` reasons are now grouped as 308 untyped parameters, 204 unresolved assignments, 50 untracked imports, 6 control-flow merges, 4 unsupported annotations, and 3 function/class bindings. The added file contributes 9 unresolved-assignment and 1 untyped-parameter UNKNOWN. The 0.7.0 Python totals are 212 dangerous, 12 sensitive, 594 unknown, 445 read-only, and 1 local; 428 files have at least one finding. The other nine pre-existing UNKNOWNs remain six dynamic services, two operations absent from the AWS snapshot, and one unmapped resource operation. Four Python syntax errors remain. |
| Session annotation regression | In the user-provided Inspector SBOM script, recognizing qualified and imported `boto3.Session` parameter annotations reduced UNKNOWN from 10 to 1. Five previously unknown calls became DANGEROUS, three became READ-ONLY, and one became LOCAL. Two additional supported effects surfaced: a read-only paginator operation and a local download. The remaining UNKNOWN is an untyped parameter in a public helper, retained under the conservative caller policy. The 0.8.0 corpus-wide impact is not yet measured. |
| Generated properties | Seventeen component properties ran 1,000 cases each with seed `20261118`, including private-helper provenance with matching and conflicting clients, function effect propagation, sort output-option rejection, independent outer and nested effects, date option rejection, declaration substitutions, IAM action precedence, Python syntax and unresolved lookup, redaction, report ordering, Bash nesting and source positions, compound commands, and malformed Bash. The installed CLI checked 20 generated compound scripts and 15 generated directory scans for totals and exit status. See the [property configuration](../tests/property-options.ts) and [test suites](../tests/). |
| Local command rules | [Local tests](../tests/local.test.ts) constrain `return`, `shift`, and `date` arguments; cover output-only text utilities; reject `sort` file-output modes, unrecognized options, and unsafe `awk`/`sed`; and check redirects. Shell and installed-CLI tests cover nested destructive commands and command exit codes. |
| Nested effects | [Shell tests](../tests/shell.test.ts) verify known outer commands retain their READ-ONLY or LOCAL effect while inner commands remain separately visible as READ-ONLY, LOCAL, DANGEROUS, or UNKNOWN. Seeded properties exercise multiple known readers. Arithmetic expansions, dynamic redirects, interpreters, opaque wrappers, and commands whose dynamic options may write remain UNKNOWN. |
| Function summaries | Shell and packaged tests verify function calls inherit READ-ONLY, LOCAL, DANGEROUS or UNKNOWN from analyzed bodies; empty and recursive bodies remain UNKNOWN. Arithmetic commands and expansions remain UNKNOWN with distinct reasons. |
| Declaration substitutions | [Shell tests](../tests/shell.test.ts) verify separately reported nested effects in declarations and `unset`, including functions, redirects, process substitutions and literal quoted text. The installed CLI checks the original `export` regression. The enclosing declaration remains UNKNOWN. |
| Counterexample | The Python grammar accepted an empty `if` suite. Seed `20261118`, path `1:0` shrank to `[0,"if True:\n"]`. The analyzer now rejects it before reporting; [empty-suite.py](../tests/fixtures/python/empty-suite.py) preserves it. |
| Deliberate regressions | The [mutation test](../tests/integration/mutations.test.ts) ran in disposable copies. Dropping chained findings failed `finds modeled commands across separators, wrappers, and harmless whitespace`; treating missing IAM data as read-only failed `AWS operation classification is independent of action order and preserves the worst effect`; bypassing redaction failed `keeps credential markers out of both report formats across token shapes`; ignoring parser errors failed `empty scripts pass and missing syntax suppresses all findings in both modes`. |
| Snapshot update | The [AWS tests](../tests/aws.test.ts) simulate download and schema errors, a failed replacement, and an integrity mismatch. They verify the previous data remains intact when an update fails. No AWS credentials or account were used. |
| Input limits | The [shell tests](../tests/shell.test.ts) verify rejection above 1 MiB and at the AST nesting bound. Literal embedded analysis stops after 12 levels; behavior past that bound is not analyzed. |
| Mocked Python | The [mock-scope fixture](../tests/python.test.ts) verifies that Moto decorators and targeted Stubber contexts annotate findings without suppressing their class. Dynamic API lookup yields UNKNOWN. |
| Prior art | The pinned DeployShield revision is represented in [shell and normalization](../tests/shell.test.ts), [database](../tests/database-corpus.test.ts), [infrastructure](../tests/iac-corpus.test.ts), [provider and context](../tests/provider-corpus.test.ts), and [installed integration](../tests/integration/packaged.test.ts) tests. The tests use `cmdclass`-specific expectations, including parse rejection and UNKNOWN for opaque operations. [NOTICE](../NOTICE) records the source revision and MIT license. |
| Context precedence | [Context tests](../tests/aws.test.ts) distinguish flags, command assignments, and inherited values. Dynamic assignments do not fall back to inherited context, and ordinary arguments do not become assignments. |
| Permission enforcement | The [packaged test](../tests/integration/packaged.test.ts) probes the same permission flags used for the installed CLI. A write in the disposable test directory, a subprocess launch, and a connection to an unbound local socket must each fail with `ERR_ACCESS_DENIED`; the probe contacts no host. |
| Redirects and external scripts | The [shell tests](../tests/shell.test.ts) verify that substitutions inside redirect targets and arguments to literal interpreters are reported, known sensitive calls retain their classification when an argument contains a substitution, and file runners do not mistake script arguments or stdin for inline code. Uninspected scripts and unsupported inline code return UNKNOWN with distinct reasons. Explicit zsh and PowerShell inputs exit 2 with no findings. |

Installed Python golden, exit `1`:

```text
cmdclass 0.9.0
DANGEROUS  5:1  delete_bucket(...)  IAM s3:DeleteBucket (Write)
READ-ONLY  4:1  list_buckets(...)  IAM s3:ListAllMyBuckets (List)
summary: 1 read-only, 0 local, 0 unknown, 0 sensitive, 1 dangerous
```

## Prompt fixtures and release gaps

The table maps the [shell edge cases](../cmdclass-build-prompt.md#edge-cases-shell-each-one-is-a-test-fixture) to named checks. It is not a claim about behavior outside the listed forms.

| Prompt rows | Named check |
|---|---|
| Chains and pipes; command after `cd`; command substitution; backticks and process substitution; commands in variables; variables in arguments; `eval` | [shell syntax fixtures distinguish substitution bodies, literal eval, and dynamic commands](../tests/shell.test.ts) |
| Line continuation; multiline scripts; loops and `if`; output redirects; dot source; comments and quotes | [loops, conditional bodies, continued lines, and local redirects retain positions](../tests/shell.test.ts) |
| Functions | [shell function bodies and calls expose known destructive effects](../tests/shell.test.ts) |
| Shell `-c`; shell heredocs | [nested commands and literal shell bodies map findings to original positions](../tests/shell.test.ts) and [literal interpreter bodies do not swallow outer substitutions or mistake script arguments for code](../tests/shell.test.ts) |
| Pipe into shell; `xargs`, `find -exec`, `find -delete`, `parallel` | [nested execution wrappers and download pipelines do not hide dangerous findings](../tests/shell.test.ts). Additional uninspected `find` actions and `xargs` arguments supplied at runtime prevent a read-only finding, even when fixed `xargs` options are recognized. |
| Source or run another file | The redirect and script-runner checks above, plus the multiline fixture's `source` and `.` cases |
| Inline Python and unsupported inline code | [shell maps inline Python and heredoc findings and errors to the original script](../tests/python.test.ts) and [redirect substitutions do not hide effects and unknown script runners explain why](../tests/shell.test.ts); the unsupported inline example is Node |
| Parse error; unsupported shell | [empty scripts pass and missing syntax suppresses all findings in both modes](../tests/shell.test.ts) and [the CLI rejects explicitly unsupported shells without emitting findings](../tests/shell.test.ts) |

| AWS prompt rows | Named check and limits |
|---|---|
| Global flags; snapshot miss; `--dry-run`; `s3api` | [CLI classifies mapped AWS calls and applies credential and profile overrides offline](../tests/aws.test.ts) |
| `elbv2`, `configservice`; S3 high-level verbs; long-lived credentials; auth and config; local side effects; custom commands; help/version; AWS invoked by path | [AWS aliases, high-level operations, custom CLI commands and overrides](../tests/aws.test.ts); `s3 rm` is also in the installed shell golden |
| Secret and short-credential reads | [documented AWS secret and short-lived credential reads are SENSITIVE](../tests/aws.test.ts) asserts the whole CLI list and the reason for each case. The [access-issuing operations check](../tests/aws.test.ts) covers additional signed links and OAuth credentials. |

| Python prompt rows | Named check and limits |
|---|---|
| Plain client; session/profile; variable service; `DryRun=True` | [classifies imported clients, sessions, resources and overrides without rendering arguments](../tests/python.test.ts) plus [unknown service and method combinations stay UNKNOWN](../tests/python.test.ts) for dynamic service and method coverage |
| Instance attribute; client passed into a function | [resolves simple factories and instance attributes; unresolved receivers stay visible](../tests/python.test.ts), [SDK helpers, typed clients, and low-level sessions use the shared AWS policy](../tests/python.test.ts), [direct calls to a simple untyped forwarder resolve the supplied SDK client](../tests/python.test.ts), and [private helpers resolve untyped client parameters only when all direct callers agree](../tests/python.test.ts). Private helper inference requires every direct in-file call to supply a proven client for the same service; public, exported, escaping, mixed-service, or ambiguous helpers retain UNKNOWN findings. No cross-file callers are inferred. |
| Paginator; waiter; client-side helpers; new credentials or links; low-level Botocore; never-called function | [SDK helpers, typed clients, and low-level sessions use the shared AWS policy](../tests/python.test.ts) covers representative upload/download and both presigning helpers. [SDK-only transfer helpers classify local downloads and remote writes](../tests/python.test.ts) covers `upload_fileobj`, `download_fileobj`, and `copy` at the adapter boundary. The SDK credential fixture covers IAM key creation. |
| Resource API; collection batch actions | [Python tests](../tests/python.test.ts) assert EC2 instance termination and filtered batch termination, SQS/SNS actions, and the S3 `objects.all().delete()` path. The installed [S3 golden](../tests/fixtures/python/s3-resource-deletes.expected.txt) checks service-level `Object(...).delete()` and `Bucket(...).objects.filter(...).delete()` as distinct `DANGEROUS` findings. No Python fixture was executed. |
| Dynamic method name; Moto and Stubber | [mock scopes annotate rather than suppress effects, and dynamic API lookup stays UNKNOWN](../tests/python.test.ts) and the imported-client fixture's `getattr` case |
| Secret and short-credential reads | [SDK credential reads match shared AWS effects and keep arguments out of reports](../tests/python.test.ts) covers Secrets Manager, KMS, ECR, RDS, and SSM; the imported-client fixture covers STS and SSM decryption. Raw arguments are omitted from Python reports, including the literal identifiers requested by the prompt. |

| Provider registry | Named checks |
|---|---|
| AWS | The AWS prompt rows above and the installed shell golden |
| kubectl | [provider rules distinguish context, sensitive output, mutations and unknown commands](../tests/aws.test.ts) and the normalization fixture |
| Helm, Terraform, Pulumi, gcloud, Azure CLI, Vault, GitHub CLI, Docker/Podman | [registered providers and aliases have independently labeled representative cases](../tests/aws.test.ts) |
| CDK, SAM, Serverless/sls, Ansible, npm, Yarn, pnpm, Twine, Gem, Cargo | [registered providers and aliases have independently labeled representative cases](../tests/aws.test.ts) |
| PostgreSQL, MySQL, MongoDB, Redis | [registered providers and aliases have independently labeled representative cases](../tests/aws.test.ts) and [database rules distinguish isolated reads, mutations, and ambiguous SQL without rendering queries](../tests/aws.test.ts) |

### Remaining checks

- Fill the uncovered variants in the matrix. All eight DeployShield test modules are represented; context tests adapt target detection, not upstream config-file discovery, glob-based blocking decisions, or hook protocols. Those features are not part of this offline CLI. The upstream open-agent-tools-coder license file identifies Apache 2.0, but its source was not copied and no dedicated AWS safety test module was found in the repository tree. The prompt's listed failure cases are covered by independent fixtures. Provider coverage is not exhaustive. Database rules recognize narrowly defined SQL and Redis operations; unrecognized or ambiguous queries remain UNKNOWN.
- The vendored Boto3 catalog covers explicit constructors, modeled actions and collection batch actions; arbitrary resource attributes and lazy enumeration are not fully modeled. General interprocedural inference, full Python syntax validation, and exact tracking across dynamic dispatch and arbitrary branches are not verified. Shell support for wrappers with arbitrary options and transformed inline source is incomplete.
- The packaged CLI generated set covers compound shell classification, not every component property. Redaction tests cover synthetic credential forms, not arbitrary secrets. The retained-evidence scan checks packaged, shell, Python, and property-test credential markers in this report and the four installed goldens.
- Both runtimes were tested on macOS ARM64. Node 22.18.0 passed package compatibility; active permission denial was verified only on Node 26.12.1. The suite does not establish production readiness.

## Follow-up: can AWS calls be distilled to verb regexes?

Yes for a rough summary, not for deciding that a command is read-only. Below are counts for canonical API operation names in the pinned snapshot, using IAM action classification **before** CLI or SDK behavior overrides:

| Regex | What it usually means | Read-only by IAM mapping | Dangerous by IAM mapping |
|---|---|---:|---:|
| `^Get` | Fetches a value or resource | 2,700 | 40 |
| `^List` | Enumerates resources | 3,228 | 11 |
| `^Describe` | Returns resource details | 1,694 | 13 |
| `^Put` | Writes or replaces data | 0 | 465 |
| `^(Create\|Update\|Delete)` | Changes state or creates access | 5 | 6,094 |

`GetSecretValue` is a read in IAM but **SENSITIVE** in `cmdclass`. Some `List` and `Describe` operations include conditional write permissions in their AWS operation mapping. Conversely, `CreateHubContentPresignedUrls` is labeled read-only by the IAM mapping but issues signed URLs. The shared classifier now handles known exceptions explicitly; a paired AWS CLI and boto3 test verifies that signed links are **DANGEROUS** and temporary sign-in tokens are **SENSITIVE**.

Reproduce the counts from project root, offline. Count each namespace/operation pair once, not once per CLI or SDK alias:

```sh
node --input-type=module <<'JS'
import { readSnapshot } from "./src/aws-data.ts";
import { classifyIamOperation } from "./src/aws/operations.ts";
const snapshot = await readSnapshot();
for (const regex of [/^Get/, /^List/, /^Describe/, /^Put/, /^(Create|Update|Delete)/]) {
  const counts = {};
  for (const key of Object.keys(snapshot.operations)) {
    const [namespace, operation] = key.split(":");
    if (!regex.test(operation)) continue;
    const { class: effect } = classifyIamOperation(snapshot, namespace, operation);
    counts[effect] = (counts[effect] ?? 0) + 1;
  }
  console.log(String(regex), counts);
}
JS
```

Keep AWS mappings and explicit behavior overrides as the source of truth. If a future report shows verb families, label `Get*`, `List*`, and `Describe*` as **read-shaped**, and `Put*`, `Create*`, `Update*`, and `Delete*` as **write-shaped**. Do not use the regexes to turn an unmapped operation into READ-ONLY.
