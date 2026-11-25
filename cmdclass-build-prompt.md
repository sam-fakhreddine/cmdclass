# Build cmdclass: a script highlighter for dangerous, sensitive and read-only commands

## What to build and why

Build a command-line tool, `cmdclass`, that reads a shell script or Python code that uses boto3 (usually code an AI assistant such as Copilot wrote) and shows, before anyone runs it, what each line will do. Both inputs matter equally: most real AWS work is in boto3, not the CLI. It is a highlighter, never a blocker: it reads the script and reports. It never stops, edits or runs anything.

Run it like this: `cmdclass deploy.sh`. Example output:

```
DANGEROUS   18  aws s3 rm s3://bucket --recursive              deletes S3 objects                       profile: prod
DANGEROUS   23  aws iam attach-role-policy ...                 IAM iam:AttachRolePolicy (Permissions management)
DANGEROUS   31  aws s3 presign s3://b/report.pdf               creates a link anyone can use to download the object
SENSITIVE   15  aws secretsmanager get-secret-value --secret-id prod/db-password
                → prints the secret value of prod/db-password
SENSITIVE   21  aws sts assume-role --role-arn ...:role/Deployer
                → creates temporary AWS keys for role Deployer
UNKNOWN     30  $CMD --force                                   command is in a variable
LOCAL       27  echo "$X" > out.txt                            writes a local file
READ-ONLY   12  aws ec2 describe-instances                     IAM ec2:DescribeInstances (List)
summary: 1 read-only, 2 sensitive (secrets or credentials it will read), 3 dangerous, 1 local, 1 unknown
```

Plain code makes every decision, using AWS's own published data. No AI model is involved.

## Safety contract

This is static analysis, not a sandbox or a guarantee that a command is safe. Never execute, expand, import or evaluate input code. Apart from the explicit `--update-aws-data` operation, analysis must not access the network. Classify unsupported or ambiguous behavior as UNKNOWN rather than inferring that it is safe.

Do not echo credential values from source into text or JSON output. Redact values supplied to credential-shaped flags (such as `--password`, `--token`, `--secret`, `--client-secret`, `--access-key` and `--secret-access-key`), credential-named environment assignments, and URL user-info. Keep the flag or variable name so the finding remains useful. Add fixtures proving that both output formats redact these values.

SENSITIVE detection covers the explicit rules in this prompt; it does not infer that arbitrary local files or variables contain secrets. State this limitation in `--help`.

## The five classes

Report them in this order, with DANGEROUS the most visible:

1. **DANGEROUS**: changes a cloud account or a remote system, deletes local data, or creates a new long-lived credential or a new way in. The last group covers `iam create-access-key`, `s3 presign`, IAM login profiles, service-specific credentials and signed URLs, even where AWS labels the action "Read".
2. **SENSITIVE**: changes nothing, but reads an existing secret or hands out a short-lived credential. These are normal in scripts, so they are highlighted, not alarmed. Each one carries a plain note saying what it hands back, using the secret name, role or object from the arguments when they are literal.
3. **UNKNOWN**: the tool cannot tell. Always give the reason.
4. **LOCAL**: changes only this machine, for example a file, a kubeconfig or the local AWS CLI config.
5. **READ-ONLY**: changes nothing anywhere and exposes no secret.

When one command fits more than one class, the worse class wins. The order of badness is DANGEROUS, then SENSITIVE, then UNKNOWN, then LOCAL, then READ-ONLY.

## Exit codes and output

The exit codes only describe the report, so a person can script around it. The tool never blocks anything on its own.

| Code | Meaning |
|---|---|
| 0 | every command is READ-ONLY |
| 1 | any DANGEROUS, UNKNOWN or LOCAL command |
| 3 | only SENSITIVE and READ-ONLY commands |
| 2 | the script cannot be parsed; name the line, and never print a partial "all clear" |

Output options:

- `--json` prints the same result as JSON with a top-level `schema_version: 1`. Each entry has line, column, command text, class, reason, source (for example `IAM s3:DeleteObject Write`), and context (profile, kube context, terraform workspace) when one is detected.
- The tool runs offline. The AWS data is a vendored snapshot stored with its date and sha256. `cmdclass --update-aws-data` refreshes it. A check never fetches anything.
- Print class groups in the order defined above, and findings within each group in source order (line, then column), with a stable tie-breaker for findings at the same location. Print a summary with counts for all five classes. A blank or comment-only input produces zero findings and exit 0.
- On parse failure, write the error and line to stderr, emit no findings or summary to stdout, and exit 2. Apply this to shell and Python input; do not return partial JSON either.
- V1 accepts one file or directory path per invocation. For an explicit file, a `.py` path is parsed as Python; other paths are parsed as shell. Directory scans discover supported scripts recursively; see [CLI usage](./README.md#install-and-run) for selection rules and partial-error reporting. `--version` and `--update-aws-data` do not require an input path.

## How it decides

1. **Parse.** Use a real parser for the supported bash/sh syntax, keeping line and column locations. The ported DeployShield splitter is a helper for segmenting commands, not a substitute for parsing shell syntax. Parse the whole script before reporting; every simple command is classified on its own.
2. **Unwrap.** Before classifying, strip `KEY=VALUE` prefixes, full paths (`/usr/local/bin/aws` becomes `aws`) and the wrappers `sudo`, `env`, `timeout`, `nohup`, `time`, `command`, `exec` and `xargs`, along with their flags.
3. **Local shell commands.** Classify known local effects explicitly: deleting or irreversibly destroying local data (for example `rm`, `shred`, `unlink`, `rmdir`, `truncate`, `find -delete`) is DANGEROUS; other recognized local mutations (for example `cp`, `mv`, `mkdir`, `touch`, `chmod`, `tee`, and in-place edits) are LOCAL. Known read-only builtins and readers may be READ-ONLY. Do not treat an unrecognized executable or script as read-only; use UNKNOWN.
4. **`aws` commands:**
   - Skip global flags and their values: `--region`, `--profile`, `--output`, `--endpoint-url`, `--no-cli-pager`, `--debug` and similar.
   - Map the CLI service name to the IAM namespace with AWS's SDK-id mapping file. For example, `s3api` is `s3` and `elbv2` is `elasticloadbalancing`.
   - Turn the CLI operation into the API operation name by converting kebab case to Pascal case (`delete-objects` becomes `DeleteObjects`).
   - Look the operation up in the service file's `Operations` list. Each entry names the IAM actions it needs (`AuthorizedActions`), and each action carries `Properties` flags (`IsList`, `IsWrite`, `IsPermissionManagement`, `IsTaggingOnly`). One operation can need several actions; the worst one decides. For example, `CopyObject` needs `s3:GetObject` and `s3:PutObject`, so it is DANGEROUS. Only when the operation is missing, fall back to treating the Pascal name as the action name.
   - An action flagged write, permissions management or tagging means DANGEROUS. Otherwise the action is READ-ONLY.
   - Apply the hand tables below last; they override the lookup.
5. **Other CLIs:** each has its own checker in a provider registry (see Prior art). A command not in any table is UNKNOWN. A provider command is not READ-ONLY merely because it is absent from a write list; each checker must have explicit read, mutation, sensitive, and unknown rules with fixtures.
6. **Context.** Detect the AWS profile (from the flag or `AWS_PROFILE=`), kube context, terraform workspace, gcloud project, az subscription and pulumi stack, and show it as a column. Resolve context in this order: command-line flag, assignment on that command, then inherited process environment when available. Do not guess if the value is dynamic. A dangerous line against prod should stand out.

AWS data source: `https://servicereference.us-east-1.amazonaws.com/v1/service-list.json`, then one file per service, plus AWS's SDK-id mapping file. Known caveats:

- Updates can lag by up to 24 hours.
- Not every service is listed.
- Namespace names can differ from CLI names.

If an action is missing from the snapshot, apply a documented hand-table or positive fallback rule when one covers it; otherwise use UNKNOWN with the reason "not in AWS data snapshot <date>". If the snapshot is malformed, a required service mapping is missing, or an operation has no usable action mapping, use UNKNOWN unless a known action already makes it DANGEROUS; never infer READ-ONLY from an incomplete lookup.

## SENSITIVE list (reads existing secrets or short-lived credentials)

**AWS:**

- `secretsmanager get-secret-value`
- `ssm get-parameter` and `ssm get-parameters` with `--with-decryption` (without the flag they are READ-ONLY)
- `kms decrypt`
- `sts assume-role`, `sts get-session-token`, `sts get-federation-token`
- `ecr get-login-password`
- `rds generate-db-auth-token`
- `codeartifact get-authorization-token`

**Other CLIs:**

- `vault read`, `vault kv get`
- `kubectl get secret` with `-o yaml` or `-o json`
- `gh auth token`
- `gcloud auth print-access-token`
- `az account get-access-token`

**DANGEROUS, not SENSITIVE:** `iam create-access-key`, `iam create-login-profile`, `iam create-service-specific-credential`, `s3 presign`, and anything else that creates a new long-lived credential or a public link.

## Edge cases: shell (each one is a test fixture)

| Case | Example | Expected |
|---|---|---|
| Chains and pipes | `aws s3 ls && aws s3 rm s3://b` | two entries on the same line: READ-ONLY and DANGEROUS |
| Command after cd | `cd repo && aws s3 rm s3://b/k` | cd is READ-ONLY, aws is DANGEROUS |
| Command substitution | `ID=$(aws ec2 run-instances ...)` | inner command classified: DANGEROUS |
| Backticks, process substitution | `` `...` ``, `<(...)`, `>(...)` | inner command classified |
| Line continuation | `aws s3 rm \` plus the next line | one entry, reported at its first line |
| Multi-line script | any | every command, not only the first |
| Loops and if | `for b in $L; do aws s3 rb s3://$b; done` | body classified once whether or not it runs: DANGEROUS |
| Functions | `wipe() { rm -rf "$1"; }` then `wipe /x` | body classified at definition; each call listed as "calls wipe (DANGEROUS)" |
| Command in a variable | `$CMD --force`, `aws $OP` | UNKNOWN, "command is in a variable" |
| Variable only in an argument | `aws s3 ls s3://$B` | classified normally |
| eval | `eval "$X"` | UNKNOWN; if the argument is a literal string, parse it and classify the inside |
| sh -c, bash -c | `bash -c "rm -rf /tmp/x"` | literal string parsed and classified, otherwise UNKNOWN |
| Heredoc into a shell | `bash <<EOF ... EOF` | heredoc body parsed as a script, lines reported at their real line numbers |
| Pipe into a shell | `curl ... \| sh` | DANGEROUS, "runs downloaded code" |
| xargs, find -exec, parallel | `... \| xargs aws s3 rm`, `find . -delete` | the inner command decides; `find -delete` is DANGEROUS |
| Output redirect | `cmd > file`, `>>`, `tee file` | at least LOCAL; `> /dev/null` and `2>&1` are ignored |
| source another file | `source ./env.sh` | UNKNOWN, "runs another file" (v1 does not follow it) |
| Dot source or script execution | `. ./env.sh`, `./deploy.sh`, `python deploy.py` | UNKNOWN, "runs another file" (v1 does not follow it) |
| Inline code | `python -c`, a Python heredoc | sent to the boto3 analyser; `node -e` and other languages are UNKNOWN, "inline code not analysed" |
| Comments and quoted text | `# aws s3 rm`, `echo "rm -rf"` | comment ignored; echo is READ-ONLY |
| Parse error | unbalanced quote | exit 2, naming the line |
| Not bash | PowerShell, zsh-only syntax | v1 supports bash and sh only; otherwise exit 2, "unsupported shell" |

## Edge cases: AWS (each one is a test fixture)

| Case | Example | Expected |
|---|---|---|
| Global flags before the service | `aws --region us-east-1 --profile p s3 rm s3://b/k` | flags skipped: DANGEROUS, context shows profile p |
| CLI name differs from the IAM namespace | `s3api`, `elbv2`, `configservice` | mapped by AWS's SDK-id file, not by hand |
| S3 high-level verbs | `s3 ls`, `cp`, `mv`, `rm`, `sync`, `mb`, `rb`, `presign`, `website` | ls is READ-ONLY; rm, mv, rb, mb, website and presign are DANGEROUS; cp and sync are DANGEROUS when the target is `s3://` and LOCAL when only the source is |
| Secret and short-credential reads | see the SENSITIVE list | SENSITIVE, with the plain note |
| New long-lived credentials | `iam create-access-key` | DANGEROUS |
| Auth and CLI config | `sso login`, `configure set`, `configure list` | login and configure set are LOCAL; configure list is READ-ONLY |
| Local side effects | `eks update-kubeconfig`, `s3 cp s3://b/k .` | LOCAL |
| Custom CLI commands not in IAM | `cloudformation deploy`, `cloudformation package`, `logs tail`, `ssm start-session`, `... wait ...` | deploy and package are DANGEROUS; logs tail is READ-ONLY; start-session is DANGEROUS (opens a shell on a host); wait is READ-ONLY |
| Help and version | `aws ... help`, `aws --version` | READ-ONLY |
| `--dry-run` | `aws ec2 terminate-instances --dry-run` | still DANGEROUS, reason notes "--dry-run present" |
| Action missing from the data | new service, data lag | UNKNOWN, naming the snapshot date |
| aws called by path | `/usr/local/bin/aws` | treated as aws |

## boto3 (Python SDK) code

This is a must, not an extra. `cmdclass` takes `.py` files, and also Python embedded in shell scripts (heredocs into `python`, `python -c`), and reports each boto3 call with its line number in the same five classes.

The AWS data already maps boto3. Each entry in a service file's `Operations` list carries an `SDK` list with `{"Name": "s3", "Method": "copy_object", "Package": "Boto3"}`. So a boto3 method maps straight to its operation and then to its IAM actions, with no guessing from names. Checked on 2026-11-18: in `s3.json`, all 195 operations have a Boto3 entry. The data names only Boto3, so other SDKs come later.

How it decides:

1. Parse the Python with a real parser (tree-sitter-python), keeping line numbers.
2. Find the clients: `boto3.client("s3")`, `boto3.Session(...).client("s3")`, `session.client("s3", region_name=...)`, and the aioboto3 forms. Track which variable holds which service client through assignments, attributes (`self.s3 = ...`), function parameters with a type hint (`s3: S3Client`) and simple returns from a factory function.
3. Map each method call on a known client (`s3.delete_objects(...)`) through the `SDK` mapping, then through the operation's actions to the class, exactly as for the CLI.
4. Detect context in the same way as for the CLI: `profile_name=` and `region_name=` on the session or client, and `AWS_PROFILE` set in `os.environ`.

### Edge cases: boto3 (each one is a test fixture)

| Case | Example | Expected |
|---|---|---|
| Plain client call | `s3 = boto3.client("s3")` then `s3.delete_object(...)` | DANGEROUS, via the SDK mapping |
| Session and profile | `boto3.Session(profile_name="prod").client("iam")` | classified, context shows profile prod |
| Client stored on self | `self.ec2 = boto3.client("ec2")` in `__init__`, used in another method | resolved through the class |
| Client passed into a function | `def wipe(s3): s3.delete_bucket(...)` | DANGEROUS if the parameter has a type hint or the call site passes a known client; otherwise UNKNOWN, "client type not known" |
| Unmapped method on known client | `s3.new_or_unmapped_method()` | UNKNOWN, "method not in AWS data snapshot <date>" |
| Paginator | `s3.get_paginator("list_objects_v2")` | uses the named operation: READ-ONLY |
| Waiter | `ec2.get_waiter("instance_running")` | READ-ONLY |
| Resource API | `boto3.resource("s3").Bucket("b").objects.all().delete()`, `Object(...).delete()`, `Instance(...).terminate()` | DANGEROUS. Map resource actions to their operations using botocore's resource JSON (the `boto3/data/<service>/<version>/resources-1.json` files), vendored with the AWS snapshot; if an action is not found, UNKNOWN |
| Batch actions on collections | `bucket.objects.filter(...).delete()` | DANGEROUS (`DeleteObjects`) |
| Dynamic method name | `getattr(s3, op)(...)`, `client.meta.method_to_api_mapping` | UNKNOWN, "method name is dynamic" |
| Service name in a variable | `boto3.client(svc)` | calls on it are UNKNOWN, "service is in a variable", unless the variable is a literal constant in the same file |
| Secret and short-credential reads | `secretsmanager.get_secret_value`, `ssm.get_parameter(WithDecryption=True)`, `sts.assume_role`, `ecr.get_authorization_token`, `rds.generate_db_auth_token`, `kms.decrypt` | SENSITIVE, with the plain note (secret id, role ARN or parameter name when it is literal) |
| New long-lived credentials or links | `iam.create_access_key`, `s3.generate_presigned_url`, `s3.generate_presigned_post` | DANGEROUS |
| Client-side helpers not in the API | `s3.upload_file`, `upload_fileobj`, `download_file`, `download_fileobj`, `copy` | hand table: upload and copy are DANGEROUS (PutObject), download is LOCAL |
| `DryRun=True` | `ec2.terminate_instances(..., DryRun=True)` | still DANGEROUS, reason notes "DryRun present" |
| Low-level botocore | `botocore.session.get_session().create_client(...)` | treated like a boto3 client |
| Code in a function never called | any | still reported; static analysis reports every call it finds |
| Moto or stubbed tests | `@mock_aws`, `Stubber(client)` | still reported, with "inside a test" in the reason so the reader can skip it |

## Prior art: port, do not reinvent

1. **DeployShield** (https://github.com/matanryngler/deployshield, MIT license; port with credit in a NOTICE file). One Python file, `hooks/scripts/validate-cloud-command.py`, plus tests split by area. Take:
   - `split_compound_command`: a state machine for `&&`, `||`, `;` and `|` that respects quotes, escapes, subshells, backticks and process substitution.
   - `extract_nested_contents` with recursion, so every nested command goes back through the whole pipeline.
   - `normalize_segment`: env prefixes, paths, and the `sudo`/`env`/`xargs` wrappers; `bash -c` checked recursively.
   - The `PROVIDERS` registry, one checker per CLI: aws, gcloud, az, kubectl, helm, terraform, pulumi, psql, mysql, mongosh/mongo, redis-cli, cdk, sam, serverless/sls, ansible-playbook, vault, gh, docker/podman, npm/yarn/pnpm, twine, gem, cargo.
   - Its special cases: kubectl and helm treat `--dry-run=client|server` as safe but not `--dry-run=none`; s3 cp downloads; the SQL read-only keyword check for database CLIs.
   - Context detection: AWS profile, kube context, terraform workspace, gcloud project, az subscription, pulumi stack.
   - Every one of its test cases becomes a fixture with our expected class.

   Where ours differs:
   - It checks one command as a hook; ours reports a whole script.
   - Its AWS check is a safe-word list; ours uses AWS's data.
   - It fails open on bad input; ours fails closed with exit 2.
   - It has two outcomes; ours has five classes.

2. **open-agent-tools `oats.tool.aws_safety`** (https://github.com/district-solutions/open-agent-tools-coder, docs at https://open-agent-tools-coder.readthedocs.io). `classify(command)` returns READ, MUTATE, AUTH or UNKNOWN for one aws command using verb sets and prefixes. Its license was not found: check it before copying any code; if there is none, reuse only its rules (facts), not its code.
   - Use its verb rules as the fallback when an action is missing from AWS's data.
   - Port its cases as fixtures.
   - Its known misses are rows in the tables above and must pass in ours: it reads only the first verb of a chain, misses aws after `cd &&`, mistakes `--region` for the service, reads only the first command in a script, and counts secret reads as plain READ.

3. Also worth porting cases from:
   - OpenAI Codex CLI `command_safety` (`is_known_safe_command`, safe operators like `|| true`)
   - koda `bash_safety.rs` (ReadOnly / LocalMutation / Destructive; excludes `xargs` on purpose because of `xargs rm`)
   - destructive_command_guard (heredocs and inline scripts)
   - bash-vet-mcp and pi-safe-shell (rule lists)

   Check cmdxray first: if it already analyses whole scripts, adopt it for the non-AWS part.

## Build plan

Implement one slice at a time. Detail the current slice before starting it; treat the remaining slices as a backlog, not a fixed sequence. Each slice must leave a runnable CLI for the behavior it supports. Until a capability lands, use UNKNOWN for valid but unsupported constructs rather than treating them as READ-ONLY.

### Slice 1: Shell parsing and reporting

1. Set up the strict TypeScript CLI and test runner. Before choosing a shell parser, check that it supports source spans, a detectable parse-error state, and the nested syntax needed by slice 3. Prove these on a few representative inputs before building normalization on top.
2. Add CLI fixtures first: a local-only script with multiple commands, a malformed script, a credential-shaped literal that must be redacted, and empty input. Implement direct AST traversal, command positions, local classification, simple wrappers and redirects, then the shared text/JSON report and exit codes.
3. Generate valid compound scripts from labeled command nodes and check that findings match those labels, independently of the parser. Test malformed shell, equivalent quoting and whitespace, report parity, and redaction.

**Exit gate:** Goldens prove the local shell path through the real CLI, including deterministic group order and hard parse failure. AWS classifications and semantic analysis of inner scripts are not required yet; fixtures depending on those capabilities land in slices 2–4.

### Slice 2: AWS data and provider classification

1. Verify the AWS snapshot schema, CLI aliases, operation/action mappings and boto3 method mappings against pinned sample data. Define a shared operation classifier so the CLI and boto3 can use it without duplicating precedence rules.
2. Add the vendored snapshot, version metadata and validated updater. Implement AWS flags, context, the explicit overrides and fallback rules, then the non-AWS provider registry. Keep missing or ambiguous matches UNKNOWN under the lookup rules above.
3. Add the AWS table and applicable prior-art fixtures. Generate synthetic action sets to check that action order does not change the outcome and that the worst applicable class wins. Simulate a failed update and assert that it leaves the previous snapshot unchanged.

**Exit gate:** AWS CLI and provider fixtures pass, normal analysis passes offline, and the updater's atomicity is demonstrated without a live AWS account.

### Slice 3: Nested shell and packaging

1. Implement inner shell analysis: substitutions, literal `sh -c` and `eval`, shell heredocs, `xargs`, `find -exec`, and function calls. Keep source locations tied to the original input and make ambiguous targets UNKNOWN. Embedded Python routes to slice 4.
2. Generate nested scripts with bounded depth and known inner commands. Check that discoveries survive nesting, positions point into the submitted script, and malformed inner input does not yield a partial report.
3. Package the CLI as one installable command. Add the full shell golden and exercise it through the packaged entry point.

**Exit gate:** The shell golden shows all five classes; shell fixtures pass except those that depend on the Python analyzer. The packaged CLI produces the same report as the development entry point.

### Slice 4: boto3 and release checks

1. Parse standalone Python, resolve known clients and contexts, and send mapped calls through the classifier from slice 2. Add the supported resource chains and helper overrides; unresolved client, service or method cases remain UNKNOWN where specified.
2. Route literal inline Python and Python heredocs through the same analyzer. Add the boto3 fixtures and Python golden, and complete the deferred shell fixtures.
3. Generate known and unresolved receiver/method cases, plus malformed Python. Check that unresolved calls never become READ-ONLY and that malformed code never yields a partial report.

**Exit gate:** Both golden reports, the full fixture suite, offline analysis and the packaged CLI checks pass.

### Close and re-groom after every slice

1. Run the slice exit gate and all earlier gates. Record commands, observed results, limitations, and minimized counterexamples. Fix regressions before moving on.
2. Re-read all remaining slices against those results. Update dependencies, scope, ordering and acceptance tests; split or re-order work when the evidence warrants it. Record what changed and why, even if the decision is to keep the plan.
3. Detail only the next slice: its smallest end-to-end path, fixture and property commitments, and exit gate. Surface unresolved scope or dependency decisions before proceeding. After the final slice, apply the same review to release readiness and deferred work.

### Slice 1 closeout and re-groom

- Passed `npm run build`, `npm run typecheck`, and `npm test` (13 tests), including real CLI text/JSON fixtures, redaction, and seeded syntax properties.
- The legacy grammar bundle could not load with the current runtime; the approved replacement works. Direct AST traversal handled the compound syntax exercised so far, so retain ported behavior fixtures but do not add a duplicate splitter unless a demonstrated gap requires it. Keep the missing-node regression in the suite.
- Keep the slice order. First prove an offline `aws` CLI classification with one mapped read and one mapped write. Expose a shared operation classifier; keep raw source and rendered command separate so the provider can classify arguments without echoing them. Then add schema/metadata validation, the atomic updater, broader fixtures and provider rules. Slice 3 owns inner-source positions and richer wrappers; slice 4 can use the Python grammar already included in the replacement package.

### Slice 2 checkpoint and re-groom

- The build, type-check, and 18 tests pass, including AWS alias and transfer cases, blocked-network classification, action-order generation, and a simulated failed refresh. The checked-in snapshot projects AWS action, operation and Boto3 method facts into a single checksummed file.
- Remaining Slice 2 evidence: the full prior-art test corpus and all provider variants. The generated AWS SDK mappings own SDK-to-IAM resolution; CLI-only naming exceptions live together in the CLI rules. Keep untested provider cases UNKNOWN rather than widening read-only rules based on verbs alone. Track remaining fixture and alias coverage in the release evidence; this checkpoint is not the full Slice 2 or release gate.
- Next shell increment: traverse substitutions using existing AST nodes so positions remain exact, then parse only statically recoverable `-c`, `eval`, and heredoc bodies. Never print an unredacted outer copy of a nested body. Cover parse failure after a valid command and exercise the compiled CLI before extending Python.

### Slices 3 and 4 checkpoint and re-groom

- The installed CLI matches the shell, Python, and embedded Python goldens. Both front ends share grammar lifecycle and AWS action classification. The release evidence records the exact tested inputs, results, and remaining gaps.
- Generating malformed Python revealed empty suites accepted by the grammar. Reject them before producing findings and keep the minimized CLI fixture. Continue using the same fail-before-report path for both languages.
- Twenty generated shell chains also pass through the installed CLI. Next release work should close the missing fixture matrix before broadening rule coverage. Keep the remaining limitations explicit in [the proof report](./docs/proof-of-working.md).
- The [proof report](./docs/proof-of-working.md#prompt-fixtures-and-release-gaps) now maps the shell, AWS and Python prompt rows to named checks and flags partial cases. Shell regression checks cover nested effects in redirects, conditionals and interpreter arguments. The AWS CLI credential list has explicit class and reason assertions. Finish the outstanding SDK variants before expanding provider rules; prior-art porting and runtime portability remain separate release checks.
- Credential and parameter-decryption behavior now lives in a shared AWS effects module instead of having the SDK adapter translate calls into CLI overrides. The downstream proof adds SDK credential, transfer helper, EC2 resource, and unresolved-method assertions. Prior-art fixture provenance and runtime portability remain separate checks.
- The pinned DeployShield segmentation suite is now ported with independent classifications and MIT attribution. Use it as the pattern for the remaining upstream modules: assert findings rather than copying the upstream hook's allow/block decisions.
- Normalization scenarios now exercise known wrapper flags, context and syntax failures. Unknown wrapper flags stay opaque; the analyzer does not reinterpret arbitrary flags as harmless. Prioritize provider and Python proof cases over broadening the wrapper allowlist.
- Supported `xargs` flags no longer hide fixed destructive commands, and runtime-supplied arguments cannot turn an uncertain command into a read-only finding. Context tests now cover flags, assignments, and inherited values. The package check directly verifies the permission boundary before running goldens; runtime portability and the remaining corpus are still separate release checks.
- Simple untyped SDK forwarders now get a finding at a call site with a known client. The definition remains UNKNOWN, so direct inference does not hide uncertainty about other callers. General interprocedural inference is not verified.
- The prior-art proof now exercises examples from all eight DeployShield modules, including packaged CLI integration. Context detection is tested; upstream hook formats and blocking policies are not part of this CLI. Filtered EC2 batches and the S3 single-object versus batch mapping now have direct assertions.
- The installed CLI passes on Node 22.18.0, and the S3 single-object and filtered batch delete findings now have an installed text and JSON golden. Keep minimum-runtime compatibility separate from the full Node 26 permission-denial proof. Neither changes the dependency pins or promotes the experiment to production.
- The packaged command now scans directories and reports partial failures without altering the single-file format. The installed checks cover both supported runtimes on macOS ARM64. The wider v1 gate remains open.
- Shell follow-up slice 1: declaration and `unset` substitutions are traversed without classifying the enclosing declaration as safe. The installed CLI and seeded property tests cover nested effects, positions, multiple substitutions, quoted literals, redirects and function calls. Comparing user-provided `opswork` reports found 88 added findings (69 UNKNOWN, 19 READ-ONLY), no removed findings, and the same eight errors. The reports do not identify their CLI version or input hashes, so the change cannot be attributed conclusively to this slice. Next, triage common unsupported commands; keep ambiguous effects UNKNOWN. Then assess nested uncertainty and investigate the four shell scan failures from sanitized examples.
- Shell follow-up slice 2 recognizes constrained `return`, `shift`, and `date` forms, retaining UNKNOWN for other forms and preserving redirect and nested effects. Version 0.2.0 adds a CLI-version header to text reports and a top-level `tool_version` to JSON reports; no input hashes are collected. Re-run the user corpus for observed changes. Prioritize other common unsupported commands only after checking their option and side-effect semantics; nested uncertainty and the four shell scan failures remain open.
- Shell follow-up slice 3 classifies the outer `echo` only for fully inspected, simple literal substitutions, leaving nested findings visible and complex cases UNKNOWN. On the user-supplied 0.2.0 corpus report, 435 UNKNOWN findings became 381 READ-ONLY and 54 LOCAL relative to the preceding report; input hashes are unavailable. The 0.3.0 corpus has not yet been scanned. Next, compare its report and investigate the four shell failures using sanitized examples; broader nested and command coverage remains conservative.
- Shell follow-up slice 4 adds constrained read-only classifications for common output-only utilities and for `sort` only when no output-file mode can apply. The 0.4.0 packaged CLI preserves `awk`/`sed` uncertainty, guards `sort -o`/`--output`, and keeps redirections visible. In the supplied 0.4.0 `opswork` report, 475 findings moved UNKNOWN→READ-ONLY and 2 moved UNKNOWN→LOCAL; 16 sort-output cases stayed UNKNOWN. Counts of dangerous findings (424) and scan errors (8) did not change from 0.3.0. The reports have no input hashes, so file identity is unverified. Next, inspect the common remaining function-call UNKNOWNs and the four shell scan failures using sanitized examples. Do not copy unknown command names into READ-ONLY without reviewing option semantics.
- Shell follow-up slice 5 lets a function call inherit a classification only from nonempty analyzed body findings, preserving UNKNOWN for unresolved, recursive, empty, or unknown-effect bodies. It also marks arithmetic commands and expansions UNKNOWN so state mutation cannot silently produce READ-ONLY summaries. The supplied `wow-slice5.json` report has 424 dangerous, 13 sensitive, 4,511 unknown, 929 local, and 3,640 read-only findings across 2,588 files, with 8 errors. Compared with 0.4.0, 233 function-call findings moved UNKNOWN to LOCAL or READ-ONLY; arithmetic uncertainty added UNKNOWN findings, for a net reduction of 98 UNKNOWN findings. No source files from `opswork` are available in this workspace.
- Shell follow-up slice 6 preserves a known outer command's effect independently of command/process substitutions, while keeping each inner finding visible. The guard excludes arithmetic expansion, dynamic redirects, interpreters, opaque wrappers, and read commands whose dynamic options could enable writes. Focused shell and seeded property tests cover READ-ONLY, LOCAL, DANGEROUS, and UNKNOWN inner effects. The supplied [0.6.0 report](./wow-slice6.json) has 424 dangerous, 13 sensitive, 4,179 unknown, 1,089 local, and 3,812 read-only findings across 2,588 files, with the same 8 error records as 0.5.0. At matching file/line/column/command locations, 172 UNKNOWN findings became READ-ONLY and 160 became LOCAL, with no added or removed findings; the nested-code reason count fell from 1,021 to 836. Input hashes are absent, so source identity is not proven. Re-groom from the remaining largest UNKNOWN reasons: unsupported commands (1,177), nested code (836), shell constructs (792), and unknown client types (575); arithmetic expansions now account for 105.
- Python-only re-groom from `wow-slice6.json`: the 2,490 `.py` reports are identical between 0.5.0 and 0.6.0. They contain 584 UNKNOWN findings, 575 for unresolved client type across 211 files; four Python files also have syntax errors. Treat client-type resolution as the next broad Python workstream, with conservative branch/function-flow boundaries and seeded properties. Keep the four parse failures separate; request sanitized excerpts only if investigating those.
- Python follow-up slice 7 (0.7.0) adds safe provenance labels to `client type not known` findings (untyped parameter, unsupported annotation, untracked import, unresolved assignment, function/class binding, or control-flow merge). It does not infer a client type or change a finding class. The full proof passed 81 tests; the packaged 0.7.0 CLI was built. The supplied `wow-slice7.json` splits the 575 prior client-type UNKNOWNs into 308 untyped parameters, 204 unresolved assignments, 50 untracked imports, 6 control-flow merges, 4 unsupported annotations, and 3 function/class bindings. The scan includes one added Python file (9 unresolved-assignment and 1 untyped-parameter UNKNOWN); all common-file Python class counts are unchanged. The largest candidates are untyped parameters and unresolved assignments, but the report omits the enclosing code and call sites. Before changing inference, get sanitized representative snippets for both patterns, including imports, definitions, assignments, and direct callers. No source values or arguments should be shared.
- Python follow-up slice 8 (0.8.0) resolves `boto3.Session` and aliased Session parameter annotations through existing module bindings; it does not guess from method names. On the user-provided Inspector SBOM script, UNKNOWN fell from 10 to 1. Five calls became DANGEROUS, three READ-ONLY, and one LOCAL; the analyzer also surfaced a read-only paginator operation and a local download. The remaining UNKNOWN is an untyped parameter in a public helper, kept conservatively. The full proof passed 83 tests and the 0.8.0 package was built. The supplied `wow-slice-ebs.json` is a separate 73-file scan: its 66 Python files have 106 findings and 22 UNKNOWNs, all with client-provenance reasons (13 untyped parameters, 8 unresolved assignments, 1 untracked import). It has no matching earlier report or input hashes, so it is a snapshot rather than a measured before/after.
- Python follow-up slice 9 (0.9.0) infers an untyped client parameter only for a private top-level helper whose direct in-file callers all supply a proven client for the same service. Public, exported, escaping, dynamic, unknown, mixed-service, and unsupported call forms stay UNKNOWN; cross-file callers are not inferred. Seeded property tests cover matching callers and conflicting services. Re-groom unresolved assignments and imports separately rather than broadening this rule.

### Property-testing standards

Use a TypeScript-compatible property-testing library such as `fast-check`. Group tests in a `TestProperties` suite and name the domain, type and failure caught in a `Catches:` comment. Use bounded generators, log the seed and replay path on failure, and preserve minimized bugs as named regression fixtures.

- **Integrity (SAFETY):** valid compound input does not lose or invent findings; deliberately malformed input never crashes or emits a partial report and exits 2.
- **Determinism (INVARIANT):** equivalent quoting, harmless whitespace and classification-neutral wrappers preserve the expected class. Repeated analysis with identical input, environment and snapshot yields identical output.
- **Ordering (SAFETY):** findings are grouped by class and ordered by source position within each group. Adding a command does not hide existing findings; derive the expected exit code from the complete set of classes, using the exit-code table rather than numeric severity.
- **Confidentiality (SAFETY):** generated synthetic credential values never appear in stdout or stderr in either output mode. Text and JSON report the same redacted findings.
- **Atomicity (SAFETY):** a failed data refresh leaves the previous snapshot intact.

Keep goldens and acceptance tests on the real CLI. Run high-volume properties against the relevant component and exercise the CLI boundary with a smaller, representative generated set. Property tests supplement, not replace, the edge-case tables and goldens.

## Done when

1. `cmdclass fixtures/copilot-sample.sh` prints exactly the checked-in expected report: line numbers, classes, reasons and the order of the groups.
2. Every row in the shell, AWS and boto3 edge-case tables has a fixture that passes.
3. `cmdclass fixtures/copilot-sample.py` prints exactly its checked-in expected report.
4. The exit codes match the table above, and a shell or Python parse error never yields a partial report or "all clear".
5. `--json` output carries `schema_version: 1`, matches the text findings, and redacts the same values.
6. Analysis succeeds with network access disabled. `--update-aws-data` validates downloaded data and its schema, records the date and sha256, and replaces the vendored snapshot atomically only after the full update succeeds; a failed update leaves the prior snapshot intact.
7. The AWS snapshot's date and sha256 appear in `cmdclass --version`.
8. Property-based tests cover the invariants above and run reproducibly as part of the test suite.

## Out of scope for v1

- Running, blocking or rewriting anything.
- Following `source`d files.
- SDKs other than boto3 (JavaScript v3, Go, Java). The AWS data maps only Boto3 methods today; add the others when it maps them.
- PowerShell.
- A hook mode. It can reuse the same engine later.

## Constraints

- TypeScript, strict mode, with a lockfile.
- Keep one source of truth per kind of fact. Generate AWS operation, SDK and IAM facts from the Service Reference snapshot; put only CLI-specific exceptions in CLI rules. Both front ends use the same operation classifier. Add provider policies in the registry, not in shell traversal; keep source decoding, classification and report rendering separate.
- Pin any dependency to a release that is at least 7 days old.
- CLI acceptance tests go through the real command-line entry point and assert the literal expected output where a golden is specified.
- Credit DeployShield (MIT) in a NOTICE file, and any other ported code under its own license.

## MEGA PROOF OF WORKING

Make this the final release gate, not a demo. Produce a reviewer-facing report at `docs/proof-of-working.md` with the exact reproduction commands, expected and observed results, and links to the tests and evidence. Build up the evidence after each slice and rerun the full gate against the packaged CLI before claiming v1 is done.

| What the reviewer should believe | Evidence required |
|---|---|
| It finds the right commands and gives the right results. | Map every shell, AWS and boto3 edge-case row and every supported provider to named tests. Run independent, hand-labeled goldens for shell, standalone Python and embedded Python. Assert classes, reasons, source locations, order, summary, JSON schema, stdout/stderr and exit status; report mismatches by class, with **any false READ-ONLY in the labeled corpus failing the gate**. |
| It survives combinations people did not handwrite. | Use seeded `fast-check` suites for mixed command chains, nesting, quoting, wrappers, malformed input, IAM action permutations, SDK resolution and redaction. Require at least 1,000 successful generated cases per core component property in the release run and a bounded representative set through the real CLI. Record run counts, seeds and replay paths for failures; check in minimized counterexamples as regression fixtures. Derive expected results from generator labels or hand-written rules, not from the implementation under test. |
| Analysis has no side effects and uncertainty stays visible. | Run the packaged CLI with network, subprocess execution and input writes denied by the test environment. Analyze synthetic scripts that would create a marker file or invoke an executable if run; assert neither happens and the inputs remain unchanged. Assert that unsupported or dynamic behavior is not reported as READ-ONLY and that malformed shell and Python exit 2 with empty stdout in both formats. |
| Reports don't leak the synthetic secrets they are designed to mask. | Put unique canaries into the documented credential forms, including nested or malformed inputs. Assert absence from stdout and stderr in text and JSON, and scan stored evidence for the same canaries. Use synthetic data only; never execute the fixture commands or access a real AWS account. |
| The exact shipped snapshot works offline and updating it cannot corrupt it. | Install from the lockfile, build and package, verify the bundled snapshot date and SHA-256, then run normal analysis with networking denied. Use simulated download, schema, integrity and write failures to prove the previous snapshot stays byte-for-byte unchanged. Compare repeated report output under the same inputs, environment and snapshot. |
| The suite catches real regressions and respects its limits. | Temporarily introduce representative regressions in a disposable copy: drop a chained finding, classify an incomplete IAM mapping as READ-ONLY, bypass redaction, and emit findings after a parse error. Record which named test fails for each, and confirm the unmodified build passes. Document resource limits and test oversized or deeply nested inputs against them; report the tested bounds and observed runtime. |

The report must identify the tested revision or source digest, Node version, OS, lockfile and AWS snapshot SHA-256. Include pass/fail/skip counts, explicit untested cases and limitations, and a short transcript from the installed command. A skipped or unrun required check is a failed release gate. Passing this gate demonstrates behavior on the documented corpus and test conditions; it does not certify scripts as safe or establish production readiness.
