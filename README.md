# cmdclass

**Status:** Installable proof of concept. It analyzes Bash/sh, supported literal shell bodies, and supported AWS SDK calls in standalone or embedded Python. See [Proof of working](./docs/proof-of-working.md) for what passed and what still blocks the v1 release gate.

This experiment asks whether an offline static analyzer can make the effects of shell and boto3 scripts easier to see before anyone runs them. It reports findings; it does not execute, rewrite, or block scripts. See the [build prompt](./cmdclass-build-prompt.md) for the scope, acceptance gates, and re-grooming process.

## Install and run

With Node.js 22.18.0 or newer, run these from the project directory:

```sh
npm ci --ignore-scripts
npm run build
npm install --global --ignore-scripts .
```

Then run `cmdclass` from any directory. It is an executable on `PATH` that uses Node.js, not a standalone native binary. To remove it, run `npm uninstall --global cmdclass`.

```sh
cmdclass --help
cmdclass ./script.sh
cmdclass ~/repos/fcc/opswork
cmdclass --json ~/repos/fcc/opswork
```

A directory scan recursively analyzes `.sh`, `.bash`, `.py`, and extensionless files with a supported Bash, sh, or Python shebang. It skips hidden entries, symbolic links within the tree, and directories named `node_modules`, `__pycache__`, `secrets`, or `credentials`. Each file is analyzed independently. Directory JSON includes relative paths in `files` and `errors`, plus a combined `summary`. Every JSON report has a top-level `tool_version`; text reports begin with the CLI version. Reports do not include input hashes, so a version alone does not establish that inputs are unchanged. The scan does not run scripts or contact AWS. Reports may contain sensitive filenames or arguments the redactor does not recognize; review before sharing.

For local commands, `return` and `shift` are recognized only without arguments or with one literal nonnegative integer. `shift` is LOCAL because it changes positional parameters. `date` is READ-ONLY only with no arguments, a UTC flag, a literal `+FORMAT`, or one of each. Other forms remain UNKNOWN; redirects and nested commands retain their own effects.

Known outer commands can retain their own effect when they contain command or process substitutions; each inner command is still reported independently, including UNKNOWN or dangerous effects. This applies only when the outer command's effect is established by a local rule. Arithmetic expansion, dynamic redirects, interpreters, and opaque wrappers remain UNKNOWN. For READ-ONLY, the nested-command allowlist excludes commands whose arguments can select a write mode unless those arguments are statically checked.

Known output-only utilities `grep`, `cat`, `dirname`, `basename`, `cut`, `tr`, `jq`, and `sleep` are recognized as READ-ONLY, subject to redirects and nested findings. `sort` is READ-ONLY except when an output-file option is present or may be dynamic; those forms remain UNKNOWN. `awk` and `sed` remain UNKNOWN because their programs can write files or launch commands.

Shell function calls inherit the least-safe finding from the analyzed function body, including LOCAL, DANGEROUS, and SENSITIVE effects. Empty, recursive, or unresolved function bodies remain UNKNOWN. Arithmetic commands and arithmetic expansions remain UNKNOWN rather than being assumed side-effect-free.

Python UNKNOWN findings for unresolved client receivers include a generic provenance reason, such as a function or class binding, untyped parameter, unsupported annotation, untracked import, unresolved assignment, or control-flow merge. These labels contain no source-level names or arguments and do not change the classification; they help identify which conservative analysis gap to address next.

Function parameters annotated with a tracked `boto3.Session` or `aioboto3.Session` type can resolve clients created through `session.client(...)`. Unsupported or dynamic annotations remain UNKNOWN; an untyped parameter is not inferred from method names.

An untyped client parameter can also be resolved in a private, top-level helper when every direct in-file call supplies a proven client for the same service. Public or exported helpers, aliases or other escapes, dynamic calls, unknown callers, mixed services, and unsupported argument forms remain UNKNOWN. This does not follow callers across files.

Exit codes: `0` for read-only or no findings, `1` for any dangerous, unknown, or local finding, `3` for sensitive findings with no exit-`1` findings, and `2` for usage, read, or parse errors. A directory scan still reports successfully analyzed files when another file fails; errors take precedence over findings in the exit code.

## Versioning

The package manifest is the source of truth for `cmdclass --version`. While this experiment is pre-1.0, use a patch bump for fixes and a minor bump for new or incompatible behavior; reaching 1.0 is a deliberate release decision. Before packaging a release, run `npm version patch --no-git-tag-version --ignore-scripts` (or replace `patch` with `minor`), then build, run the proof suite, and run `npm pack --ignore-scripts`. This updates the manifest and lockfile together without creating a Git tag.

## Validate the components

The 0.5.0 CLI was verified on the minimum supported Node.js version, 22.18.0, on macOS ARM64. The 0.9.0 changes have full proof on Node 26; rerun the minimum-version check before release because its cached runtime is not present in this workspace. See the [proof report](./docs/proof-of-working.md) for reproduction steps.

```sh
npm ci --ignore-scripts
npm run build
npm run typecheck
npm test
npm run test:proof
node dist/cli.js tests/fixtures/shell/local-effects.sh
```

Tests cover report formatting, ordering, terminal control-character escaping, exit-code precedence across all class combinations, conservative classification of already-parsed local commands, and redaction of synthetic credentials from command text in both report formats. Property tests generate report orderings and credential shapes. The tests themselves require no cloud account, network access, or cleanup after installation.

The approved `@vscode/tree-sitter-wasm` grammar loads with `web-tree-sitter` and reports missing nodes through the root's error flag. The CLI rejects the whole script in that case. The regression fixture covers an unclosed substitution after a valid command.

## Where changes belong

- **AWS operation facts:** [the generated snapshot](./data/aws.json) is the single source of truth for SDK names, operation-to-action mappings, and IAM access levels. Refresh it with `node dist/cli.js --update-aws-data`; do not hand-edit it or add a competing service-to-IAM table.
- **AWS behavior:** [CLI parsing](./src/aws/cli.ts) handles flags and context; [CLI rules](./src/aws/cli-rules.ts) holds CLI-only behavior and CLI-to-SDK name exceptions. Both front ends use [shared effects](./src/aws/effects.ts) for credential and parameter-decryption policy and [the operation classifier](./src/aws/operations.ts) for canonical API operations and IAM mappings.
- **Python behavior:** [the Python analyzer](./src/python.ts) resolves source bindings and delegates SDK classification to [the SDK adapter](./src/aws/python.ts). Resource shapes and action names come from the [generated Boto3 catalog](./data/boto3-resources.json); IAM effects still come from the AWS snapshot. Maintainers can regenerate the resource catalog with `node scripts/update-boto3-resources.mjs` using GitHub CLI access. Both input languages share [parser lifecycle and input bounds](./src/syntax.ts).
- **Shell behavior:** [the shell analyzer](./src/shell.ts) walks syntax and dispatches findings. [Source handling](./src/shell/source.ts) owns literal extraction and location mapping. [Wrapper normalization](./src/shell/wrappers.ts) unwraps known command forms without guessing unknown options. Provider rules belong in [the provider registry](./src/providers.ts), not in AST traversal.

See the [build plan](./cmdclass-build-prompt.md#slice-2-checkpoint-and-re-groom) for outstanding fixture coverage and the release gate.
