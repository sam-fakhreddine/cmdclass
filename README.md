# cmdclass

cmdclass is an offline static analyzer for Bash/sh scripts and supported AWS calls in Python. It reports possible effects without running or changing the input.

![Terminal demo: cmdclass reports dangerous, sensitive, unknown, local, and read-only findings](./docs/demo.gif)

Illustrated replay of actual CLI output; colors are added.

This proof of concept has coverage gaps, including dynamic behavior. An empty report does not mean a script is safe. Reports can contain sensitive filenames or arguments. Review them before sharing.

## Install

Requires Node.js 22.18.0 or newer. From the project directory:

```sh
npm ci --ignore-scripts
npm run build
npm install --global --ignore-scripts .
```

To uninstall, run `npm uninstall --global cmdclass`.

## Use

```sh
cmdclass --help
cmdclass ./script.sh
cmdclass ./script.py
cmdclass ./scripts
cmdclass --json ./scripts
cmdclass --permissions ./script.sh
cmdclass --permissions --json ./scripts
```

Directory scans include `.sh`, `.bash`, `.py`, and extensionless files with a supported shebang. Hidden entries, symlinks, and directories named `node_modules`, `__pycache__`, `cdk.out`, `secrets`, or `credentials` are skipped. Each file gets its own report. A Python file's imports of project modules are followed when the module is found beside the script or in a parent directory, up to the repository root (`.git`) or the outermost `pyproject.toml`, `setup.py`, or `setup.cfg`; installed packages and shell `source` are not followed.

Use `--permissions` to report candidate IAM actions from the bundled AWS snapshot. Combine it with `--json` for action locations and unresolved findings. The report is not a proven minimum: mappings can include conditional actions, and dynamic code, subprocesses, runtime conditions, and downstream calls can require additional permissions. Resources are UNKNOWN; the report does not generate an IAM policy. Directory exclusions and scan errors can leave permissions undiscovered. Exit codes retain the effect report semantics.

Findings are grouped by effect:

| Class | Meaning |
|---|---|
| MUTATING | Changes remote state, deletes local data, or creates credentials or access |
| SENSITIVE | Reads a secret or returns temporary credentials |
| UNKNOWN | The effect cannot be determined |
| LOCAL | Changes local state |
| READ-ONLY | A recognized read with no reported sensitive effect |

Exit codes are `0` for read-only or no findings, `1` for mutating, unknown, or local findings, `3` for sensitive findings without exit-`1` findings, and `2` for usage, read, or parse errors. Directory scans report successful files alongside errors; errors take precedence.

Python AWS clients are followed through assignments, functions, classes, tuples, and imported project helpers. A client passed into a function is resolved from the call sites in the same file; when the function can also be called from elsewhere, the reason says `client inferred from call sites in this file`. Calls made inside an imported helper are reported at the call site with `in an imported function`. An SDK-shaped call on a receiver that cannot be traced is reported as UNKNOWN with the reason it could not be traced, never dropped; in `--permissions` output it carries candidate actions when the method name is distinctive. Not followed: clients that arrive from callers in other files, values stored in containers, `getattr` and other dynamic dispatch, decorators that change a call, and classes or helpers from installed packages. A script that calls such a method on a non-AWS object with the same method name also gets an UNKNOWN.

Python UNKNOWN findings carry a sub-label when the cause is known. `EXTERNAL CALL` means the answer depends on code or values outside the file: a client or service name handed in by a caller, an object from a module that was not followed, or a launched program. `INLINE` means everything is in the file but is only known at runtime, such as a service name computed in a loop, a client taken from a container, or callers in the file that pass different clients. The text report shows it before the reason (`EXTERNAL CALL: client type not known (...)`), and JSON entries carry it as `unknown_kind`. Findings with no sub-label are gaps in the bundled AWS data. Among shell findings, only text-scan hits are sub-labelled. Report JSON is `schema_version` 2: it added this field and renamed the `DANGEROUS` class to `MUTATING`.

In shell scripts, commands are reported wherever they appear, including loop headers, `for` and `case` word lists, and several assignments on one line. Declarations (`local`, `export`, `declare`, `unset`), assignments, and arithmetic are LOCAL; the commands nested in them are reported separately. Arithmetic is not inspected for variables whose contents could themselves run code. Builtins and text filters are classified only in forms whose effect is certain: `sed` without in-place editing or a write or execute flag, `awk` with a literal program that has no `system`, pipe, redirect, or `getline`, `find` without an action, `kill -0`, and `command -v`. An AWS call keeps its AWS reason when its output is redirected, and an `aws` command handed to an unknown wrapper (`retry 3 aws ...`) is classified when it mutates or reads secrets.

Inline Python in a shell script (`python -c`, a heredoc) is analysed for AWS calls and process launches only; when it yields neither, the line is reported UNKNOWN instead of being left out. The read-only rules are checked against the [GTFOBins](https://gtfobins.org) catalogue of binaries that can write files or run commands: `node scripts/crosscheck-gtfobins.ts <api.json>` fails if any catalogued abuse comes out READ-ONLY or unreported. That data is GPL-3.0 and is not bundled.

As a backstop, a text scan looks for `aws <service> <operation>` anywhere in a shell script that no analysed command accounts for, such as a command stored in a string or written into a heredoc. Each hit is UNKNOWN with the reason `AWS command in script text, not confirmed as executed`, followed by what the operation would be. Comments and text that is only printed to the terminal are skipped.

Python subprocess launches retain an UNKNOWN finding. Some literal AWS commands and direct wrapper calls also receive a separate AWS classification; dynamic or unsupported command forms remain uncertain.

## Validate

```sh
npm run test:proof
```

## Release

Bump the package version with `npm version patch --no-git-tag-version --ignore-scripts` (or use `minor` for a feature release), then commit and push the version change. Push a matching `v<version>` tag to run the release workflow. It runs the proof suite and attaches the `npm pack` tarball to a GitHub Release.

See the [proof of working](./docs/proof-of-working.md) for test evidence and known gaps, and the [build prompt](./cmdclass-build-prompt.md) for scope and design details. Analysis uses the bundled AWS snapshot; `cmdclass --update-aws-data` explicitly refreshes it.
