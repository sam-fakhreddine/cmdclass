import type { Node } from "web-tree-sitter";
import { classifyAws } from "./aws/cli.ts";
import { classifySdkMethod } from "./aws/python.ts";
import { classifyOperation, loadOfflineSnapshot, sdkIndex, unknownAws } from "./aws/operations.ts";
import type { AwsEffect } from "./aws/operations.ts";
import { loadResources, resourceShape } from "./aws/resources.ts";
import type { Finding } from "./report.ts";
import { withSyntax } from "./syntax.ts";

type UnknownOrigin =
  | "untracked import"
  | "function or class binding"
  | "untyped function parameter"
  | "unsupported parameter annotation"
  | "unresolved assignment"
  | "control-flow merge";
interface ProcessWrapper {
  parameters: string[];
  rest: string;
  command: Node;
  process: Node;
}
type Binding =
  | { kind: "module"; path: string }
  | { kind: "literal"; value: string }
  | { kind: "session" | "client" | "resource"; service?: string; context?: Record<string, string>; shape?: string; collection?: boolean }
  | { kind: "factory"; result: Binding }
  | { kind: "function"; name: string }
  | { kind: "process-wrapper"; wrapper: ProcessWrapper }
  | { kind: "forwarder"; parameter: string; method: string; call: Node }
  | { kind: "unknown"; origin?: UnknownOrigin };
const unknown = (origin: UnknownOrigin): Binding => ({ kind: "unknown", origin });
type Scope = Map<string, Binding>;
const field = (node: Node | null, name: string) => node?.childForFieldName(name) ?? null;
const identifier = (node: Node | null) => node?.type === "identifier" ? node.text : undefined;
const safeName = (value: string | undefined) => value && /^[a-zA-Z0-9._-]+$/.test(value) ? value : undefined;
const simpleString = (node: Node | null) => {
  if (node?.type !== "string") return undefined;
  return /^(["'])([^"'\\\r\n]*)\1$/.exec(node.text)?.[2];
};
const awsModule = /^(?:boto3|aioboto3|botocore|moto)(?:\.|$)/;
const trackedModule = /^(?:boto3|aioboto3|botocore|moto|subprocess|asyncio|os)(?:\.|$)/;
const processLaunchPaths = new Set([
  "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call",
  "subprocess.check_output", "subprocess.getoutput", "subprocess.getstatusoutput",
  "os.system", "os.popen", "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell",
]);
const argvProcessPaths = new Set([
  "subprocess.run", "subprocess.Popen", "subprocess.call",
  "subprocess.check_call", "subprocess.check_output",
]);
const branches = new Set(["if_statement", "for_statement", "while_statement", "try_statement", "match_statement"]);
const sessionTypePaths = new Set([
  "boto3.Session", "boto3.session.Session", "aioboto3.Session", "aioboto3.session.Session",
]);
const sessionFactoryPaths = new Set([...sessionTypePaths, "botocore.session.get_session"]);
type Catalog = Awaited<ReturnType<typeof loadResources>>;

function argumentsOf(call: Node) {
  const args = field(call, "arguments")?.namedChildren ?? [];
  const keyword = (key: string) => field(args.find((arg) =>
    arg.type === "keyword_argument" && field(arg, "name")?.text === key) ?? null, "value");
  return { args, keyword, unpacked: args.some((n) => n.type === "dictionary_splat") };
}

function policyContext(call: Node, scope: Scope, previous?: Record<string, string>) {
  const { keyword } = argumentsOf(call);
  const context = { ...previous };
  for (const [argument, label] of [["profile_name", "profile"], ["region_name", "region"]]) {
    const node = keyword(argument);
    if (!node) continue;
    const value = safeName(literal(node, scope));
    if (value) context[label] = value;
    else delete context[label];
  }
  return Object.keys(context).length ? context : undefined;
}

function literal(node: Node | null, scope: Scope) {
  const v = node && scope.get(node.text);
  return v?.kind === "literal" ? v.value : simpleString(node);
}

function resolve(node: Node | null, scope: Scope, catalog: Catalog): Binding | undefined {
  if (!node) return undefined;
  if (node.type === "identifier") return scope.get(node.text);
  if (node.type === "await" || node.type === "parenthesized_expression") return resolve(node.firstNamedChild, scope, catalog);
  if (node.type === "attribute") {
    const bound = scope.get(node.text);
    if (bound) return bound;
    const base = resolve(field(node, "object"), scope, catalog);
    const attr = field(node, "attribute")?.text;
    if (base?.kind === "module" && attr) return { kind: "module", path: `${base.path}.${attr}` };
    if (base?.kind === "resource" && attr && !base.collection) {
      const collections = resourceShape(catalog, base.service, base.shape)?.collections;
      if (collections && Object.hasOwn(collections, attr)) return { ...base, shape: collections[attr], collection: true };
    }
  }
  if (node.type === "call") {
    const fn = field(node, "function");
    const object = resolve(field(fn, "object"), scope, catalog);
    const method = field(fn, "attribute")?.text;
    const target = fn?.type === "attribute"
      ? object?.kind === "module" && method ? { kind: "module" as const, path: `${object.path}.${method}` } : undefined
      : resolve(fn, scope, catalog);
    const { args, keyword } = argumentsOf(node);
    if (target?.kind === "factory" && !args.length) return target.result;
    if (target?.kind === "module" && sessionFactoryPaths.has(target.path)) {
      return { kind: "session", context: policyContext(node, scope) };
    }
    const direct = target?.kind === "module" && /^(?:boto3|aioboto3)\.(?:client|resource)$/.test(target.path);
    if (direct || (object?.kind === "session" && ["client", "resource", "create_client"].includes(method ?? ""))) {
      const service = safeName(literal(keyword("service_name") ?? args[0] ?? null, scope));
      return { kind: (method ?? (target?.kind === "module" ? target.path.split(".").at(-1) : "")) === "resource"
        ? "resource" : "client", service, context: policyContext(node, scope, object?.kind === "session" ? object.context : undefined) };
    }
    if (object?.kind === "resource" && method) {
      const shape = resourceShape(catalog, object.service, object.shape);
      if (object.collection && ["all", "filter", "limit", "page_size"].includes(method)) return object;
      if (shape && !object.collection) {
        const type = Object.hasOwn(shape.constructors, method) ? shape.constructors[method] :
          Object.hasOwn(shape.actions, method) ? shape.actions[method].result : undefined;
        if (type) return { ...object, shape: type };
      }
    }
  }
}

function bindImports(node: Node, scope: Scope) {
  const from = field(node, "module_name")?.text;
  for (const name of node.childrenForFieldName("name")) {
    const qualified = (field(name, "name") ?? name).text;
    const alias = field(name, "alias")?.text ?? (from ? qualified : qualified.split(".")[0]);
    const path = from ? `${from}.${qualified}` : field(name, "alias") ? qualified : alias;
    scope.set(alias, trackedModule.test(path) ? { kind: "module", path } : unknown("untracked import"));
  }
}

export async function analyzePython(source: string): Promise<Finding[]> {
  return withSyntax("python", source, async (root) => {
    const [snapshot, catalog] = await Promise.all([loadOfflineSnapshot(), loadResources()]);
    const findings: Finding[] = [];
    const processFindings = new Map<number, Promise<Finding | undefined>>();
    const sdk = snapshot && sdkIndex(snapshot);
    type HelperCandidate = {
      node: Node;
      name: string;
      parameters: string[];
      binding: Extract<Binding, { kind: "function" }>;
      directCalls: number;
      callArguments: (Map<string, Binding> | undefined)[];
      invalid: boolean;
      definitionScope?: Scope;
      originalFindings?: Finding[];
    };
    const helperCandidates = new Map<string, HelperCandidate>();
    const candidatesByNode = new WeakMap<Node, HelperCandidate>();
    const exportedFunctions = new Set<string>();
    let dynamicExports = false;
    for (const statement of root.namedChildren) {
      const assignment = statement.type === "expression_statement" ? statement.firstNamedChild : statement;
      if (assignment?.type === "augmented_assignment" &&
          identifier(field(assignment, "left")) === "__all__") {
        dynamicExports = true;
      }
      if (assignment?.type !== "assignment" || identifier(field(assignment, "left")) !== "__all__") continue;
      const value = field(assignment, "right");
      if (!value || !["list", "tuple"].includes(value.type) ||
          value.namedChildren.some((item) => item.type !== "string" || simpleString(item) === undefined)) {
        dynamicExports = true;
        continue;
      }
      for (const item of value.namedChildren) {
        const name = simpleString(item);
        if (name) exportedFunctions.add(name);
      }
    }
    function findNestedExports(node: Node) {
      if ((node.type === "assignment" || node.type === "augmented_assignment") &&
          identifier(field(node, "left")) === "__all__" &&
          !(node.parent?.type === "expression_statement" && node.parent.parent?.type === "module")) {
        dynamicExports = true;
      }
      for (const child of node.namedChildren) findNestedExports(child);
    }
    findNestedExports(root);

    function directUses(definition: Node, name: string) {
      const defName = field(definition, "name");
      let calls = 0;
      let escapes = false;
      function walk(node: Node) {
        if (node.type === "identifier" && node.text === name) {
          if (node.startIndex === defName?.startIndex && node.endIndex === defName.endIndex) return;
          const parent = node.parent;
          if (parent?.type === "attribute" && field(parent, "attribute")?.startIndex === node.startIndex) return;
          if (parent?.type === "call" && field(parent, "function")?.startIndex === node.startIndex) calls++;
          else escapes = true;
        }
        if (node.type === "string" && simpleString(node) === name) escapes = true;
        for (const child of node.namedChildren) walk(child);
      }
      walk(root);
      return { calls, escapes };
    }

    const topLevelFunctions = root.namedChildren.filter((node) => node.type === "function_definition");
    const functionCounts = new Map<string, number>();
    for (const node of topLevelFunctions) {
      const name = identifier(field(node, "name"));
      if (name) functionCounts.set(name, (functionCounts.get(name) ?? 0) + 1);
    }
    for (const node of topLevelFunctions) {
      const name = identifier(field(node, "name"));
      const parameters = field(node, "parameters")?.namedChildren ?? [];
      const body = field(node, "body");
      if (!name || !name.startsWith("_") || name.startsWith("__") ||
          dynamicExports || exportedFunctions.has(name) ||
          functionCounts.get(name) !== 1 || !body || !parameters.length ||
          parameters.some((parameter) => parameter.type !== "identifier")) continue;
      const parameterNames = parameters.map((parameter) => parameter.text);
      const statements = body.namedChildren.filter((entry) => entry.type !== "comment");
      const call = statements.length === 1 && statements[0].type === "expression_statement"
        ? statements[0].firstNamedChild : null;
      const target = call?.type === "call" ? field(call, "function") : null;
      if (parameterNames.length === 1 && identifier(field(target, "object")) === parameterNames[0] &&
          identifier(field(target, "attribute"))) continue;
      const uses = directUses(node, name);
      if (uses.escapes || !uses.calls) continue;
      const candidate: HelperCandidate = {
        node, name, parameters: parameterNames, binding: { kind: "function", name },
        directCalls: uses.calls, callArguments: [], invalid: false,
      };
      helperCandidates.set(name, candidate);
      candidatesByNode.set(node, candidate);
    }

    let mocked = false;
    const stubbed = new Set<Binding>();
    let collectingHelperCalls = true;
    const moduleScope: Scope = new Map();

    function emit(node: Node, method: string, effect: AwsEffect, receiver?: Binding) {
      const context = receiver && "context" in receiver ? receiver.context : undefined;
      findings.push({
        line: node.startPosition.row + 1, column: node.startPosition.column + 1,
        command: `${method}(...)`, ...effect, ...(context && { context }),
        reason: mocked || (receiver && stubbed.has(receiver)) ? `${effect.reason}; inside a test` : effect.reason,
      });
    }

    function importedPath(node: Node | null, scope: Scope) {
      const binding = resolve(node?.type === "call" ? field(node, "function") : node, scope, catalog);
      return binding?.kind === "module" ? binding.path : undefined;
    }

    function processArgument(call: Node, scope: Scope) {
      if (!argvProcessPaths.has(importedPath(field(call, "function"), scope) ?? "")) return undefined;
      const { args } = argumentsOf(call);
      const positional = args.filter((arg) => arg.type !== "keyword_argument");
      if (positional.length !== 1 || positional[0].type === "list_splat" ||
          positional[0].type === "dictionary_splat") return undefined;
      for (const arg of args.filter((item) => item.type === "keyword_argument")) {
        const key = field(arg, "name")?.text;
        const value = field(arg, "value");
        if (key === "shell" && value?.type === "false") continue;
        if (!key || !["capture_output", "text", "timeout", "check", "encoding", "errors"].includes(key) ||
            !value || !["true", "false", "integer", "float", "none", "string"].includes(value.type) ||
            (value.type === "string" && simpleString(value) === undefined)) return undefined;
      }
      return positional[0];
    }

    function wrapperFor(node: Node, scope: Scope): ProcessWrapper | undefined {
      if (node.parent?.type !== "module") return undefined;
      const params = field(node, "parameters")?.namedChildren ?? [];
      const restNode = params.at(-1);
      const rest = restNode?.type === "list_splat_pattern" ? identifier(restNode.firstNamedChild) : undefined;
      if (!rest || params.slice(0, -1).some((parameter) => parameter.type !== "identifier")) return undefined;
      const statements = field(node, "body")?.namedChildren.filter((entry) => entry.type !== "comment") ?? [];
      const assignment = statements[0]?.type === "expression_statement" ? statements[0].firstNamedChild : null;
      const target = identifier(field(assignment, "left"));
      const command = field(assignment, "right");
      if (assignment?.type !== "assignment" || !target || !command ||
          !["list", "tuple"].includes(command.type)) return undefined;
      const statement = statements[1];
      let process = statement?.type === "return_statement" || statement?.type === "expression_statement"
        ? statement.firstNamedChild : null;
      if (process?.type === "assignment") process = field(process, "right");
      if (process?.type !== "call" || identifier(processArgument(process, scope) ?? null) !== target) return undefined;
      return { parameters: params.slice(0, -1).map((parameter) => parameter.text), rest, command, process };
    }

    const unknownSpread = Symbol("unknown spread");
    type ProcessWord = string | null | typeof unknownSpread;
    function commandWords(command: Node, values?: ReadonlyMap<string, string | null>,
      restName?: string, rest: ProcessWord[] = []): (string | null)[] | undefined {
      if (!["list", "tuple"].includes(command.type)) return undefined;
      const words: (string | null)[] = [];
      for (const item of command.namedChildren) {
        const tokens: ProcessWord[] = item.type === "list_splat"
          ? restName !== undefined && identifier(item.firstNamedChild) === restName ? rest : [unknownSpread]
          : [values?.get(item.text) ?? simpleString(item) ?? null];
        for (const token of tokens) {
          if (token === unknownSpread) return [...words, null];
          words.push(token);
        }
      }
      return words;
    }

    function recordAwsProcess(node: Node, words: (string | null)[] | undefined) {
      if (!words || words[0] !== "aws") return;
      const line = node.startPosition.row + 1;
      const column = node.startPosition.column + 1;
      processFindings.set(node.startIndex, classifyAws(words, null).then((effect) => {
        if (effect.class === "UNKNOWN") return undefined;
        return {
          line, column, command: "aws(...)", class: effect.class,
          reason: `${effect.reason}; via Python subprocess`, source: effect.source,
        };
      }));
    }

    function inspectProcessWrapper(node: Node, wrapper: ProcessWrapper, scope: Scope) {
      if (!processArgument(wrapper.process, scope)) return;
      const { args } = argumentsOf(node);
      const values = new Map<string, string | null>();
      const rest: ProcessWord[] = [];
      for (const arg of args) {
        if (arg.type === "keyword_argument" || arg.type === "dictionary_splat") return;
        if (arg.type === "list_splat") {
          if (values.size < wrapper.parameters.length) return;
          rest.push(unknownSpread);
          break;
        }
        if (values.size < wrapper.parameters.length) {
          values.set(wrapper.parameters[values.size], simpleString(arg) ?? null);
        } else rest.push(simpleString(arg) ?? null);
      }
      if (values.size !== wrapper.parameters.length) return;
      recordAwsProcess(node, commandWords(wrapper.command, values, wrapper.rest, rest));
    }

    function sdkEffect(node: Node, scope: Scope | undefined, service: string, method: string) {
      const { args, keyword, unpacked } = argumentsOf(node);
      const decrypt = keyword("WithDecryption");
      const target = args[0] ?? null;
      return classifySdkMethod(snapshot, service, method, {
        target: scope ? literal(target, scope) : simpleString(target), unpacked,
        decrypt: !decrypt || decrypt.type === "false" ? false : decrypt.type === "true" ? true : undefined,
        dryRun: keyword("DryRun")?.type === "true",
      });
    }

    function callArguments(call: Node, parameters: string[], scope: Scope) {
      const args = argumentsOf(call).args;
      if (args.some((arg) => arg.type === "list_splat" || arg.type === "dictionary_splat")) return undefined;
      const assigned = new Map<string, Node>();
      let position = 0;
      for (const arg of args) {
        if (arg.type === "keyword_argument") {
          const name = field(arg, "name")?.text;
          const value = field(arg, "value");
          if (!name || !value || !parameters.includes(name) || assigned.has(name)) return undefined;
          assigned.set(name, value);
        } else {
          const name = parameters[position++];
          if (!name || assigned.has(name)) return undefined;
          assigned.set(name, arg);
        }
      }
      if (assigned.size !== parameters.length) return undefined;
      return new Map(parameters.map((name) => {
        const value = resolve(assigned.get(name) ?? null, scope, catalog);
        return [name, value ?? unknown("unresolved assignment")];
      }));
    }

    function inspectCall(node: Node, scope: Scope) {
      const fn = field(node, "function");
      const path = importedPath(fn, scope);
      if (path && processLaunchPaths.has(path)) {
        emit(node, path, {
          class: "UNKNOWN", reason: "Python subprocess command is not analysed", source: "Python process launch",
        });
        const argument = processArgument(node, scope);
        if (argument) recordAwsProcess(node, commandWords(argument));
        return;
      }
      const name = identifier(fn);
      const candidate = name && helperCandidates.get(name);
      if (collectingHelperCalls && candidate) {
        const binding = scope.get(name!);
        if ((!binding && scope === moduleScope) || (binding && binding !== candidate.binding)) {
          candidate.invalid = true;
        }
        candidate.callArguments.push(callArguments(node, candidate.parameters, scope));
      }
      const bound = name && scope.get(name);
      if (bound && bound.kind === "process-wrapper") inspectProcessWrapper(node, bound.wrapper, scope);
      if (bound && bound.kind === "forwarder") {
        const { args, keyword } = argumentsOf(node);
        const argument = args.length === 1 && args[0].type !== "keyword_argument" ? args[0] : null;
        const receiver = args.length === 1 ? resolve(keyword(bound.parameter) ?? argument, scope, catalog) : undefined;
        if (receiver?.kind === "client" && receiver.service) {
          const effect = sdkEffect(bound.call, undefined, receiver.service, bound.method);
          emit(node, bound.method, { ...effect, reason: `${effect.reason}; via ${name}()` }, receiver);
        }
      }
      const method = identifier(field(fn, "attribute"));
      const receiver = resolve(field(fn, "object"), scope, catalog);
      if (fn?.type === "call" && identifier(field(fn, "function")) === "getattr") {
        const target = resolve(argumentsOf(fn).args[0] ?? null, scope, catalog);
        if (target?.kind === "client" || target?.kind === "resource") {
          emit(node, "getattr", unknownAws("method name is dynamic"), target);
        }
      }
      if (!method) return;
      if (receiver?.kind !== "client" && receiver?.kind !== "resource") {
        if (receiver?.kind === "unknown" && sdk?.methods.has(method) &&
            [...scope.values()].some((value) => value.kind === "module" && awsModule.test(value.path))) {
        const reason = receiver.origin
          ? `client type not known (${receiver.origin})`
          : "client type not known";
        emit(node, method, unknownAws(reason));
        }
        return;
      }
      if (!receiver.service) {
        emit(node, method, unknownAws("service is in a variable"), receiver);
        return;
      }
      let effect: AwsEffect;
      if (receiver.kind === "resource") {
        const shape = resourceShape(catalog, receiver.service, receiver.shape);
        const actions = receiver.collection ? shape?.batch : shape?.actions;
        const action = actions && Object.hasOwn(actions, method) ? actions[method] : undefined;
        if (!action && resolve(node, scope, catalog)?.kind === "resource") return;
        const namespaces = sdk?.namespaces.get(receiver.service);
        const namespace = namespaces?.values().next().value ?? receiver.service;
        effect = action && snapshot && (namespaces?.size ?? 0) <= 1
          ? classifyOperation(snapshot, namespace, action.operation) : unknownAws("resource operation is not mapped");
      } else effect = sdkEffect(node, scope, receiver.service, method);
      emit(node, method, effect, receiver);
    }

    function visit(
      node: Node, scope: Scope, parameterOverrides?: ReadonlyMap<string, Binding>, replayingHelper = false,
    ) {
      if (node.type === "import_statement" || node.type === "import_from_statement") {
        bindImports(node, scope);
        return;
      }
      if (node.type === "decorated_definition") {
        const definition = field(node, "definition");
        const decorators = node.namedChildren.filter((item) => item.type === "decorator");
        const previous = mocked;
        for (const decorator of decorators) visit(decorator, scope);
        mocked ||= decorators.some((item) => importedPath(item.firstNamedChild, scope) === "moto.mock_aws");
        try {
          if (definition) visit(definition, scope);
        } finally {
          mocked = previous;
        }
        return;
      }
      if (node.type === "with_statement") {
        const previous = mocked;
        const added: Binding[] = [];
        const clause = node.namedChildren.find((item) => item.type === "with_clause");
        if (clause) visit(clause, scope);
        for (const item of clause?.namedChildren ?? []) {
          const value = field(item, "value");
          const expression = value?.type === "as_pattern" ? value.firstNamedChild : value;
          if (expression?.type !== "call") continue;
          const path = importedPath(expression, scope);
          if (path === "moto.mock_aws") mocked = true;
          if (path === "botocore.stub.Stubber") {
            const receiver = resolve(argumentsOf(expression).args[0] ?? null, scope, catalog);
            if (receiver?.kind === "client" && !stubbed.has(receiver)) {
              stubbed.add(receiver);
              added.push(receiver);
            }
          }
        }
        try {
          const body = field(node, "body");
          if (body) visit(body, scope);
        } finally {
          mocked = previous;
          for (const receiver of added) stubbed.delete(receiver);
        }
        return;
      }
      if (node.type === "function_definition" || node.type === "class_definition") {
        const name = identifier(field(node, "name"));
        const helper = candidatesByNode.get(node);
        if (name) scope.set(name, helper?.binding ?? unknown("function or class binding"));
        const child = new Map(scope);
        for (const parameter of field(node, "parameters")?.namedChildren ?? []) {
          const param = identifier(parameter.type === "identifier" ? parameter :
            field(parameter, "name") ?? parameter.firstNamedChild);
          if (!param) continue;
          const override = parameterOverrides?.get(param);
          if (override) {
            child.set(param, override);
            continue;
          }
          const annotationNode = field(parameter, "type");
          const annotation = annotationNode?.text;
          const annotationBinding = resolve(annotationNode?.firstNamedChild ?? null, child, catalog);
          const service = annotation && /^([a-zA-Z0-9]+)Client$/.exec(annotation)?.[1]?.toLowerCase();
          child.set(param, annotationBinding?.kind === "module" && sessionTypePaths.has(annotationBinding.path)
            ? { kind: "session" }
            : service && sdk?.namespaces.has(service)
              ? { kind: "client", service }
              : unknown(annotation ? "unsupported parameter annotation" : "untyped function parameter"));
        }
        const body = field(node, "body");
        const findingsStart = findings.length;
        if (helper && !replayingHelper) helper.definitionScope = new Map(scope);
        if (body) visit(body, child);
        if (helper && body && !replayingHelper) {
          helper.originalFindings = findings.splice(findingsStart);
        }
        const parameters = field(node, "parameters");
        if (body && name && parameters && node.parent?.type === "module") {
          const params = parameters.namedChildren;
          const statements = body.namedChildren.filter((entry) => entry.type !== "comment");
          const call = statements.length === 1 && statements[0].type === "expression_statement"
            ? statements[0].firstNamedChild : null;
          const target = call?.type === "call" ? field(call, "function") : null;
          const parameter = identifier(field(target, "object"));
          const method = identifier(field(target, "attribute"));
          if (call && parameter && method && params.length === 1 && identifier(params[0]) === parameter) {
            scope.set(name, { kind: "forwarder", parameter, method, call });
          }
        }
        if (body && name && parameters && !parameters.namedChildCount) {
          const statements = body.namedChildren.filter((entry) => entry.type !== "comment");
          const last = statements.at(-1);
          if (last?.type === "return_statement" && statements.slice(0, -1).every((statement) =>
              statement.type === "expression_statement" && statement.firstNamedChild?.type === "assignment")) {
            const result = resolve(last.firstNamedChild, child, catalog);
            if (result?.kind === "client" || result?.kind === "resource" || result?.kind === "session") {
              scope.set(name, { kind: "factory", result });
            }
          }
        }
        if (name && !helper) {
          const wrapper = wrapperFor(node, scope);
          if (wrapper) scope.set(name, { kind: "process-wrapper", wrapper });
        }
        if (name === "__init__") {
          for (const [key, value] of child) {
            if (key.startsWith("self.") && (value.kind === "client" || value.kind === "resource")) scope.set(key, value);
          }
        }
        return;
      }
      if (branches.has(node.type)) {
        const branches: Scope[] = [];
        if (node.type === "if_statement") {
          for (const item of node.namedChildren) {
            if (!["block", "elif_clause", "else_clause"].includes(item.type)) {
              visit(item, scope);
              continue;
            }
            const branch = new Map(scope);
            visit(item, branch);
            branches.push(branch);
          }
        } else {
          const branch = new Map(scope);
          for (const item of node.namedChildren) visit(item, branch);
          branches.push(branch);
        }
        const changed = new Set<string>();
        for (const branch of branches) {
          for (const [key, value] of branch) if (scope.get(key) !== value) changed.add(key);
        }
        for (const key of changed) {
          const candidates = [scope.get(key), ...branches.map((branch) => branch.get(key))];
          scope.set(key, candidates.some((value) => value?.kind === "client" || value?.kind === "resource")
            ? { kind: "client" } : unknown("control-flow merge"));
        }
        return;
      }
      if (node.type === "call") inspectCall(node, scope);
      if (node.type === "attribute" && field(node, "attribute")?.text === "method_to_api_mapping") {
        const meta = field(node, "object");
        if (field(meta, "attribute")?.text === "meta") {
          const receiver = resolve(field(meta, "object"), scope, catalog);
          if (receiver?.kind === "client") emit(node, "method_to_api_mapping", unknownAws("method name is dynamic"), receiver);
        }
      }
      for (const child of node.namedChildren) visit(child, scope);
      if (node.type === "assignment" || node.type === "augmented_assignment") {
        const left = field(node, "left");
        if (left?.type !== "identifier" && left?.type !== "attribute") return;
        const right = field(node, "right");
        const value = node.type === "assignment" ? literal(right, scope) : undefined;
        const resolved = node.type === "assignment" ? resolve(right, scope, catalog) : undefined;
        const past = scope.get(left.text);
        scope.set(left.text, value !== undefined ? { kind: "literal", value } :
          resolved ?? (past?.kind === "client" ? { kind: "client" } : unknown("unresolved assignment")));
      }
    }

    visit(root, moduleScope);
    // Analyze deferred helpers only after their direct call sites are known.
    for (const candidate of helperCandidates.values()) {
      if (!candidate.invalid && candidate.callArguments.length === candidate.directCalls &&
          candidate.directCalls > 0) {
        const inferred = new Map<string, Binding>();
        for (const parameter of candidate.parameters) {
          const bindings = candidate.callArguments.map((args) => args?.get(parameter));
          const first = bindings[0];
          if (!first || first.kind !== "client" || !first.service ||
              !bindings.every((binding) => binding?.kind === "client" &&
                binding.service === first.service &&
                JSON.stringify(binding.context ?? {}) === JSON.stringify(first.context ?? {}))) continue;
          inferred.set(parameter, first);
        }
        if (inferred.size && candidate.definitionScope) {
          collectingHelperCalls = false;
          visit(candidate.node, new Map(candidate.definitionScope), inferred, true);
          collectingHelperCalls = true;
          continue;
        }
      }
      findings.push(...(candidate.originalFindings ?? []));
    }
    findings.push(...(await Promise.all(processFindings.values())).filter((finding) => finding !== undefined));
    findings.sort((a, b) => a.line - b.line || a.column - b.column);
    return findings;
  });
}
