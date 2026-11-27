import type { Node } from "web-tree-sitter";

export interface Parameter {
  name: string;
  kind: "plain" | "rest" | "keywords";
  optional: boolean;
  /** The declared default is None, so an omitted argument makes the parameter None. */
  defaultsToNone: boolean;
  keywordOnly: boolean;
}
export interface FunctionInfo {
  node: Node;
  /** Start offset of the definition; stable across analysis rounds over the same tree. */
  key: number;
  name: string;
  parameters: Parameter[];
  /** The class whose body directly contains this function. */
  owner?: Node;
  /** Defined directly in the module body. */
  topLevel: boolean;
  decorators: ReadonlySet<string>;
  /** Top-level, underscore-prefixed and not exported: every caller is visible in this file. */
  private: boolean;
  /** Referenced other than by a direct call, so some callers cannot be seen. */
  escapes: boolean;
  /** A one-statement function that forwards its only parameter; reported at its call sites instead. */
  forwarder: boolean;
}
export interface Definitions {
  functions: ReadonlyMap<number, FunctionInfo>;
  methods: ReadonlyMap<number, ReadonlyMap<string, FunctionInfo>>;
  methodsByName: ReadonlyMap<string, readonly FunctionInfo[]>;
  /** Top-level classes by name, for module summaries. */
  classes: ReadonlyMap<string, Node>;
}

const field = (node: Node | null, name: string) => node?.childForFieldName(name) ?? null;
const identifier = (node: Node | null) => node?.type === "identifier" ? node.text : undefined;
const simpleString = (node: Node) => /^(["'])([^"'\\\r\n]*)\1$/.exec(node.text)?.[2];
const propertyDecorators = new Set(["property", "cached_property"]);

function parseParameters(definition: Node): Parameter[] {
  const parameters: Parameter[] = [];
  let keywordOnly = false;
  for (const node of field(definition, "parameters")?.namedChildren ?? []) {
    if (node.type === "keyword_separator") {
      keywordOnly = true;
      continue;
    }
    const inner = node.type === "typed_parameter" ? node.firstNamedChild : node;
    if (inner?.type === "list_splat_pattern" || inner?.type === "dictionary_splat_pattern") {
      const name = identifier(inner.firstNamedChild);
      const rest = inner.type === "list_splat_pattern";
      if (name) {
        parameters.push({ name, kind: rest ? "rest" : "keywords", optional: true, defaultsToNone: false, keywordOnly: false });
      }
      if (rest) keywordOnly = true;
      continue;
    }
    const name = identifier(inner) ?? identifier(field(node, "name"));
    if (!name) continue;
    const optional = node.type === "default_parameter" || node.type === "typed_default_parameter";
    const defaultsToNone = optional && field(node, "value")?.type === "none";
    parameters.push({ name, kind: "plain", optional, defaultsToNone, keywordOnly });
  }
  return parameters;
}

function decoratorNames(definition: Node): Set<string> {
  const names = new Set<string>();
  if (definition.parent?.type !== "decorated_definition") return names;
  for (const decorator of definition.parent.namedChildren) {
    if (decorator.type !== "decorator") continue;
    const expression = decorator.firstNamedChild;
    const target = expression?.type === "call" ? field(expression, "function") : expression;
    const name = target?.type === "attribute" ? field(target, "attribute")?.text : target?.text;
    if (name) names.add(propertyDecorators.has(name) ? "property" : name);
  }
  return names;
}

/** The class or function body that directly holds a definition, looking through decorators. */
function container(definition: Node): Node | null {
  const holder = definition.parent?.type === "decorated_definition" ? definition.parent.parent : definition.parent;
  return holder?.type === "block" ? holder.parent : holder ?? null;
}

function isForwarder(definition: Node, parameters: Parameter[]): boolean {
  const declared = field(definition, "parameters")?.namedChildren ?? [];
  if (parameters.length !== 1 || declared.length !== 1 || declared[0].type !== "identifier") return false;
  const statements = field(definition, "body")?.namedChildren.filter((entry) => entry.type !== "comment") ?? [];
  const call = statements.length === 1 && statements[0].type === "expression_statement"
    ? statements[0].firstNamedChild : null;
  const target = call?.type === "call" ? field(call, "function") : null;
  return identifier(field(target, "object")) === parameters[0].name && Boolean(identifier(field(target, "attribute")));
}

function moduleExports(root: Node) {
  const exported = new Set<string>();
  let dynamic = false;
  function walk(node: Node) {
    if ((node.type === "assignment" || node.type === "augmented_assignment") &&
        identifier(field(node, "left")) === "__all__") {
      const value = field(node, "right");
      const topLevel = node.parent?.type === "expression_statement" && node.parent.parent?.type === "module";
      const literalList = node.type === "assignment" && value && ["list", "tuple"].includes(value.type) &&
        value.namedChildren.every((item) => item.type === "string" && simpleString(item) !== undefined);
      if (!topLevel || !literalList) dynamic = true;
      else for (const item of value.namedChildren) exported.add(simpleString(item) ?? "");
    }
    for (const child of node.namedChildren) walk(child);
  }
  walk(root);
  return { exported, dynamic };
}

/** The arguments written at a call, or undefined when they are not a plain argument list. */
export function callArguments(call: Node): Node[] | undefined {
  const list = field(call, "arguments");
  return list?.type === "argument_list" ? list.namedChildren.filter((entry) => entry.type !== "comment") : undefined;
}

const deferredPositions = new Map([["submit", 0], ["to_thread", 0], ["run_in_executor", 1]]);
const deferredConstructors = new Set(["Thread", "Process"]);

/**
 * Standard-library calls that run a callable they are handed: `executor.submit(f, a)`,
 * `asyncio.to_thread(f, a)`, `loop.run_in_executor(pool, f, a)` and `Thread(target=f, args=(a,))`.
 * Returns the callable and the arguments it will receive; `args` is undefined when they are dynamic.
 */
export function deferredCall(call: Node): { target: Node; args: Node[] | undefined } | undefined {
  const fn = field(call, "function");
  const name = fn?.type === "attribute" ? field(fn, "attribute")?.text : identifier(fn);
  const written = callArguments(call);
  if (!name || !written) return undefined;
  const position = deferredPositions.get(name);
  if (position !== undefined) {
    const leading = written.slice(0, position + 1);
    const plain = leading.every((argument) => argument.type !== "keyword_argument" && !argument.type.endsWith("_splat"));
    return leading.length > position && plain ? { target: leading[position], args: written.slice(position + 1) } : undefined;
  }
  if (!deferredConstructors.has(name)) return undefined;
  const keyword = (key: string) => field(written.find((argument) =>
    argument.type === "keyword_argument" && field(argument, "name")?.text === key) ?? null, "value");
  const target = keyword("target");
  if (!target) return undefined;
  const positional = keyword("args");
  if (keyword("kwargs")) return { target, args: undefined };
  if (!positional) return { target, args: [] };
  const literal = positional.type === "tuple" || positional.type === "list";
  return { target, args: literal ? positional.namedChildren.filter((entry) => entry.type !== "comment") : undefined };
}

const isDeferredTarget = (node: Node) => {
  const holder = node.parent?.type === "keyword_argument" ? node.parent.parent : node.parent;
  const call = holder?.type === "argument_list" ? holder.parent : null;
  return call?.type === "call" && deferredCall(call)?.target.id === node.id;
};

function insideAnnotation(node: Node): boolean {
  let current = node.parent;
  for (let depth = 0; current && depth < 6; depth++) {
    if (current.type === "type") return true;
    if (current.type.endsWith("_statement") || current.type === "block") return false;
    current = current.parent;
  }
  return false;
}

export function indexDefinitions(root: Node): Definitions {
  const functions = new Map<number, FunctionInfo>();
  const methods = new Map<number, Map<string, FunctionInfo>>();
  const methodsByName = new Map<string, FunctionInfo[]>();
  const byName = new Map<string, FunctionInfo[]>();
  const constructors = new Map<string, FunctionInfo[]>();
  const classes = new Map<string, Node>();
  const exports = moduleExports(root);

  function collect(node: Node) {
    if (node.type === "class_definition" && container(node)?.type === "module") {
      const name = identifier(field(node, "name"));
      if (name) classes.set(name, node);
    }
    if (node.type === "function_definition") {
      const name = identifier(field(node, "name"));
      const holder = container(node);
      if (name) {
        const parameters = parseParameters(node);
        const owner = holder?.type === "class_definition" ? holder : undefined;
        const topLevel = holder?.type === "module";
        const info: FunctionInfo = {
          node, key: node.startIndex, name, parameters, owner, topLevel, decorators: decoratorNames(node),
          private: topLevel && /^_(?!_)/.test(name) && !exports.dynamic && !exports.exported.has(name),
          escapes: false, forwarder: topLevel && isForwarder(node, parameters),
        };
        functions.set(info.key, info);
        if (owner) {
          let members = methods.get(owner.startIndex);
          if (!members) methods.set(owner.startIndex, members = new Map());
          members.set(name, info);
          methodsByName.set(name, [...(methodsByName.get(name) ?? []), info]);
          const className = identifier(field(owner, "name"));
          if (name === "__init__" && className) {
            constructors.set(className, [...(constructors.get(className) ?? []), info]);
          }
        } else byName.set(name, [...(byName.get(name) ?? []), info]);
      }
    }
    for (const child of node.namedChildren) collect(child);
  }
  collect(root);

  const escape = (infos: readonly FunctionInfo[] | undefined) => {
    for (const info of infos ?? []) info.escapes = true;
  };
  for (const infos of byName.values()) if (infos.length > 1) escape(infos);
  for (const infos of constructors.values()) if (infos.length > 1) escape(infos);

  function findEscapes(node: Node) {
    const parent = node.parent;
    if (node.type === "identifier" && (byName.has(node.text) || constructors.has(node.text))) {
      const isDefinitionName = (parent?.type === "function_definition" || parent?.type === "class_definition") &&
        field(parent, "name")?.startIndex === node.startIndex;
      const isCallee = parent?.type === "call" && field(parent, "function")?.startIndex === node.startIndex;
      const isMemberName = parent?.type === "attribute" && field(parent, "attribute")?.startIndex === node.startIndex;
      const isKeywordName = parent?.type === "keyword_argument" && field(parent, "name")?.startIndex === node.startIndex;
      if (!isDefinitionName && !isCallee && !isMemberName && !isKeywordName && !isDeferredTarget(node) &&
          !insideAnnotation(node)) {
        escape(byName.get(node.text));
        escape(constructors.get(node.text));
      }
    }
    if (node.type === "attribute") {
      const member = field(node, "attribute")?.text;
      const isCallee = parent?.type === "call" && field(parent, "function")?.startIndex === node.startIndex;
      if (member && !isCallee && !isDeferredTarget(node)) escape(methodsByName.get(member));
    }
    if (node.type === "string") {
      const text = simpleString(node);
      if (text) {
        escape(byName.get(text));
        escape(methodsByName.get(text));
      }
    }
    for (const child of node.namedChildren) findEscapes(child);
  }
  findEscapes(root);
  return { functions, methods, methodsByName, classes };
}

/**
 * Pairs the arguments a callee receives with its named parameters. `bound` drops the implicit receiver.
 * A null value means the parameter fell back to its default. Returns undefined when the call
 * cannot be mapped (unpacking, unknown keywords, missing or surplus arguments).
 */
export function mapArguments(
  written: readonly Node[] | undefined, declared: readonly Parameter[], bound: boolean,
): Map<string, Node | null> | undefined {
  if (!written || (bound && declared[0]?.kind !== "plain")) return undefined;
  const parameters = bound ? declared.slice(1) : declared;
  const plain = parameters.filter((parameter) => parameter.kind === "plain");
  const positional = plain.filter((parameter) => !parameter.keywordOnly);
  const acceptsRest = parameters.some((parameter) => parameter.kind === "rest");
  const acceptsKeywords = parameters.some((parameter) => parameter.kind === "keywords");
  const assigned = new Map<string, Node | null>();
  let position = 0;
  for (const argument of written) {
    if (argument.type === "list_splat" || argument.type === "dictionary_splat") return undefined;
    if (argument.type === "keyword_argument") {
      const name = field(argument, "name")?.text;
      const target = plain.find((parameter) => parameter.name === name);
      if (!name || assigned.has(name)) return undefined;
      if (target) assigned.set(name, field(argument, "value"));
      else if (!acceptsKeywords) return undefined;
      continue;
    }
    const target = positional[position++];
    if (target) assigned.set(target.name, argument);
    else if (!acceptsRest) return undefined;
  }
  for (const parameter of plain) {
    if (assigned.has(parameter.name)) continue;
    if (!parameter.optional) return undefined;
    assigned.set(parameter.name, null);
  }
  return assigned;
}
