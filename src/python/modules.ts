import type { Node } from "web-tree-sitter";
import { field, isHandle, trackedModule } from "./bindings.ts";
import type { Binding } from "./bindings.ts";

export interface LoadedModule {
  /** Identity of the module file, used to cache summaries and stop import cycles. */
  key: string;
  source: string;
  /** The module is a package (`__init__.py`), so names imported from it may be submodules. */
  package: boolean;
  /** Resolves the imports written inside this module. */
  loader: ModuleLoader;
}
/** Finds a project module by the name written in an import, leading dots included. */
export type ModuleLoader = (name: string) => Promise<LoadedModule | undefined>;
export interface ImportRequest {
  module: string;
  /** Names imported from the module; each may be a submodule when the module is a package. */
  names: string[];
}

const moduleName = /^(?:\.+|\.*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)$/;
const maxImportRequests = 64;

export const submoduleName = (module: string, name: string) => `${module}${module.endsWith(".") ? "" : "."}${name}`;

/** Lists the modules a file imports that might be project files, skipping the ones tracked natively. */
export function importRequests(root: Node): ImportRequest[] {
  const requests = new Map<string, Set<string>>();
  const add = (module: string, name?: string) => {
    if (!moduleName.test(module) || trackedModule.test(module)) return;
    let names = requests.get(module);
    if (!names) requests.set(module, names = new Set());
    if (name && /^[A-Za-z_]\w*$/.test(name)) names.add(name);
  };
  function walk(node: Node) {
    if (node.type === "import_statement") {
      for (const name of node.childrenForFieldName("name")) add((field(name, "name") ?? name).text);
    }
    if (node.type === "import_from_statement") {
      const module = field(node, "module_name")?.text;
      if (module) {
        add(module);
        for (const name of node.childrenForFieldName("name")) add(module, (field(name, "name") ?? name).text);
      }
    }
    for (const child of node.namedChildren) walk(child);
  }
  walk(root);
  return [...requests].slice(0, maxImportRequests).map(([module, names]) => ({ module, names: [...names] }));
}

/** Keeps the parts of a binding that stay valid after the defining module's syntax tree is freed. */
export function portable(binding: Binding | undefined): Binding | undefined {
  if (!binding) return undefined;
  if (isHandle(binding) || binding.kind === "literal") return binding;
  if (binding.kind === "tuple") {
    const items = binding.items.map(portable);
    return items.some(Boolean) ? { kind: "tuple", items } : undefined;
  }
  return undefined;
}
