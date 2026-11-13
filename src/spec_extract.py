"""Extract a Python public-API spec, or replay its examples.

The spec records signatures, docstrings, exported names, and literal
input/output examples. It does not record function bodies.
"""

import ast
import importlib
import json
import sys

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "node_modules",
    "dist",
    "build",
    ".eggs",
}
SKIP_FILES = {"setup.py", "conftest.py", "conf.py"}


def call_name(node):
    parts = []
    cur = node.func if isinstance(node, ast.Call) else node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def literal_repr(node):
    if node is None:
        return None
    try:
        value = ast.literal_eval(node)
    except (ValueError, SyntaxError, MemoryError, TypeError):
        return None
    return repr(value)


def is_test_path(path, root):
    try:
        rel = path.relative_to(root)
    except ValueError:
        return True
    if set(rel.parts) & {"tests", "test"}:
        return True
    name = path.name
    return name.startswith("test_") or name.endswith("_test.py")


def iter_py(root):
    import os
    from pathlib import Path

    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS and not name.startswith(".")]
        for name in filenames:
            if name.endswith(".py"):
                yield Path(dirpath) / name


def signature_of(node):
    rendered = f"{node.name}({ast.unparse(node.args)})"
    if node.returns is not None:
        rendered += " -> " + ast.unparse(node.returns)
    if "\n" in rendered or ";" in rendered:
        return None
    return rendered


def simple_params(node):
    args = node.args
    if args.vararg or args.kwarg or args.kwonlyargs:
        return None
    return [item.arg for item in args.posonlyargs + args.args]


def exported_all(tree):
    for node in tree.body:
        targets = []
        value = None
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets = [node.target]
            value = node.value
        for target in targets:
            if isinstance(target, ast.Name) and target.id == "__all__" and value is not None:
                try:
                    names = ast.literal_eval(value)
                except (ValueError, SyntaxError, MemoryError, TypeError):
                    return None
                if isinstance(names, (list, tuple)) and all(isinstance(item, str) for item in names):
                    return list(names)
    return None


def public_name(name, allow):
    if allow is not None:
        return name in allow
    if name.startswith("_"):
        return False
    return True


def function_record(node, allow):
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    if node.name != "__init__" and not public_name(node.name, allow):
        return None
    sig = signature_of(node)
    if sig is None:
        return None
    params = simple_params(node)
    return {
        "name": node.name,
        "signature": sig,
        "params": params or [],
        "lookup": params is not None,
        "doc": ast.get_docstring(node),
        "examples": [],
    }


def module_api(path, module_name):
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError, UnicodeError):
        return None
    allow = exported_all(tree)
    functions = []
    classes = []
    exports = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            rec = function_record(node, allow)
            if rec is not None and rec["name"] != "__init__":
                functions.append(rec)
                exports.append(rec["name"])
        elif isinstance(node, ast.ClassDef) and public_name(node.name, allow):
            methods = []
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    method = function_record(item, None)
                    if method is not None:
                        methods.append(method)
            classes.append(
                {
                    "name": node.name,
                    "doc": ast.get_docstring(node),
                    "methods": methods,
                }
            )
            exports.append(node.name)
    if allow is not None:
        exports = list(allow)
    return {
        "name": module_name,
        "exports": exports,
        "functions": functions,
        "classes": classes,
    }


def doctest_examples(doc, func_name):
    if not doc:
        return []
    lines = doc.splitlines()
    found = []
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped.startswith(">>>"):
            index += 1
            continue
        expr = stripped[3:].strip()
        index += 1
        while index < len(lines) and lines[index].strip().startswith("..."):
            expr += " " + lines[index].strip()[3:].strip()
            index += 1
        if index >= len(lines):
            break
        result = lines[index].strip()
        if not result or result.startswith(">>>"):
            continue
        example = example_from_expr(expr, result, func_name)
        if example is not None:
            found.append(example)
    return found


def example_from_expr(expr, result, func_name):
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError:
        return None
    if not isinstance(tree.body, ast.Call):
        return None
    name = call_name(tree.body)
    if name is None or name.split(".")[-1] != func_name:
        return None
    args = []
    for arg in tree.body.args:
        rendered = literal_repr(arg)
        if rendered is None:
            return None
        args.append(rendered)
    if tree.body.keywords:
        return None
    try:
        expected = repr(ast.literal_eval(result))
    except (ValueError, SyntaxError, MemoryError, TypeError):
        return None
    return {"args": args, "kwargs": {}, "expected": expected}


def param_names(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [part.strip() for part in node.value.split(",") if part.strip()]
    if isinstance(node, (ast.List, ast.Tuple)):
        names = []
        for elt in node.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                names.append(elt.value)
            else:
                return None
        return names
    return None


def row_values(node, count):
    if isinstance(node, ast.Call):
        name = call_name(node) or ""
        if name == "pytest.param" or name.endswith(".param") or name == "param":
            node = ast.Tuple(elts=list(node.args), ctx=ast.Load())
        else:
            return None
    if count == 1 and not isinstance(node, (ast.List, ast.Tuple)):
        rendered = literal_repr(node)
        return [rendered] if rendered is not None else None
    if isinstance(node, (ast.List, ast.Tuple)):
        values = [literal_repr(elt) for elt in node.elts]
        if len(values) < count or any(item is None for item in values[:count]):
            return None
        return values[:count]
    return None


def parametrize(fn):
    marks = []
    for dec in fn.decorator_list:
        if isinstance(dec, ast.Call):
            name = call_name(dec) or ""
            if name.endswith("parametrize"):
                marks.append(dec)
    # shortcut: stacked pytest.mark.parametrize is ignored. Upgrade when a library multiplies cases that way.
    if len(marks) != 1 or len(marks[0].args) < 2:
        return None
    names = param_names(marks[0].args[0])
    rows_node = marks[0].args[1]
    if not names or not isinstance(rows_node, (ast.List, ast.Tuple)):
        return None
    rows = []
    for elt in rows_node.elts:
        values = row_values(elt, len(names))
        if values is None:
            return None
        rows.append(dict(zip(names, values)))
    return rows


def call_example(call, expected_repr, bindings):
    name = call_name(call)
    if name is None:
        return None
    last = name.split(".")[-1]
    if last.startswith("assert") or name.startswith("self.assert"):
        return None
    args = []
    for arg in call.args:
        if isinstance(arg, ast.Name) and bindings and arg.id in bindings:
            args.append(bindings[arg.id])
        else:
            rendered = literal_repr(arg)
            if rendered is None:
                return None
            args.append(rendered)
    kwargs = {}
    for kw in call.keywords:
        if kw.arg is None:
            return None
        if isinstance(kw.value, ast.Name) and bindings and kw.value.id in bindings:
            kwargs[kw.arg] = bindings[kw.value.id]
        else:
            rendered = literal_repr(kw.value)
            if rendered is None:
                return None
            kwargs[kw.arg] = rendered
    return {"func": last, "qual": name, "args": args, "kwargs": kwargs, "expected": expected_repr}


def expected_repr(node, bindings):
    if isinstance(node, ast.Name) and bindings and node.id in bindings:
        return bindings[node.id]
    return literal_repr(node)


def pairs_from_assert(node, bindings):
    test = node.test
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or not isinstance(test.ops[0], ast.Eq):
        return []
    if len(test.comparators) != 1:
        return []
    return pair_nodes(test.left, test.comparators[0], bindings)


def pair_nodes(left, right, bindings):
    if isinstance(left, ast.Call):
        expected = expected_repr(right, bindings)
        if expected is None:
            return []
        example = call_example(left, expected, bindings)
        return [example] if example else []
    if isinstance(right, ast.Call):
        expected = expected_repr(left, bindings)
        if expected is None:
            return []
        example = call_example(right, expected, bindings)
        return [example] if example else []
    return []


def pairs_from_call(call, bindings):
    name = call_name(call) or ""
    if name not in {
        "self.assertEqual",
        "self.assertEquals",
        "self.assertIs",
        "assertEqual",
        "assertEquals",
    }:
        return []
    if len(call.args) < 2:
        return []
    return pair_nodes(call.args[0], call.args[1], bindings)


def examples_in_function(fn):
    rows = parametrize(fn)
    bindings_list = rows if rows is not None else [None]
    found = []

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node):
            if node is fn:
                self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node):
            if node is fn:
                self.generic_visit(node)

        def visit_Assert(self, node):
            for bindings in bindings_list:
                found.extend(item for item in pairs_from_assert(node, bindings) if item)
            self.generic_visit(node)

        def visit_Expr(self, node):
            if isinstance(node.value, ast.Call):
                for bindings in bindings_list:
                    found.extend(item for item in pairs_from_call(node.value, bindings) if item)
            self.generic_visit(node)

    Visitor().visit(fn)
    return found


def collect_test_examples(root):
    from pathlib import Path

    examples = []
    root = Path(root)
    for path in iter_py(root):
        if not is_test_path(path, root):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError, UnicodeError):
            continue
        nodes = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
                nodes.append(node)
            elif isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.startswith("test"):
                        nodes.append(item)
        for node in nodes:
            examples.extend(examples_in_function(node))
    return examples


def attach_examples(modules, examples):
    index = []
    for module in modules:
        for fn in module["functions"]:
            index.append((module, fn))
    for example in examples:
        matches = []
        for module, fn in index:
            if fn["name"] != example["func"]:
                continue
            qual = example["qual"]
            prefix = qual[: -len(example["func"])].rstrip(".")
            if not prefix or module["name"] == prefix or module["name"].endswith("." + prefix) or prefix.endswith(module["name"]):
                matches.append(fn)
        # shortcut: an unqualified name is kept only when one function has it. Upgrade when imports can be resolved.
        if len(matches) == 1:
            matches[0]["examples"].append(
                {
                    "args": example["args"],
                    "kwargs": example["kwargs"],
                    "expected": example["expected"],
                }
            )


def discover_modules(root):
    from pathlib import Path

    root = Path(root).resolve()
    modules = []
    seen = set()

    def add_file(path, module_name):
        key = str(path.resolve())
        if key in seen or path.name in SKIP_FILES or is_test_path(path, root):
            return
        seen.add(key)
        record = module_api(path, module_name)
        if record is not None and (record["functions"] or record["classes"] or record["exports"]):
            modules.append(record)

    def add_package(pkg_dir):
        pkg_name = pkg_dir.name
        for path in iter_py(pkg_dir):
            if is_test_path(path, root) or path.name in SKIP_FILES:
                continue
            rel = path.relative_to(pkg_dir).with_suffix("")
            parts = list(rel.parts)
            if parts[-1] == "__init__":
                parts = parts[:-1]
            module_name = ".".join([pkg_name, *parts]) if parts else pkg_name
            add_file(path, module_name)

    src = root / "src"
    if src.is_dir():
        for child in sorted(src.iterdir()):
            if child.is_dir() and (child / "__init__.py").is_file() and child.name not in SKIP_DIRS:
                add_package(child)
        for path in sorted(src.glob("*.py")):
            add_file(path, path.stem)
    if (root / "__init__.py").is_file():
        add_package(root)
    for child in sorted(root.iterdir()):
        if not child.is_dir() or child.name in SKIP_DIRS or child.name in {"src", "tests", "test"}:
            continue
        if (child / "__init__.py").is_file():
            add_package(child)
    # shortcut: every non-test .py file is a module, including repo tools such as noxfile.py. Upgrade when the package list comes from pyproject.
    for path in sorted(root.glob("*.py")):
        add_file(path, path.stem)
    return modules


def extract(root):
    from pathlib import Path

    root = Path(root).resolve()
    modules = discover_modules(root)
    for module in modules:
        for fn in module["functions"]:
            fn["examples"].extend(doctest_examples(fn["doc"], fn["name"]))
    attach_examples(modules, collect_test_examples(root))
    for module in modules:
        for fn in module["functions"]:
            dedup = []
            seen = set()
            for example in fn["examples"]:
                key = json.dumps(example, sort_keys=True)
                if key not in seen:
                    seen.add(key)
                    dedup.append(example)
            fn["examples"] = dedup
    return {
        "language": "python",
        "origin_name": root.name,
        "origin": str(root),
        "modules": modules,
    }


def example_selected(example, which):
    held = bool(example.get("held_out"))
    if which == "all":
        return True
    return held


def record(results, module, func, example, ok, error):
    results.append(
        {
            "module": module,
            "func": func,
            "ok": ok,
            "held_out": bool(example.get("held_out")),
            "error": error,
        }
    )


def check(rebuild, spec_path, which):
    sys.path.insert(0, rebuild)
    with open(spec_path, encoding="utf-8") as handle:
        spec = json.load(handle)
    results = []
    for module in spec.get("modules", []):
        try:
            imported = importlib.import_module(module["name"])
            import_error = None
        except Exception as exc:  # noqa: BLE001 — report any import failure as an example failure
            imported = None
            import_error = f"{type(exc).__name__}: {exc}"
        for fn in module.get("functions", []):
            target = None if imported is None else getattr(imported, fn["name"], None)
            for example in fn.get("examples", []):
                if not example_selected(example, which):
                    continue
                if import_error is not None:
                    record(results, module["name"], fn["name"], example, False, import_error)
                    continue
                if target is None:
                    record(
                        results,
                        module["name"],
                        fn["name"],
                        example,
                        False,
                        "function is not exported",
                    )
                    continue
                try:
                    args = [ast.literal_eval(item) for item in example.get("args", [])]
                    kwargs = {key: ast.literal_eval(value) for key, value in example.get("kwargs", {}).items()}
                    got = target(*args, **kwargs)
                    expected = ast.literal_eval(example["expected"])
                    ok = got == expected
                    record(
                        results,
                        module["name"],
                        fn["name"],
                        example,
                        ok,
                        None if ok else f"{got!r} != {expected!r}",
                    )
                except Exception as exc:  # noqa: BLE001
                    record(
                        results,
                        module["name"],
                        fn["name"],
                        example,
                        False,
                        f"{type(exc).__name__}: {exc}",
                    )
    json.dump({"results": results}, sys.stdout)
    sys.stdout.write("\n")


def literals():
    payload = json.load(sys.stdin)
    for item in payload:
        ast.literal_eval(item)
    json.dump({"ok": True}, sys.stdout)


def main():
    if len(sys.argv) < 2:
        print("usage: spec_extract.py extract|check|literals ...", file=sys.stderr)
        return 2
    mode = sys.argv[1]
    if mode == "extract":
        if len(sys.argv) != 3:
            print("usage: spec_extract.py extract <dir>", file=sys.stderr)
            return 2
        spec = extract(sys.argv[2])
        if not spec["modules"]:
            print("spec extraction supports Python libraries only", file=sys.stderr)
            return 1
        json.dump(spec, sys.stdout)
        sys.stdout.write("\n")
        return 0
    if mode == "check":
        if len(sys.argv) not in (4, 5):
            print("usage: spec_extract.py check <rebuild> <spec> [held-out|all]", file=sys.stderr)
            return 2
        which = sys.argv[4] if len(sys.argv) == 5 else "held-out"
        check(sys.argv[2], sys.argv[3], which)
        return 0
    if mode == "literals":
        literals()
        return 0
    print(f"unknown mode {mode}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
