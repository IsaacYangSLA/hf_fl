"""Check job-control boundaries and a clean installed manager wheel.

The manager never loads training code. Only the sandbox runtime entry point
may import HF2L or model frameworks, and those imports must be function-local.
Use installation modes in a fresh environment, independently of HF2L.
"""
from __future__ import annotations

import argparse
import ast
import importlib
import importlib.metadata
import importlib.resources
import importlib.util
from html.parser import HTMLParser
import pkgutil
import re
from pathlib import Path
import sys


ML_MODULES = frozenset({"hf2l", "torch", "numpy", "safetensors", "huggingface_hub"})
ML_DISTRIBUTIONS = frozenset({"hf2l", "torch", "numpy", "safetensors", "huggingface-hub"})
SANDBOX_ENTRY_POINTS = frozenset({"runtime.py"})
DOMAIN_FORBIDDEN = frozenset({"fastapi", "sqlalchemy", "uvicorn", "psycopg", "hf2l_exchange"})
PACKAGE = "hf2l_jobs"


class ImportVisitor(ast.NodeVisitor):
    """Retain execution depth, including ordinary function-local imports."""

    def __init__(self, package=PACKAGE):
        self.package = package
        self.depth = 0
        self.imports = []
        self.dynamic_calls = []
        self.dynamic_aliases = {}

    def visit_Import(self, node):
        self.imports.extend((node.lineno, alias.name, self.depth == 0) for alias in node.names)

    def visit_ImportFrom(self, node):
        if not node.level and node.module in {"importlib", "builtins"}:
            for alias in node.names:
                if alias.name in {"import_module", "__import__", "exec", "eval"}:
                    self.dynamic_aliases[alias.asname or alias.name] = alias.name
        if not node.level and node.module == self.package:
            for alias in node.names:
                self.imports.append((node.lineno, f"{self.package}.{alias.name}", self.depth == 0))
            return
        if node.level:
            target = f"{self.package}.{node.module or ''}".rstrip(".")
            if not node.module:
                for alias in node.names:
                    self.imports.append((node.lineno, f"{self.package}.{alias.name}", self.depth == 0))
                return
        else:
            target = node.module or ""
        self.imports.append((node.lineno, target, self.depth == 0))

    def dynamic_name(self, value):
        if isinstance(value, ast.Name):
            return self.dynamic_aliases.get(value.id, value.id)
        if isinstance(value, ast.Attribute):
            return value.attr
        return ""

    def bind_dynamic_alias(self, target, value):
        name = self.dynamic_name(value)
        if isinstance(target, ast.Name) and name in {"import_module", "__import__", "exec", "eval"}:
            self.dynamic_aliases[target.id] = name
        elif isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List)):
            for item, expression in zip(target.elts, value.elts):
                self.bind_dynamic_alias(item, expression)

    def visit_Assign(self, node):
        for target in node.targets:
            self.bind_dynamic_alias(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.bind_dynamic_alias(node.target, node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node):
        self.bind_dynamic_alias(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = self.dynamic_name(node.func)
        if name in {"import_module", "__import__", "exec", "eval"}:
            self.dynamic_calls.append((node.lineno, name, self.depth == 0))
        if name in {"import_module", "__import__"} and node.args:
            value = node.args[0]
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                self.imports.append((node.lineno, value.value, self.depth == 0))
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        # Decorators and default values execute when a module is imported.
        arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        arguments += [argument for argument in (node.args.vararg, node.args.kwarg) if argument is not None]
        annotations = [argument.annotation for argument in arguments] + [node.returns]
        for child in [*node.decorator_list, *node.args.defaults, *node.args.kw_defaults, *annotations]:
            if child is not None:
                self.visit(child)
        self.depth += 1
        for child in node.body:
            self.visit(child)
        self.depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef


def source_problems(relative: Path, source: str) -> list[str]:
    visitor = ImportVisitor()
    visitor.visit(ast.parse(source, filename=str(relative)))
    runtime = relative.as_posix() in SANDBOX_ENTRY_POINTS
    domain = relative.as_posix() == "domain.py"
    problems = []
    for line, imported, eager in visitor.imports:
        top = imported.split(".", 1)[0]
        if top in ML_MODULES and (not runtime or eager):
            problems.append(f"{relative}:{line}: prohibited {'eager ' if eager else ''}training import {imported}")
        if domain and (top in DOMAIN_FORBIDDEN or imported.startswith(f"{PACKAGE}.")):
            problems.append(f"{relative}:{line}: domain imports infrastructure {imported}")
        if not runtime and eager and imported in {f"{PACKAGE}.runtime"}:
            problems.append(f"{relative}:{line}: control plane eagerly imports sandbox runtime")
    for line, call, eager in visitor.dynamic_calls:
        if not runtime or eager:
            problems.append(f"{relative}:{line}: control-plane dynamic code loading is forbidden: {call}")
    return problems


def generic_service_problems(relative: Path, source: str) -> list[str]:
    visitor = ImportVisitor(package="hf2l_exchange")
    visitor.visit(ast.parse(source, filename=str(relative)))
    return [
        f"{relative}:{line}: generic Exchange imports job management {imported}"
        for line, imported, _ in visitor.imports
        if imported.split(".", 1)[0] == PACKAGE
    ]


def check_source(root: Path) -> list[str]:
    source = root / "packages/jobs/src" / PACKAGE
    files = sorted(source.rglob("*.py"))
    if not files:
        return [f"No job manager sources found at {source}"]
    problems = [
        problem for path in files
        for problem in source_problems(path.relative_to(source), path.read_text(encoding="utf-8"))
    ]
    exchange = root / "packages/exchange/src/hf2l_exchange"
    for path in sorted(exchange.rglob("*.py")):
        problems.extend(generic_service_problems(path.relative_to(root), path.read_text(encoding="utf-8")))
    return problems


def check_metadata() -> list[str]:
    distribution = importlib.metadata.distribution("hf2l-jobs")
    problems = []
    for requirement in distribution.requires or []:
        match = re.match(r"[A-Za-z0-9_.-]+", requirement)
        if match and match.group(0).lower().replace("_", "-") in ML_DISTRIBUTIONS:
            problems.append(f"Manager distribution declares a training dependency: {requirement}")
    entries = {entry.name: entry.value for entry in distribution.entry_points if entry.group == "console_scripts"}
    if entries.get("hf2l-jobs") != "hf2l_jobs.cli:main":
        problems.append("hf2l-jobs console entry point is missing or incorrect")
    python_requires = distribution.metadata.get("Requires-Python", "")
    if python_requires.strip() != ">=3.11":
        problems.append(f"Expected Python >=3.11 metadata, got {python_requires!r}")
    return problems


class DashboardAssets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.references = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "script" and values.get("src"):
            self.references.append(values["src"])
        elif tag == "link" and values.get("rel") == "stylesheet" and values.get("href"):
            self.references.append(values["href"])


def check_assets() -> list[str]:
    assets = importlib.resources.files(PACKAGE).joinpath("static")
    index = assets.joinpath("index.html")
    if not index.is_file():
        return ["Manager wheel is missing dashboard static/index.html"]
    problems = []
    text = index.read_text(encoding="utf-8")
    parser = DashboardAssets()
    parser.feed(text)
    references = parser.references
    if not references:
        problems.append("Dashboard does not reference packaged static assets")
    for reference in references:
        reference = reference.removeprefix("/static/").removeprefix("static/")
        if ".." in Path(reference).parts or Path(reference).is_absolute():
            problems.append(f"Unsafe dashboard asset reference {reference}")
        elif not assets.joinpath(reference).is_file():
            problems.append(f"Manager wheel is missing dashboard asset {reference}")
    return problems


def check_installation(mode: str, root: Path) -> list[str]:
    problems = check_metadata() + check_assets()
    for name in sorted(ML_MODULES):
        if importlib.util.find_spec(name) is not None:
            problems.append(f"{mode} environment unexpectedly contains training module {name}")
    package = importlib.import_module(PACKAGE)
    if Path(package.__file__).resolve().is_relative_to(root / "packages/jobs/src"):
        problems.append("Installation check requires a built wheel, not the editable checkout")
    # These imports are the actual control-plane surface; runtime remains a
    # separately selected CLI command and must import without training libraries.
    for module in pkgutil.walk_packages(package.__path__, prefix=PACKAGE + "."):
        if module.name != PACKAGE + ".__main__":
            importlib.import_module(module.name)
    imported_ml = sorted(name for name in ML_MODULES if name in sys.modules)
    if imported_ml:
        problems.append(f"Control-plane imports loaded training modules: {imported_ml}")
    if mode == "server":
        importlib.import_module("uvicorn")
        importlib.import_module("psycopg")
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("source", "manager", "server"), default="source")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    problems = check_source(args.root)
    if args.mode != "source":
        problems.extend(check_installation(args.mode, args.root.resolve()))
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    print(f"Jobs {args.mode} dependency boundaries passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
