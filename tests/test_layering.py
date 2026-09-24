"""V3 architecture gate over both distributions and their installed examples.

The WP0 parser and adversarial tests are retained. All present source modules are
checked, including untracked work. Historical v1 modules have named, bounded
allowlists; they are not silently excluded from architecture verification.
"""

from __future__ import annotations

import ast
import subprocess
import sys
import unittest
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "hf2l"

SOURCE_ROOTS = ("hf2l", "packages/exchange/src/hf2l_exchange", "examples")
INTERNAL_PACKAGES = ("hf2l", "hf2l_exchange", "examples")


def covers(prefix: str, module: str) -> bool:
    """True when `module` is `prefix` itself or a dotted child of it."""
    return module == prefix or module.startswith(prefix + ".")


def internal_name(module: str) -> bool:
    return any(covers(package, module) for package in INTERNAL_PACKAGES)


def in_scope(module: str) -> bool:
    """V3 checks every source module, including retained compatibility modules."""
    return internal_name(module)


STDLIB_ONLY: frozenset[str] = frozenset()
CHECKPOINT_BASE_DEPS: frozenset[str] = frozenset({"numpy", "safetensors"})  # base deps of the distribution


@dataclass(frozen=True)
class Layer:
    """One allowlist row: which hf2l modules and which third-party packages the member modules may import."""

    name: str
    members: tuple[str, ...]
    imports: tuple[str, ...]
    third_party: frozenset[str] | None = None  # None: unrestricted; STDLIB_ONLY: standard library only


ROOT = Layer("root", (PACKAGE,), (), STDLIB_ONLY)  # hf2l/__init__.py: version only

# New seams have narrow dependency directions. Compatibility surfaces are named
# explicitly below so retaining the old CLIs and regression service cannot become
# an escape hatch for new modules. A new top-level module needs an assigned row.
LEGACY_EXCHANGE_MODULES = frozenset({
    "hf2l.exchange", "hf2l.exchange.api", "hf2l.exchange.auth",
    "hf2l.exchange.cli", "hf2l.exchange.client", "hf2l.exchange.config",
    "hf2l.exchange.leases", "hf2l.exchange.migrations", "hf2l.exchange.models",
    "hf2l.exchange.protocol", "hf2l.exchange.schemas", "hf2l.exchange.storage",
    "hf2l.exchange.worker",
})
LEGACY_COMMANDS = (
    "hf2l.owner_fedavg", "hf2l.init_repo", "hf2l.client_download",
    "hf2l.client_upload", "hf2l.client_train", "hf2l.create_allowlist",
)
SDK_MODULES = (
    "hf2l_exchange.client", "hf2l_exchange.client_types",
    "hf2l_exchange.client_state", "hf2l_exchange.transfer_client",
)
LAYERS: tuple[Layer, ...] = (
    Layer("common", ("hf2l.common",), ("hf2l.common",), STDLIB_ONLY),
    Layer("core", ("hf2l.core",), ("hf2l.common", "hf2l.core"), STDLIB_ONLY),
    Layer("checkpoint numpy backend", ("hf2l.checkpoint.safetensors_numpy",),
          ("hf2l.common", "hf2l.core.errors", "hf2l.checkpoint"), CHECKPOINT_BASE_DEPS),
    Layer("checkpoint torch backend", ("hf2l.checkpoint.safetensors_torch",),
          ("hf2l.common", "hf2l.core.errors", "hf2l.checkpoint"), CHECKPOINT_BASE_DEPS | {"torch"}),
    Layer("checkpoint.safetensors", ("hf2l.checkpoint.safetensors",),
          ("hf2l.common", "hf2l.core.errors", "hf2l.checkpoint"), STDLIB_ONLY),
    Layer("checkpoint", ("hf2l.checkpoint",),
          ("hf2l.common", "hf2l.core.errors", "hf2l.checkpoint"), CHECKPOINT_BASE_DEPS),
    Layer("checkpoint compatibility facade", ("hf2l.checkpoint_utils",),
          ("hf2l.checkpoint", "hf2l.core.protocol"), STDLIB_ONLY),
    Layer("compatibility helpers", ("hf2l.hub_helpers",),
          ("hf2l.common", "hf2l.core.protocol"), STDLIB_ONLY),
    Layer("backend exchange", ("hf2l.backends.exchange",),
          ("hf2l.common", "hf2l.core", "hf2l.backends.base", "hf2l.hub_helpers") + SDK_MODULES),
    Layer("backends", ("hf2l.backends",),
          ("hf2l.common", "hf2l.core", "hf2l.backends")),
    Layer("round", ("hf2l.round",),
          ("hf2l.common", "hf2l.core", "hf2l.checkpoint", "hf2l.round")),
    Layer("round orchestration", ("hf2l.fedavg_runner",),
          ("hf2l.common", "hf2l.core", "hf2l.round", "hf2l.backends.base",
           "hf2l.checkpoint", "hf2l.checkpoint_utils", "hf2l.hub_helpers",
           "hf2l.allowlist", "hf2l.plugin_loader")),
    Layer("client orchestration", ("hf2l.client_steps",),
          ("hf2l.common", "hf2l.core", "hf2l.backends.base", "hf2l.checkpoint",
           "hf2l.checkpoint_utils", "hf2l.hub_helpers")),
    Layer("listener engine", ("hf2l.listener.engine",),
          ("hf2l.common", "hf2l.listener.engine"), STDLIB_ONLY),
    Layer("owner listener", ("hf2l.listener.owner",),
          ("hf2l.common", "hf2l.core", "hf2l.round", "hf2l.fedavg_runner",
           "hf2l.listener.engine"), STDLIB_ONLY),
    Layer("client listener", ("hf2l.listener",),
          ("hf2l.common", "hf2l.core", "hf2l.checkpoint", "hf2l.client_steps",
           "hf2l.listener"), STDLIB_ONLY),
    Layer("allowlist", ("hf2l.allowlist",),
          ("hf2l.common", "hf2l.hub_helpers"), STDLIB_ONLY),
    Layer("plugin loader", ("hf2l.plugin_loader",), (), STDLIB_ONLY),
    Layer("plugins.api", ("hf2l.plugins.api",), ("hf2l.common", "hf2l.core")),
    Layer("plugins", ("hf2l.plugins",),
          ("hf2l.plugins.api", "hf2l.examples", "examples", "hf2l.training", "hf2l.data_utils")),
    Layer("training examples", ("hf2l.training", "hf2l.data_utils"), ()),
    Layer("examples", ("hf2l.examples",), ("hf2l.examples",)),
    Layer("installed generic example", ("examples.generic_exchange",), SDK_MODULES),
    # These demo composition scripts need specific Exchange helpers. Keep the
    # grants on the scripts so sibling examples cannot import server internals.
    Layer("CIFAR-10 setup composition", ("examples.exchange_cifar10.setup_federation",),
          ("hf2l_exchange.auth", "hf2l_exchange.client")),
    Layer("CIFAR-10 service composition", ("examples.exchange_cifar10.start_service",),
          ("hf2l_exchange.transfer_client",)),
    Layer("installed examples", ("examples",), ("examples", "hf2l.data_utils")),
    Layer("cli", ("hf2l.cli",), ("hf2l", "hf2l_exchange.cli")),
    Layer("legacy commands", LEGACY_COMMANDS, ("hf2l",)),
    Layer("relay", ("hf2l.relay",), ("hf2l.common",)),
    Layer("legacy exchange protocol", ("hf2l.exchange.protocol",),
          ("hf2l.hub_helpers",), STDLIB_ONLY),
    Layer("legacy exchange client", ("hf2l.exchange.client",),
          ("hf2l.exchange.protocol",), frozenset({"httpx"})),
    Layer("legacy exchange", tuple(LEGACY_EXCHANGE_MODULES), ("hf2l.exchange",)),
    Layer("exchange SDK", SDK_MODULES, SDK_MODULES, frozenset({"httpx"})),
    Layer("exchange vocabulary", ("hf2l_exchange.vocabulary",), (), STDLIB_ONLY),
    Layer("exchange domain", ("hf2l_exchange.domain",), ("hf2l_exchange.vocabulary",), STDLIB_ONLY),
    Layer("exchange profiles", ("hf2l_exchange.profiles",), ("hf2l_exchange.domain",), STDLIB_ONLY),
    Layer("exchange settings", ("hf2l_exchange.config",), (), STDLIB_ONLY),
    Layer("exchange application", ("hf2l_exchange.application",),
          ("hf2l_exchange.domain", "hf2l_exchange.models", "hf2l_exchange.profiles",
           "hf2l_exchange.schemas", "hf2l_exchange.vocabulary"), frozenset({"sqlalchemy"})),
    Layer("exchange persistence", ("hf2l_exchange.models", "hf2l_exchange.migrations"),
          ("hf2l_exchange.domain", "hf2l_exchange.vocabulary"), frozenset({"sqlalchemy"})),
    Layer("exchange schema validation", ("hf2l_exchange.schemas",),
          ("hf2l_exchange.domain", "hf2l_exchange.vocabulary"), frozenset({"jsonschema", "referencing"})),
    Layer("exchange identity", ("hf2l_exchange.auth",),
          ("hf2l_exchange.domain", "hf2l_exchange.vocabulary"), frozenset({"jwt"})),
    Layer("exchange storage", ("hf2l_exchange.storage",),
          ("hf2l_exchange.domain", "hf2l_exchange.vocabulary"), frozenset({"boto3", "botocore"})),
    Layer("exchange transfer orchestration", ("hf2l_exchange.transfers",),
          ("hf2l_exchange.domain", "hf2l_exchange.models", "hf2l_exchange.storage",
           "hf2l_exchange.vocabulary"), frozenset({"sqlalchemy"})),
    Layer("exchange worker", ("hf2l_exchange.worker",),
          ("hf2l_exchange.models", "hf2l_exchange.vocabulary"), frozenset({"sqlalchemy"})),
    Layer("exchange HTTP composition", ("hf2l_exchange.api",),
          ("hf2l_exchange.application", "hf2l_exchange.auth", "hf2l_exchange.config",
           "hf2l_exchange.domain", "hf2l_exchange.migrations", "hf2l_exchange.storage",
           "hf2l_exchange.transfers", "hf2l_exchange.vocabulary")),
    Layer("exchange CLI composition", ("hf2l_exchange.cli",), ("hf2l_exchange",)),
    Layer("exchange contract export", ("hf2l_exchange.contracts",),
          ("hf2l_exchange.api", "hf2l_exchange.config", "hf2l_exchange.vocabulary")),
    Layer("exchange package", ("hf2l_exchange",), (), STDLIB_ONLY),
    # Historical target names stay covered for the WP0 adversarial parser tests;
    # V3 does not create a second SDK under the legacy service package.
    Layer("stores.exchange", ("hf2l.stores.exchange",),
          ("hf2l.common", "hf2l.core", "hf2l.stores", "hf2l.exchange.sdk",
           "hf2l.exchange.vocabulary", "hf2l.exchange.profiles")),
    Layer("stores", ("hf2l.stores",), ("hf2l.common", "hf2l.core", "hf2l.stores")),
    Layer("exchange.vocabulary", ("hf2l.exchange.vocabulary",), ("hf2l.common",), STDLIB_ONLY),
    Layer("exchange.profiles", ("hf2l.exchange.profiles",), ("hf2l.common",), STDLIB_ONLY),
    Layer("exchange.sdk", ("hf2l.exchange.sdk",),
          ("hf2l.common", "hf2l.exchange.vocabulary"), frozenset({"httpx"})),
    Layer("exchange", ("hf2l.exchange.domain",), ("hf2l.common", "hf2l.exchange")),
)

COMPOSITION_ROOT = "hf2l.cli"
LAZY_REGISTRY_PACKAGE = "hf2l.stores"
COMPATIBILITY_EXPORT_PACKAGE = "hf2l.backends"
TORCH_IMPORTERS = ("hf2l.checkpoint.safetensors_torch", "hf2l.plugins", "hf2l.examples", "examples", "hf2l.training")
TORCH_MODULES = ("torch", "safetensors.torch")
PRINTERS = ("hf2l.cli", "hf2l.examples", "examples", "hf2l_exchange.cli", "hf2l.exchange.cli", "hf2l.training") + LEGACY_COMMANDS


def layer_of(module: str) -> Layer | None:
    if module == PACKAGE:
        return ROOT
    return next((layer for layer in LAYERS
                 if (module in layer.members if layer.name in {"legacy exchange", "exchange package"}
                     else any(covers(m, module) for m in layer.members))), None)


@dataclass(frozen=True)
class Module:
    name: str
    path: PurePosixPath  # repository-relative
    is_package: bool

    @classmethod
    def from_path(cls, relative: str) -> Module | None:
        path = PurePosixPath(relative)
        if path.suffix != ".py":
            return None
        parts = list(path.with_suffix("").parts)
        if parts[:3] == ["packages", "exchange", "src"]:
            parts = parts[3:]
        is_package = parts[-1] == "__init__"
        if is_package:
            parts.pop()
        return cls(".".join(parts), path, is_package)


@dataclass(frozen=True)
class Import:
    # Absolute dotted name. `from X import y` targets X.y when X is third-party (only its prefixes are judged) or when
    # X.y is a known hf2l module; otherwise y is an attribute of X and the target is X.
    target: str
    line: int
    eager: bool  # executes at import time: not inside a def and not under `if TYPE_CHECKING:`
    type_only: bool  # under `if TYPE_CHECKING:`: never executes, so it is not a runtime dependency
    statement: str

    @property
    def top(self) -> str:
        return self.target.partition(".")[0]

    @property
    def internal(self) -> bool:
        return internal_name(self.target)


@dataclass(frozen=True)
class Source:
    module: Module
    imports: tuple[Import, ...]
    prints: tuple[int, ...]  # line numbers of print() calls


def _is_type_checking(test: ast.expr) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


class _ImportCollector(ast.NodeVisitor):
    def __init__(self, module: Module, known: frozenset[str]) -> None:
        self.module = module
        self.known = known
        self.found: list[Import] = []
        self._def_depth = 0
        self._type_depth = 0

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._def_depth += 1
        self.generic_visit(node)
        self._def_depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_If(self, node: ast.If) -> None:
        if not _is_type_checking(node.test):
            self.generic_visit(node)
            return
        self._type_depth += 1
        for child in node.body:
            self.visit(child)
        self._type_depth -= 1
        for child in node.orelse:
            self.visit(child)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._add(alias.name, node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        base = self._resolve(node)
        for alias in node.names:
            candidate = f"{base}.{alias.name}"
            self._add(candidate if candidate in self.known or not internal_name(base) else base, node)

    def _resolve(self, node: ast.ImportFrom) -> str:
        if node.level == 0:
            return node.module or ""
        package = self.module.name if self.module.is_package else self.module.name.rpartition(".")[0]
        parts = package.split(".")
        base = ".".join(parts[: max(len(parts) - (node.level - 1), 0)])
        return f"{base}.{node.module}" if node.module else base

    def _add(self, target: str, node: ast.stmt) -> None:
        eager = self._def_depth == 0 and self._type_depth == 0
        self.found.append(Import(target, node.lineno, eager, self._type_depth > 0, ast.unparse(node)))


def analyse(module: Module, text: str, known: frozenset[str]) -> Source:
    tree = ast.parse(text, filename=str(module.path))
    collector = _ImportCollector(module, known)
    collector.visit(tree)
    prints = tuple(
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print"
    )
    return Source(module, tuple(collector.found), prints)


def tracked_modules() -> list[Module]:
    """All production Python modules, tracked and new nonignored sources alike."""
    listing = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard", *SOURCE_ROOTS],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    modules = (Module.from_path(line) for line in listing.splitlines() if line)
    return sorted((m for m in modules if m is not None and (REPO_ROOT / m.path).is_file()), key=lambda m: m.name)


def _is_stdlib(top: str) -> bool:
    return top in sys.stdlib_module_names or top in sys.builtin_module_names


def _allowed(names: tuple[str, ...]) -> str:
    return ", ".join(names) if names else "nothing from hf2l"


Rule = Callable[[Source], list[str]]


def edge_violations(source: Source) -> list[str]:
    """Layering is conceptual, so typing-only and lazy hf2l edges count as much as eager ones."""
    layer = layer_of(source.module.name)
    if layer is None:
        return []
    return [
        f"{source.module.path}:{i.line}: `{i.statement}` imports {i.target}; "
        f"layer '{layer.name}' may import {_allowed(layer.imports)}"
        for i in source.imports
        if i.internal and i.target != source.module.name and not any(covers(a, i.target) for a in layer.imports)
    ]


def init_violations(source: Source) -> list[str]:
    if not source.module.is_package or source.module.name in {COMPOSITION_ROOT, COMPATIBILITY_EXPORT_PACKAGE}:
        return []
    lazy_allowed = source.module.name == LAZY_REGISTRY_PACKAGE
    what = "only lazily (inside a function) for the stores REGISTRY" if lazy_allowed else "nothing from hf2l"
    return [
        f"{source.module.path}:{i.line}: `{i.statement}` imports {i.target}; package __init__ files import {what}"
        for i in source.imports
        if i.internal and (i.eager or not lazy_allowed)
    ]


def third_party_violations(source: Source) -> list[str]:
    """A runtime-dependency rule: typing-only imports are exempt, function-local ones are not (they do execute)."""
    layer = layer_of(source.module.name)
    if layer is None or layer.third_party is None:
        return []
    extra = f" and {', '.join(sorted(layer.third_party))}" if layer.third_party else ""
    return [
        f"{source.module.path}:{i.line}: `{i.statement}` imports {i.top}; "
        f"layer '{layer.name}' may import only the standard library{extra} (typing-only imports excepted)"
        for i in source.imports
        if not i.internal and not i.type_only and not _is_stdlib(i.top) and i.top not in layer.third_party
    ]


def torch_violations(source: Source) -> list[str]:
    if any(covers(p, source.module.name) for p in TORCH_IMPORTERS):
        return []
    return [
        f"{source.module.path}:{i.line}: `{i.statement}`; {' and '.join(TORCH_MODULES)} are imported only by "
        f"{', '.join(TORCH_IMPORTERS)}"
        for i in source.imports
        if any(covers(t, i.target) for t in TORCH_MODULES)
    ]


def exchange_framework_violations(source: Source) -> list[str]:
    if not covers("hf2l_exchange", source.module.name):
        return []
    forbidden = {"torch", "numpy", "safetensors", "huggingface_hub"}
    return [f"{source.module.path}:{i.line}: generic exchange imports ML dependency {i.target}"
            for i in source.imports if i.top in forbidden]


def eager_backend_violations(source: Source) -> list[str]:
    if source.module.name not in {"hf2l.backends", "hf2l.backends.factory"}:
        return []
    providers = ("hf2l.backends.huggingface", "hf2l.backends.jfrog", "hf2l.backends.exchange", "hf2l.backends.local")
    return [f"{source.module.path}:{i.line}: registry eagerly imports provider {i.target}"
            for i in source.imports if i.eager and any(covers(p, i.target) for p in providers)]


def print_violations(source: Source) -> list[str]:
    if any(covers(p, source.module.name) for p in PRINTERS):
        return []
    return [f"{source.module.path}:{line}: print() call; only {', '.join(PRINTERS)} print" for line in source.prints]


class LayeringTests(unittest.TestCase):
    """Allowlist over every production module from `git ls-files -co`."""

    sources: list[Source]

    @classmethod
    def setUpClass(cls) -> None:
        modules = tracked_modules()
        known = frozenset(m.name for m in modules)
        cls.sources = [
            analyse(m, (REPO_ROOT / m.path).read_text(encoding="utf-8"), known) for m in modules if in_scope(m.name)
        ]

    def _assert_clean(self, rule: Rule) -> None:
        problems = [problem for source in self.sources for problem in rule(source)]
        if problems:
            self.fail(f"{len(problems)} layering violation(s):\n" + "\n".join(problems))

    def test_every_scoped_module_is_assigned_a_layer(self) -> None:
        unassigned = [str(s.module.path) for s in self.sources if layer_of(s.module.name) is None]
        self.assertEqual([], unassigned, "modules without an allowlist row; add one to LAYERS")

    def test_generic_exchange_has_no_ml_framework_dependencies(self) -> None:
        self._assert_clean(exchange_framework_violations)

    def test_backend_registry_loads_providers_lazily(self) -> None:
        self._assert_clean(eager_backend_violations)

    def test_intra_package_edges_are_allowlisted(self) -> None:
        self._assert_clean(edge_violations)

    def test_package_inits_import_nothing_from_hf2l(self) -> None:
        self._assert_clean(init_violations)

    def test_stdlib_layers_import_only_the_standard_library(self) -> None:
        self._assert_clean(third_party_violations)

    def test_torch_is_confined_to_its_backend_plugins_and_examples(self) -> None:
        self._assert_clean(torch_violations)

    def test_print_is_confined_to_cli_and_examples(self) -> None:
        self._assert_clean(print_violations)


class GateSelfTests(unittest.TestCase):
    """The gate keeps rejecting the seeded WP0 edge after the stub that carried it is gone, row by row."""

    KNOWN = frozenset(
        {
            "hf2l",
            "hf2l.core",
            "hf2l.core.ports",
            "hf2l.cli",
            "hf2l.cli.fl",
            "hf2l.exchange",
            "hf2l.exchange.runtime",
            "hf2l.exchange.domain.refs",
            "hf2l.examples.trainer",
        }
    )

    @staticmethod
    def _source(name: str, text: str, *, is_package: bool = False, known: frozenset[str] = KNOWN) -> Source:
        path = PurePosixPath(*name.split("."))
        path = path / "__init__.py" if is_package else path.with_suffix(".py")
        return analyse(Module(name, path, is_package), text, known)

    def test_seeded_edge_is_rejected_by_the_sdk_row_and_the_allowed_one_accepted(self) -> None:
        text = "from hf2l.core import ports\nfrom hf2l.exchange.vocabulary import ErrorCode\n"
        problems = edge_violations(self._source("hf2l.exchange.sdk", text))
        self.assertEqual(1, len(problems))
        self.assertIn("hf2l/exchange/sdk.py:1: `from hf2l.core import ports` imports hf2l.core.ports", problems[0])
        self.assertIn("layer 'exchange.sdk' may import hf2l.common, hf2l.exchange.vocabulary", problems[0])

    def test_sdk_row_forbids_other_exchange_modules_and_any_client_but_httpx(self) -> None:
        text = "import httpx\nimport requests\nfrom hf2l.exchange import runtime\nfrom hf2l.common import fs\n"
        source = self._source("hf2l.exchange.sdk", text)
        edges = edge_violations(source)
        self.assertEqual(1, len(edges))
        self.assertIn(
            "hf2l/exchange/sdk.py:3: `from hf2l.exchange import runtime` imports hf2l.exchange.runtime", edges[0]
        )
        clients = third_party_violations(source)
        self.assertEqual(1, len(clients))
        self.assertIn(
            "`import requests` imports requests; layer 'exchange.sdk' may import only the standard library and httpx",
            clients[0],
        )

    def test_from_import_targets_the_hf2l_submodule_only_when_it_exists(self) -> None:
        source = self._source("hf2l.stores.exchange", "from hf2l.core import ports, Capability\n")
        self.assertEqual(["hf2l.core.ports", "hf2l.core"], [i.target for i in source.imports])

    def test_from_import_of_a_third_party_name_keeps_the_dotted_target(self) -> None:
        text = "from safetensors import numpy as stn\nfrom __future__ import annotations\n"
        source = self._source("hf2l.checkpoint.aggregate", text)
        self.assertEqual(["safetensors.numpy", "__future__.annotations"], [i.target for i in source.imports])
        self.assertEqual(["safetensors", "__future__"], [i.top for i in source.imports])
        self.assertEqual([], third_party_violations(source))

    def test_relative_imports_resolve_against_the_importing_package(self) -> None:
        text = "from ..vocabulary import ErrorCode\nfrom . import refs\n"
        source = self._source("hf2l.exchange.domain.records", text)
        self.assertEqual(["hf2l.exchange.vocabulary", "hf2l.exchange.domain.refs"], [i.target for i in source.imports])

    def test_imports_inside_functions_or_type_checking_blocks_are_lazy(self) -> None:
        text = (
            "from typing import TYPE_CHECKING\n"
            "import hf2l.core\n"
            "if TYPE_CHECKING:\n    from hf2l.core import ports\n"
            "def spec():\n    from hf2l.stores import local\n"
        )
        source = self._source("hf2l.stores", text, is_package=True)
        self.assertEqual([True, True, False, False], [i.eager for i in source.imports])
        self.assertEqual([False, False, True, False], [i.type_only for i in source.imports])
        self.assertEqual(1, len(init_violations(source)))
        self.assertIn("hf2l/stores/__init__.py:2", init_violations(source)[0])

    def test_stdlib_only_layers_reject_third_party_but_not_stdlib(self) -> None:
        source = self._source("hf2l.core.protocol", "import json\nimport numpy as np\nfrom hf2l.common import fs\n")
        problems = third_party_violations(source)
        self.assertEqual(1, len(problems))
        self.assertIn("`import numpy as np` imports numpy", problems[0])
        self.assertEqual([], edge_violations(source))

    def test_stdlib_only_layers_accept_typing_only_third_party_imports_but_not_function_local_ones(self) -> None:
        text = (
            "from typing import TYPE_CHECKING\n"
            "if TYPE_CHECKING:\n    from numpy.typing import NDArray\n"
            "def load():\n    import numpy\n"
        )
        problems = third_party_violations(self._source("hf2l.core.ports", text))
        self.assertEqual(1, len(problems))
        self.assertIn("hf2l/core/ports.py:5: `import numpy` imports numpy", problems[0])
        # a typing-only hf2l edge is still a layering edge
        typed_edge = "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from hf2l.core import protocol\n"
        self.assertEqual(1, len(edge_violations(self._source("hf2l.checkpoint.format", typed_edge))))

    def test_checkpoint_is_numpy_and_safetensors_capable_except_the_stdlib_sniffer(self) -> None:
        numpy_import = "import numpy as np\nfrom safetensors.numpy import load_file\n"
        self.assertEqual([], third_party_violations(self._source("hf2l.checkpoint.format", numpy_import)))
        self.assertEqual([], third_party_violations(self._source("hf2l.checkpoint.aggregate", numpy_import)))
        sniffer = third_party_violations(self._source("hf2l.checkpoint.safetensors", numpy_import))
        self.assertEqual(2, len(sniffer))
        self.assertIn("layer 'checkpoint.safetensors' may import only the standard library", sniffer[0])
        self.assertEqual([], torch_violations(self._source("hf2l.checkpoint.aggregate", numpy_import)))

    def test_safetensors_torch_counts_as_a_torch_import_outside_the_torch_backend(self) -> None:
        statements = (
            "import safetensors.torch\n",
            "from safetensors import torch as st\n",
            "from safetensors.torch import load_file\n",
        )
        for statement in statements:
            with self.subTest(statement=statement.strip()):
                problems = torch_violations(self._source("hf2l.checkpoint.safetensors_numpy", statement))
                self.assertEqual(1, len(problems))
                self.assertIn("torch and safetensors.torch are imported only by", problems[0])
                self.assertEqual([], torch_violations(self._source("hf2l.checkpoint.safetensors_torch", statement)))
        harmless = self._source("hf2l.checkpoint.safetensors_numpy", "from safetensors import numpy\n")
        self.assertEqual([], torch_violations(harmless))

    def test_examples_may_import_each_other_but_nothing_else_from_hf2l(self) -> None:
        sibling = self._source("hf2l.examples.mnist_data", "from hf2l.examples.trainer import stable_seed\n")
        self.assertEqual([], edge_violations(sibling))
        problems = edge_violations(self._source("hf2l.examples.mnist_data", "from hf2l.core import ports\n"))
        self.assertEqual(1, len(problems))
        self.assertIn("layer 'examples' may import hf2l.examples", problems[0])

    def test_cifar10_composition_scripts_accept_their_required_exchange_imports(self) -> None:
        scripts = {
            "examples.exchange_cifar10.setup_federation": (
                "from hf2l_exchange.auth import principal_id\n"
                "from hf2l_exchange.client import ExchangeClient\n"
            ),
            "examples.exchange_cifar10.start_service": (
                "def run():\n    from hf2l_exchange.transfer_client import require_tls\n"
            ),
        }
        for name, text in scripts.items():
            with self.subTest(module=name):
                self.assertEqual([], edge_violations(self._source(name, text)))

    def test_cifar10_composition_scripts_reject_unrelated_exchange_imports(self) -> None:
        forbidden = {
            "examples.exchange_cifar10.setup_federation": (
                "hf2l_exchange.api", "hf2l_exchange.application", "hf2l_exchange.storage",
                "hf2l_exchange.transfer_client",
            ),
            "examples.exchange_cifar10.start_service": (
                "hf2l_exchange.api", "hf2l_exchange.application", "hf2l_exchange.storage",
                "hf2l_exchange.auth", "hf2l_exchange.client",
            ),
        }
        for name, targets in forbidden.items():
            for target in targets:
                with self.subTest(module=name, target=target):
                    problems = edge_violations(self._source(name, f"import {target}\n"))
                    self.assertEqual(1, len(problems))
                    self.assertIn(f"imports {target};", problems[0])

    def test_cifar10_composition_allowances_do_not_extend_to_sibling_examples(self) -> None:
        siblings = (
            "examples.exchange_cifar10", "examples.exchange_cifar10.train_client",
            "examples.exchange_cifar10.setup_federation_extra", "examples.exchange_cifar10.start_service_extra",
            "examples.other.setup_federation", "examples.other.start_service",
        )
        text = (
            "from hf2l_exchange.auth import principal_id\n"
            "from hf2l_exchange.client import ExchangeClient\n"
            "from hf2l_exchange.transfer_client import require_tls\n"
        )
        for name in siblings:
            with self.subTest(module=name):
                self.assertEqual("installed examples", layer_of(name).name)
                self.assertEqual(3, len(edge_violations(self._source(name, text))))

    def test_only_the_cli_init_may_import_hf2l_eagerly(self) -> None:
        self.assertEqual([], init_violations(self._source("hf2l.cli", "from hf2l.cli import fl\n", is_package=True)))
        problems = init_violations(self._source("hf2l.round", "from hf2l.core import ports\n", is_package=True))
        self.assertEqual(1, len(problems))
        self.assertIn("hf2l/round/__init__.py:1", problems[0])

    def test_scope_covers_all_production_modules_in_both_distributions(self) -> None:
        self.assertTrue(in_scope("hf2l.plugins.lenet"))
        self.assertTrue(in_scope("hf2l.exchange.domain.records"))
        self.assertTrue(in_scope("hf2l.exchange"))
        self.assertTrue(in_scope("hf2l.plugins.lenet_poc"))
        self.assertTrue(in_scope("hf2l.exchange.api"))
        self.assertTrue(in_scope("hf2l_exchange.client"))
        self.assertFalse(in_scope("tests.test_layering"))

    def test_standalone_sdk_cannot_import_server_or_application(self) -> None:
        source = self._source("hf2l_exchange.client", "from hf2l_exchange.application import Service\nfrom hf2l.core import ports\nimport httpx\nimport sqlalchemy\n")
        self.assertEqual(2, len(edge_violations(source)))
        self.assertEqual(1, len(third_party_violations(source)))

    def test_server_cannot_import_fl_even_lazily(self) -> None:
        source = self._source("hf2l_exchange.application", "def bad():\n    from hf2l.core import ports\n    import torch\n")
        self.assertEqual(1, len(edge_violations(source)))
        self.assertEqual(1, len(exchange_framework_violations(source)))

    def test_legacy_service_is_bounded_and_cannot_expand_into_new_application(self) -> None:
        self.assertIsNone(layer_of("hf2l.exchange.new_feature"))
        source = self._source("hf2l.exchange.api", "from hf2l.core import ports\n")
        self.assertEqual(1, len(edge_violations(source)))
        current = self._source("hf2l.fedavg_runner", "from hf2l.exchange.api import Service\n")
        self.assertEqual(1, len(edge_violations(current)))

    def test_transactional_application_cannot_import_http_or_sdk(self) -> None:
        source = self._source("hf2l_exchange.application", "from hf2l_exchange.api import create_app\nfrom hf2l_exchange.client import ExchangeClient\n")
        self.assertEqual(2, len(edge_violations(source)))
        self.assertIsNone(layer_of("hf2l_exchange.unassigned_feature"))

    def test_distribution_source_path_resolves_to_importable_package(self) -> None:
        module = Module.from_path("packages/exchange/src/hf2l_exchange/client.py")
        self.assertEqual(module.name, "hf2l_exchange.client")
        self.assertEqual(str(module.path), "packages/exchange/src/hf2l_exchange/client.py")

    def test_registry_imports_providers_only_when_called(self) -> None:
        eager = self._source("hf2l.backends.factory", "import hf2l.backends.huggingface\n")
        lazy = self._source("hf2l.backends.factory", "def make():\n    import hf2l.backends.huggingface\n")
        self.assertEqual(1, len(eager_backend_violations(eager)))
        self.assertEqual([], eager_backend_violations(lazy))

    def test_module_specific_rows_do_not_cover_their_siblings(self) -> None:
        self.assertEqual("checkpoint.safetensors", layer_of("hf2l.checkpoint.safetensors").name)
        self.assertEqual("checkpoint numpy backend", layer_of("hf2l.checkpoint.safetensors_numpy").name)
        self.assertEqual("checkpoint", layer_of("hf2l.checkpoint.format").name)
        self.assertEqual("exchange.sdk", layer_of("hf2l.exchange.sdk").name)
        self.assertEqual("exchange", layer_of("hf2l.exchange.domain.refs").name)
        self.assertEqual("root", layer_of(PACKAGE).name)


if __name__ == "__main__":
    unittest.main()
