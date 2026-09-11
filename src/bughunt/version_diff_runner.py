from __future__ import annotations

import ast
import itertools
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

SAFE_CALLS = {
    "abs",
    "all",
    "any",
    "bool",
    "bytes",
    "dict",
    "enumerate",
    "float",
    "int",
    "len",
    "list",
    "max",
    "min",
    "range",
    "reversed",
    "round",
    "set",
    "sorted",
    "str",
    "sum",
    "tuple",
    "zip",
}
SAMPLES: dict[str, list[Any]] = {
    "int": [-10, -2, -1, 0, 1, 2, 10, 2**31 - 1],
    "float": [-10.5, -1.0, -0.0, 0.0, 0.5, 1.0, 10.5],
    "str": ["", "a", "A", "0", "é", "İ", "ß", "a b", "x" * 80],
    "bytes": [b"", b"\x00", b"a", b"\xff", b"abc"],
    "bool": [False, True],
}


# trace:v1 id=impl.src-bughunt-version_diff_runner.-git-show work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _git_show(root: Path, ref: str, rel: str) -> str | None:
    if not shutil.which("git"):
        return None
    p = subprocess.run(
        ["git", "show", f"{ref}:{rel}"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    return p.stdout if p.returncode == 0 else None


def _annotation_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    return None


# trace:v1 id=impl.src-bughunt-version_diff_runner.-safe-function work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _safe_function(node: ast.FunctionDef) -> tuple[list[str], list[list[Any]]] | None:
    if (
        node.decorator_list
        or node.args.vararg
        or node.args.kwarg
        or node.args.kwonlyargs
    ):
        return None
    args = [*node.args.posonlyargs, *node.args.args]
    if not args or len(args) > 3:
        return None
    domains: list[list[Any]] = []
    for arg in args:
        ann = _annotation_name(arg.annotation)
        if ann not in SAMPLES:
            return None
        domains.append(SAMPLES[ann])
    # Side-effect-free conservative subset. No loops, await/yield, mutation,
    # comprehensions, attributes/subscripts stores, or arbitrary calls.
    banned = (
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.With,
        ast.AsyncWith,
        ast.Try,
        ast.Raise,
        ast.Yield,
        ast.YieldFrom,
        ast.Await,
        ast.Delete,
        ast.Global,
        ast.Nonlocal,
        ast.Import,
        ast.ImportFrom,
        ast.Lambda,
        ast.ListComp,
        ast.SetComp,
        ast.DictComp,
        ast.GeneratorExp,
    )
    for child in ast.walk(node):
        if isinstance(child, banned):
            return None
        if isinstance(child, ast.Call) and (
            not isinstance(child.func, ast.Name) or child.func.id not in SAFE_CALLS
        ):
            return None
        if isinstance(child, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = child.targets if isinstance(child, ast.Assign) else [child.target]
            if any(not isinstance(t, ast.Name) for t in targets):
                return None
    return [a.arg for a in args], domains


# trace:v1 id=impl.src-bughunt-version_diff_runner.-functions work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _functions(source: str) -> dict[str, ast.FunctionDef]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}
    return {
        n.name: n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and not n.name.startswith("_")
    }


# trace:v1 id=impl.src-bughunt-version_diff_runner.-compile-function work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _compile_function(node: ast.FunctionDef) -> Any:
    clean = ast.FunctionDef(
        name=node.name,
        args=node.args,
        body=node.body,
        decorator_list=[],
        returns=node.returns,
        type_comment=node.type_comment,
        type_params=getattr(node, "type_params", []),
    )
    module = ast.fix_missing_locations(ast.Module(body=[clean], type_ignores=[]))
    ns: dict[str, Any] = (
        {name: getattr(__builtins__, name, None) for name in SAFE_CALLS}
        if not isinstance(__builtins__, dict)
        else {name: __builtins__.get(name) for name in SAFE_CALLS}
    )
    exec(compile(module, "<bughunt-version-diff>", "exec"), ns, ns)  # noqa: S102 - sandboxed differential harness: AST-gated to SAFE_CALLS with restricted builtins
    return ns[node.name]


# trace:v1 id=impl.src-bughunt-version_diff_runner.main work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    if len(args) < 3:
        print(
            json.dumps(
                {
                    "findings": [],
                    "compared": 0,
                    "reason": "root baseline source paths required",
                },
            ),
        )
        return 0
    root = Path(args.pop(0)).resolve()
    baseline = args.pop(0)
    source_paths = args
    findings: list[dict[str, object]] = []
    compared = 0
    for relroot in source_paths:
        base = root / relroot
        paths = (
            [base]
            if base.is_file()
            else list(base.rglob("*.py"))
            if base.is_dir()
            else []
        )
        for path in paths:
            try:
                rel = path.relative_to(root).as_posix()
                current_source = path.read_text(errors="replace")
            except OSError:
                continue
            old_source = _git_show(root, baseline, rel)
            if old_source is None or old_source == current_source:
                continue
            oldf, newf = _functions(old_source), _functions(current_source)
            for name in sorted(oldf.keys() & newf.keys()):
                old_info = _safe_function(oldf[name])
                new_info = _safe_function(newf[name])
                if not old_info or not new_info or old_info[0] != new_info[0]:
                    continue
                # Require identical annotation domains to avoid declaring an intentional
                # signature change a behavioral mismatch; Griffe owns API-shape drift.
                if [
                    _annotation_name(a.annotation)
                    for a in [*oldf[name].args.posonlyargs, *oldf[name].args.args]
                ] != [
                    _annotation_name(a.annotation)
                    for a in [*newf[name].args.posonlyargs, *newf[name].args.args]
                ]:
                    continue
                try:
                    old_fn, new_fn = (
                        _compile_function(oldf[name]),
                        _compile_function(newf[name]),
                    )
                except Exception:  # noqa: BLE001, S112 - differential harness: uncompilable sampled pairs are skipped, not findings
                    continue
                compared += 1
                cases = itertools.product(*new_info[1])
                for idx, case in enumerate(cases):
                    if idx >= 256:
                        break
                    try:
                        before = old_fn(*case)
                        before_exc = None
                    except Exception as exc:  # noqa: BLE001 - differential oracle: the exception type is the recorded signal
                        before = None
                        before_exc = type(exc).__name__
                    try:
                        after = new_fn(*case)
                        after_exc = None
                    except Exception as exc:  # noqa: BLE001 - differential oracle: the exception type is the recorded signal
                        after = None
                        after_exc = type(exc).__name__
                    if before_exc != after_exc or (
                        before_exc is None and before != after
                    ):
                        findings.append(
                            {
                                "tool": "version-diff",
                                "code": "BHDIFF001",
                                "path": rel,
                                "line": getattr(newf[name], "lineno", None),
                                "severity": "warning",
                                "message": (
                                    f"public side-effect-free function {name} changed "
                                    f"observable behavior vs {baseline[:12]} for "
                                    f"args={case!r}: old={before_exc or before!r}, "
                                    f"new={after_exc or after!r}"
                                ),
                            },
                        )
                        break
    print(
        json.dumps({"findings": findings, "compared": compared, "baseline": baseline}),
    )
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
