"""Regenerate Python protobuf and gRPC bindings for `agentic.v1`.

Usage (with grpcio-tools installed):

    python services/python-cognitive/scripts/gen_proto.py

Docker alternative from the project root:

    docker run --rm -v "$PWD:/work" -w /work python:3.12-slim \
      bash -c "pip install -q grpcio-tools==1.74.0 && \
      python services/python-cognitive/scripts/gen_proto.py"
"""

from __future__ import annotations

import re
from pathlib import Path

import grpc_tools
from grpc_tools import protoc

SERVICE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVICE_ROOT.parents[1]
PROTO_ROOT = REPO_ROOT / "proto"
PROTO_FILE = PROTO_ROOT / "agentic" / "v1" / "cognitive.proto"
OUT_DIR = SERVICE_ROOT / "app" / "gen"


def _write_namespace_packages() -> None:
    for path in (
        OUT_DIR,
        OUT_DIR / "agentic",
        OUT_DIR / "agentic" / "v1",
    ):
        path.mkdir(parents=True, exist_ok=True)
        init = path / "__init__.py"
        init.touch(exist_ok=True)


def _make_grpc_imports_relative() -> None:
    """Convert protoc's absolute package imports to relative imports.

    protoc emits `from agentic.v1 import cognitive_pb2` for grpc stubs. Our
    generated package lives at `app.gen.agentic.v1`, so the absolute form does
    not resolve when installed as `app`. Relative imports keep the package
    importable without adding `app/gen` to `sys.path`.
    """
    pattern = re.compile(
        r"^from agentic\.v1 import (\w+)( as \w+)?$", re.MULTILINE
    )
    for path in OUT_DIR.rglob("*_pb2_grpc.py"):
        text = path.read_text(encoding="utf-8")
        patched = pattern.sub(r"from . import \1\2", text)
        if patched != text:
            path.write_text(patched, encoding="utf-8")


def main() -> int:
    if not PROTO_FILE.is_file():
        raise SystemExit(f"proto not found: {PROTO_FILE}")

    _write_namespace_packages()

    include_dir = Path(grpc_tools.__file__).resolve().parent / "_proto"
    args = [
        "protoc",
        f"-I{PROTO_ROOT}",
        f"-I{include_dir}",
        f"--python_out={OUT_DIR}",
        f"--grpc_python_out={OUT_DIR}",
        str(PROTO_FILE),
    ]
    result = protoc.main(args)
    if result == 0:
        _make_grpc_imports_relative()
    return result


if __name__ == "__main__":
    raise SystemExit(main())
