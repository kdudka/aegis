#!/usr/bin/env python3
"""Generate docs/openapi.json and docs/openapi.yml from the FastAPI app."""

import json
import sys
from pathlib import Path

import yaml

from aegis_ai_web.src.main import app

DOCS_DIR = Path(__file__).resolve().parent.parent / "docs"


def generate(output_dir: Path | None = None) -> None:
    target = output_dir or DOCS_DIR
    target.mkdir(parents=True, exist_ok=True)

    schema = app.openapi()

    json_path = target / "openapi.json"
    json_path.write_text(
        json.dumps(schema, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    yml_path = target / "openapi.yml"
    yml_path.write_text(
        yaml.dump(schema, default_flow_style=False, sort_keys=True),
        encoding="utf-8",
    )


if __name__ == "__main__":
    output_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    generate(output_dir)
