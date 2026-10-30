from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


def write_json_report(path: str, payload: Dict[str, Any]) -> str:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    return str(output_path)
