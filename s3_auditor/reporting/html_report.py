from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape


def render_html_report(payload: Dict[str, Any], template_path: str = "s3_auditor/reporting/templates/report.html") -> str:
    env = Environment(
        loader=FileSystemLoader(str(Path(template_path).parent)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html")
    return template.render(report=payload)


def write_html_report(path: str, payload: Dict[str, Any]) -> str:
    html = render_html_report(payload)
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return str(output_path)
