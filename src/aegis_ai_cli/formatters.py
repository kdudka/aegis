"""Markdown formatters for CLI output models.

To add a custom formatter for a model, write a function that takes the model
instance and returns a markdown string, then register it in ``_CUSTOM_FORMATTERS``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import BaseModel

_META_FIELDS = frozenset({"data_quality", "confidence", "tools_used", "disclaimer"})
_HEADING_FIELDS = frozenset({"cve_id", "component_name"})


def _field_label(name: str) -> str:
    return name.replace("_", " ").title()


def _meta_footer(output: Any) -> str:
    lines: list[str] = ["---", ""]
    if hasattr(output, "confidence"):
        lines.append(f"**Confidence**: {output.confidence:.0%}")
    if hasattr(output, "data_quality"):
        lines.append(f"**Data Quality**: {output.data_quality:.0%}")
    if hasattr(output, "tools_used") and output.tools_used:
        lines.append(f"**Tools Used**: {', '.join(output.tools_used)}")
    if hasattr(output, "disclaimer"):
        lines.append(f"\n*{output.disclaimer}*")
    return "\n".join(lines)


def _format_value(value: Any) -> str:
    if isinstance(value, list):
        if not value:
            return ""
        if isinstance(value[0], BaseModel):
            parts: list[str] = []
            for item in value:
                fields = [
                    f"  **{_field_label(k)}**: {v}"
                    for k, v in item.model_dump().items()
                    if v is not None
                ]
                parts.append("\n".join(fields))
            return "\n\n".join(parts)
        return "\n".join(f"- {item}" for item in value)
    return str(value)


def _generic_markdown(output: Any) -> str:
    parts: list[str] = []

    heading_parts: list[str] = []
    for name in _HEADING_FIELDS:
        val = getattr(output, name, None)
        if val is not None:
            heading_parts.append(str(val))
    title = getattr(output, "title", None)
    if title and "title" in getattr(output, "model_fields", {}):
        heading_parts.append(title)
    if heading_parts:
        parts.append(f"# {' — '.join(heading_parts)}")
        parts.append("")

    skip = _META_FIELDS | _HEADING_FIELDS | {"explanation", "title"}
    for name, field_info in output.model_fields.items():
        if name in skip:
            continue
        if getattr(field_info, "exclude", False):
            continue
        value = getattr(output, name)
        if value is None:
            continue

        label = _field_label(name)
        formatted = _format_value(value)
        if isinstance(value, list):
            parts.append(f"**{label}**:")
            parts.append(formatted)
            parts.append("")
        else:
            parts.append(f"**{label}**: {formatted}")

    explanation = getattr(output, "explanation", None)
    if explanation is not None:
        parts.append("")
        parts.append("## Explanation")
        parts.append("")
        parts.append(explanation)

    from aegis_ai.features.data_models import AegisFeatureModel

    if isinstance(output, AegisFeatureModel):
        parts.append("")
        parts.append(_meta_footer(output))

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Custom formatters
# ---------------------------------------------------------------------------


def _format_suggest_impact(output: Any) -> str:
    parts: list[str] = []

    heading = str(output.cve_id)
    if output.title:
        heading += f" — {output.title}"
    parts.append(f"# {heading}")
    parts.append("")

    parts.append(f"**Impact**: {output.impact}")
    parts.append(f"**CVSS Score**: {output.cvss3_score}")
    if output.cvss3_vector:
        parts.append(f"**CVSS Vector**: {output.cvss3_vector}")

    parts.append("")
    parts.append("## Explanation")
    parts.append("")
    parts.append(output.explanation)

    parts.append("")
    parts.append(_meta_footer(output))
    return "\n".join(parts)


_CUSTOM_FORMATTERS: dict[type, Callable[..., str]] = {}


def _register_custom_formatters() -> None:
    from aegis_ai.features.cve.data_models import SuggestImpactModel

    _CUSTOM_FORMATTERS[SuggestImpactModel] = _format_suggest_impact


def format_markdown(output: Any) -> str:
    if not _CUSTOM_FORMATTERS:
        _register_custom_formatters()
    formatter = _CUSTOM_FORMATTERS.get(type(output), _generic_markdown)
    return formatter(output)
