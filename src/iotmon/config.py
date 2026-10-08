"""Configuration: the project's config.yaml and rules/detection_rules.yaml,
optionally overridden by a site config (--config) or another rule file
(--rules).

    config.yaml                  site settings: networks, baseline, flows
    rules/detection_rules.yaml   rule catalogue: IDs, names, thresholds

The result is one dict. `config["detections"][<detector>]` holds each
rule's settings plus `enabled`, which is what the detection engine reads,
and `config["rules"]` keeps the full catalogue (IDs, names, severities,
ATT&CK) for display and validation.

Both files live at the repository root, found relative to this package
(src/iotmon/ -> ../..). Set IOTMON_HOME to use another directory, e.g. for
a non-editable install.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

import yaml

HOME = Path(os.environ.get("IOTMON_HOME") or Path(__file__).resolve().parents[2])
DEFAULT_CONFIG = HOME / "config.yaml"
DEFAULT_RULES = HOME / "rules" / "detection_rules.yaml"
RULE_FIELDS = ("id", "detector", "name", "severities", "attack")


def _merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def _read(path: str | Path) -> dict:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"{path} not found (set IOTMON_HOME to the directory holding config.yaml "
                                "and rules/, or pass --config / --rules)")
    if path.suffix == ".toml":  # site configs from before Week 6
        with open(path, "rb") as f:
            return tomllib.load(f)
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_rules(path: str | Path | None = None) -> list[dict]:
    """The rule catalogue, validated: every rule has the required fields and a unique ID and detector."""
    rules = _read(path or DEFAULT_RULES).get("rules") or []
    seen: set[str] = set()
    for r in rules:
        missing = [f for f in RULE_FIELDS if f not in r]
        if missing:
            raise ValueError(f"rule {r.get('id', '?')} is missing {', '.join(missing)}")
        for key in (r["id"], r["detector"]):
            if key in seen:
                raise ValueError(f"duplicate rule id or detector: {key}")
            seen.add(key)
    return rules


def load_config(path: str | Path | None = None, rules: str | Path | None = None) -> dict:
    cfg = _read(DEFAULT_CONFIG)
    catalogue = load_rules(rules)
    cfg["rules"] = catalogue
    cfg["detections"] = {r["detector"]: {"enabled": r.get("enabled", True), **(r.get("settings") or {})}
                         for r in catalogue}
    if path:
        cfg = _merge(cfg, _read(path))
    return cfg
