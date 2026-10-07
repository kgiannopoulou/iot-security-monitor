"""Configuration: built-in defaults (config/default.toml) merged with an
optional user file."""

from __future__ import annotations

import tomllib
from pathlib import Path

DEFAULT_CONFIG = Path(__file__).resolve().parent / "default.toml"


def _merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def load_config(path: str | Path | None = None) -> dict:
    with open(DEFAULT_CONFIG, "rb") as f:
        cfg = tomllib.load(f)
    if path:
        with open(path, "rb") as f:
            cfg = _merge(cfg, tomllib.load(f))
    return cfg
