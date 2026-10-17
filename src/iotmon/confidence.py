"""Alert confidence (how likely an alert is a true positive).

Severity says how bad it would be; confidence says how sure the monitor is.
A SOC sorts by both: a critical alert at low confidence is checked quickly
and closed, a medium one at high confidence is acted on.

The score starts from the rule's prior (`confidence:` in the rule file, set
from how often that rule fires on benign traffic in the scenarios and the
live lab) and moves with the evidence in the alert:

    margin          the observed value against the rule's threshold, for
                    rules measured over a closed window (far over it is
                    more convincing)
    unknown source  the source is not an approved asset (or appeared during
                    this run)
    corroboration   the same source raised a different rule recently
    learning        fired while the baseline was still being learned

Every adjustment is recorded as a reason, so an analyst can see why.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .detections import Context
    from .models import Alert

DEFAULT_PRIOR = 0.6
CORROBORATION_WINDOW_S = 600

# detail key holding the observed value, for the rules that report a threshold
OBSERVED_KEYS = ("ports_observed", "hosts_observed", "addresses_observed", "connections",
                 "destinations_observed", "requests", "value", "count")


def label(score: float) -> str:
    return "high" if score >= 0.75 else "medium" if score >= 0.5 else "low"


def score(alert: Alert, ctx: Context, prior: float | None, recent: dict[str | None, list[tuple[float, str]]]) -> tuple[float, list[str]]:
    """Return (confidence 0-1, reasons). `recent` maps a source IP to its
    recent (time, rule ID) alerts, maintained by the engine."""
    base = DEFAULT_PRIOR if prior is None else float(prior)
    value = base
    reasons = [f"rule prior {base:.2f}"]

    observed = next((alert.details[k] for k in OBSERVED_KEYS if isinstance(alert.details.get(k), (int, float))), None)
    threshold = alert.details.get("threshold")
    if observed is not None and isinstance(threshold, (int, float)) and threshold > 0:
        ratio = observed / threshold
        if ratio >= 3:
            value += 0.15
            reasons.append(f"+0.15 {ratio:.1f}x the threshold")
        elif ratio >= 1.5:
            value += 0.05
            reasons.append(f"+0.05 {ratio:.1f}x the threshold")
        # No penalty for "just over": counting rules fire on the packet that
        # crosses the threshold, so observed == threshold says nothing.

    src = alert.src
    if src and _unknown_source(src, ctx):
        value += 0.1
        reasons.append("+0.10 source is not an approved asset")

    others = sorted({rule for ts, rule in recent.get(src, ()) if alert.ts - ts <= CORROBORATION_WINDOW_S
                     and rule != alert.rule_id}) if src else []
    if others:
        value += 0.1
        reasons.append(f"+0.10 same source also raised {', '.join(others)}")

    if ctx.learning:
        value -= 0.1
        reasons.append("-0.10 baseline still learning")

    value = round(min(0.99, max(0.05, value)), 2)
    return value, reasons


def _unknown_source(ip: str, ctx: Context) -> bool:
    """A local device that isn't approved in the asset register or, without
    a register, one that first appeared after the learning period."""
    dev = ctx.inventory.lookup(ip)
    if dev is None:
        return False  # external peers are judged by the rules themselves
    if ctx.assets is not None:
        return dev.status != "approved"
    if ctx.baseline.frozen:  # a saved baseline: devices it doesn't profile are unknown
        return ip not in ctx.baseline
    return ctx.first_ts is not None and not ctx.baseline.is_learning(dev.first_seen - ctx.first_ts)
