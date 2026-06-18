from __future__ import annotations

from collections.abc import Callable

from seevie_pri.context import TriageContext


def run(ctx: TriageContext, stages: list[Callable]) -> TriageContext:
    for stage in stages:
        ctx = stage(ctx)
    return ctx
