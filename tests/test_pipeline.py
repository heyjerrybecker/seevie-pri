from seevie_pri.pipeline import run
from seevie_pri.context import TriageContext


def test_run_applies_stages_in_order():
    ctx = TriageContext()

    def stage_a(ctx):
        ctx.options["a"] = 1
        return ctx

    def stage_b(ctx):
        ctx.options["b"] = ctx.options["a"] + 1
        return ctx

    result = run(ctx, [stage_a, stage_b])
    assert result.options == {"a": 1, "b": 2}


def test_run_with_no_stages():
    ctx = TriageContext()
    result = run(ctx, [])
    assert result is ctx
