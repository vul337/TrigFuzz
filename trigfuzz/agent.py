"""Progressive-prompting agent.

The paper's §3.1 describes an interactive loop: the LLM is shown the
vulnerable function first, and whenever it writes a line like

    Need the content of function(s): foo, bar

the agent looks up the bodies of `foo` and `bar` in a prebuilt
dictionary and sends them back.  This is what the `ledfuzz` prototype
lacks - its LLM driver just runs a single shot.

The function dictionary is built ahead of time by whatever means the
caller prefers (ctags, tree-sitter, SVF, or a simple grep).  We accept
it as a plain `dict[str, str]` so the agent stays decoupled from the
static-analysis back-end.
"""

from __future__ import annotations

import re
from typing import Callable

from .llm_client import LLMClient
from .prompts import build_user_turn
from .tcu import TCU, parse_tcu_output


_NEED_RE = re.compile(
    r"Need the content of function\(s\)\s*:\s*(.+)", re.IGNORECASE
)

# Hard cap on interactive rounds so a confused model cannot loop forever.
# Three is enough to resolve typical Magma targets; the paper reports ~1.4
# rounds average.
MAX_ROUNDS = 5


def generate_tcus(
    *,
    report: dict,
    seed_source: dict[str, str],
    func_dict: dict[str, str],
    llm: LLMClient | None = None,
) -> list[TCU]:
    """Run one full agent session.

    `seed_source` is the initial set of source slices (typically just
    the vulnerable function).  `func_dict` maps function name to its
    numbered source; the agent pulls from here on demand.
    """
    llm = llm or LLMClient()
    gathered = dict(seed_source)
    messages = [{"role": "user", "content": build_user_turn(report, gathered)}]

    for _ in range(MAX_ROUNDS):
        reply = llm.query(messages)
        need = _NEED_RE.search(reply)
        if not need:
            # Final answer - extract the tuples.
            return parse_tcu_output(reply)

        # The model asked for more source.  Resolve, append, loop.
        wanted = [n.strip() for n in need.group(1).split(",") if n.strip()]
        added = {}
        for name in wanted:
            body = func_dict.get(name)
            if body is not None:
                added[f"(function) {name}"] = body

        messages.append({"role": "assistant", "content": reply})
        if added:
            # Feed only the new slices to keep the context short.
            messages.append({
                "role": "user",
                "content": "Here are the requested function bodies:\n\n"
                           + "\n\n".join(f"{k}:\n{v}" for k, v in added.items())
                           + "\n\nPlease finish the TCU tuples.",
            })
        else:
            messages.append({
                "role": "user",
                "content": "I don't have definitions for those functions - "
                           "please proceed with the information available.",
            })

    # If we fell out of the loop without a tuple-bearing reply, return
    # whatever the parser can salvage from the last attempt.
    return parse_tcu_output(messages[-1]["content"] if messages else "")


# ---------------------------------------------------------------------------
# TC Validation samples the agent `k` times (k=3 in the paper) and picks
# the best candidate using dynamic triggering validation (validation.py).
# We expose a small convenience wrapper for that.
# ---------------------------------------------------------------------------

def sample_candidates(k: int = 3, **kwargs) -> list[list[TCU]]:
    return [generate_tcus(**kwargs) for _ in range(k)]
