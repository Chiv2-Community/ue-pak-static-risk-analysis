"""Original schema fixture; not engine/game evidence or an alternate evaluator."""

from copy import deepcopy


def dispatch():
    return {"schema-version": 1, "origin": {"asset": "/Game/Owned", "function": "Bind", "offset": 17},
            "opcode": "EX_BindDelegate", "kind": "delegate-binding", "function-name": "Sensitive",
            "receiver": "unknown", "resolution": "possible",
            "candidates": [{"owner": "/Game/Owned.Class", "function": "Sensitive", "provenance": "local-function"}],
            "diagnostics": ["binding-flow-unresolved", "open-world", "receiver-unavailable"],
            "source": "kismet-serialized-v1"}


def callback_dispatches(opcode="EX_BindDelegate"):
    binding, call = dispatch(), dispatch()
    binding["opcode"] = opcode
    call.update(kind="multicast", opcode="EX_CallMulticastDelegate", **{"function-name": None})
    call["origin"]["offset"] = 30
    call["possible-binding-origins"] = [dict(binding["origin"])]
    return [{"evidence": evidence, "possibly-flagged": False, "possibly-forbidden": True}
            for evidence in (binding, call)]


def invalid_callback_dispatches():
    for name in ("duplicate", "direct-only", "missing", "removed-binding", "non-binding", "forward", "cross-function", "cross-asset"):
        items = deepcopy(callback_dispatches())
        binding, call = (d["evidence"] for d in items)
        origin = call["possible-binding-origins"][0]
        if name == "duplicate":
            call["possible-binding-origins"].append(dict(reversed(list(origin.items()))))
        elif name in ("direct-only", "missing"):
            origin["offset"] = 0 if name == "direct-only" else 11
        elif name == "non-binding":
            binding.update(kind="virtual", opcode="EX_VirtualFunction")
        elif name == "removed-binding":
            items = items[1:]
        else:
            key, value = {"forward": ("offset", 31), "cross-function": ("function", "Other"),
                          "cross-asset": ("asset", "/Game/Other")}[name]
            origin[key] = binding["origin"][key] = value
        yield name, items
