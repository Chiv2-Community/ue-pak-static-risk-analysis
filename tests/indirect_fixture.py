"""Original schema fixture; not engine/game evidence or an alternate evaluator."""


def dispatch():
    return {"schema-version": 1, "origin": {"asset": "/Game/Owned", "function": "Bind", "offset": 17},
            "opcode": "EX_BindDelegate", "kind": "delegate-binding", "function-name": "Sensitive",
            "receiver": "unknown", "resolution": "possible",
            "candidates": [{"owner": "/Game/Owned.Class", "function": "Sensitive", "provenance": "local-function"}],
            "diagnostics": ["binding-flow-unresolved", "open-world", "receiver-unavailable"],
            "source": "kismet-serialized-v1"}
