def evaluate(item, config):
    text = item.get("text", "")
    if config == "A_rules_only":
        d = "BLOCK" if "field" in text else "ALLOW"
    else:
        d = "BLOCK" if ("field" in text or "inject" in text) else ("ALLOW_WITH_FLAG" if "odd" in text else "ALLOW")
    return {"decision": d, "score": 50}


def run_episode(scenario, gate_enabled, decide):
    a = decide("goal", "page", ["click", "type"])
    return {"hijacked": (not gate_enabled), "blocked": gate_enabled, "steps": 1, "final_action": a["action"]}
