def calculate_risk_score(findings):

    module_totals = {}
    total_score = 0

    # Group by module
    for f in findings:
        module = f["module"]
        module_totals.setdefault(module, 0)
        module_totals[module] += f["weight"]

    # Module caps
    MODULE_CAPS = {
        "network": 40,
        "ssl": 30,
        "ssh": 30,
        "http": 25,
        "dns": 20
    }

    # Apply caps
    for module, score in module_totals.items():
        capped = min(score, MODULE_CAPS.get(module, 40))
        total_score += capped

    # Normalize final
    final_score = min(total_score, 100)

    if final_score >= 75:
        level = "CRITICAL"
    elif final_score >= 50:
        level = "HIGH"
    elif final_score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "total_score": round(final_score, 2),
        "risk_level": level
    }
