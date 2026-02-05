def calculate_risk_score(findings):
    total = sum(f["weight"] for f in findings)

    if total >= 90:
        level = "CRITICAL"
    elif total >= 60:
        level = "HIGH"
    elif total >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "total_score": total,
        "risk_level": level
    }
