from flask import Flask, render_template, request, redirect, url_for
from utils.target_check import is_valid_target
from scanner.port_scan import scan_ports
from scanner.dns_enum import dns_enum
from scanner.ssl_tls import ssl_scan
from scanner.ssh_check import ssh_check
from risk_engine.rules import apply_rules
from risk_engine.scorer import calculate_risk_score

app = Flask(__name__)


# ================= HOME PAGE =================
@app.route("/", methods=["GET", "POST"])
def index():
    error = None

    if request.method == "POST":
        target = request.form["target"]

        if not is_valid_target(target):
            error = "Invalid or private IP"
            return render_template("index.html", error=error)

        # Redirect to dashboard route
        return redirect(url_for("dashboard", target=target))

    return render_template("index.html", error=error)


# ================= DASHBOARD PAGE =================
@app.route("/dashboard/<target>")
def dashboard(target):

    if not is_valid_target(target):
        return "Invalid target"

    # Perform scans
    scan_results = {}
    scan_results["ports"], scan_results["services"] = scan_ports(target)
    scan_results["dns"] = dns_enum(target)
    scan_results["ssl"] = ssl_scan(target)
    scan_results["ssh"] = ssh_check(target)

    # Apply rules & calculate risk
    findings = apply_rules(scan_results)
    risk = calculate_risk_score(findings)

    # Port details
    scan_ports_details = []
    for port_num in scan_results["ports"]:
        scan_ports_details.append({
            "number": port_num,
            "protocol": "TCP",
            "service": scan_results["services"].get(port_num, "unknown"),
            "status": "OPEN",
            "severity": "LOW",
            "notes": ""
        })

    # Summary counts
    summary = {
        "total_score": risk.get("total_score", 0),
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in findings if f["severity"] == "LOW")
    }

    # Service distribution
    service_dist = {}
    for service_name in scan_results["services"].values():
        service_dist[service_name] = service_dist.get(service_name, 0) + 1

    return render_template(
        "dashboard.html",
        scan_target=target,
        scan_summary=summary,
        scan_ports=scan_ports_details,
        service_dist=service_dist
    )


# ================= RULES PAGE =================
@app.route("/rules")
def rules():
    findings = apply_rules({})
    return render_template("rules.html", findings=findings)


if __name__ == "__main__":
    app.run(debug=True)
