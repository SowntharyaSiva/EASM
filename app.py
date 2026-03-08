from flask import Flask, render_template, request, redirect, url_for
from utils.target_check import is_valid_target
from scanner.port_scan import scan_ports
from scanner.dns_enum import dns_enum
from scanner.ssl_tls import ssl_scan
from scanner.ssh_check import ssh_check
from risk_engine.rules import apply_rules
from risk_engine.scorer import calculate_risk_score
from scanner.http_headers import check_http_security
import socket

def resolve_target(target):
    try:
        ip = socket.gethostbyname(target)
        return ip
    except:
        return None


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

    resolved_ip = resolve_target(target)

    if not resolved_ip:
        return "Unable to resolve target"

    # ================= SCAN EXECUTION =================
    ports, services = scan_ports(resolved_ip)

    scan_results = {
        "ports": ports,
        "services": services,
        "dns": dns_enum(target),
        "ssl": ssl_scan(target),
        "ssh": ssh_check(target),
        "http": check_http_security(target)  # Keep your original module
    }

    # ================= RULE ENGINE =================
    findings = apply_rules(scan_results)
    risk = calculate_risk_score(findings)

    # ================= MODULE RISK CONTRIBUTION =================
    module_dist = {}
    for f in findings:
        module = f.get("module", "other")
        weight = f.get("weight", 0)
        module_dist[module] = module_dist.get(module, 0) + weight

    # ================= PORT TABLE =================
    port_table = []
    for p in ports:
        service = services.get(p, "unknown")

        # Keep your service-based severity logic
        sev = "LOW"
        if service in ["ftp", "telnet"]:
            sev = "CRITICAL"
        elif service in ["ssh"]:
            sev = "HIGH"
        elif service in ["http"]:
            sev = "MEDIUM"

        port_table.append({
            "number": p,
            "protocol": "TCP",
            "service": service,
            "status": "OPEN",
            "severity": sev,
            "notes": ""
        })

    # ================= SUMMARY =================
    summary = {
        "total_score": risk["total_score"],
        "risk_level": risk["risk_level"],
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in findings if f["severity"] == "LOW")
    }

    # ================= SERVICE DISTRIBUTION =================
    service_dist = {}
    for s in services.values():
        service_dist[s] = service_dist.get(s, 0) + 1

    return render_template(
        "dashboard.html",
        scan_target=target,
        scan_summary=summary,
        scan_ports=port_table,
        service_dist=service_dist,
        module_dist=module_dist,
        dns=scan_results["dns"],
        ssl=scan_results["ssl"],
        ssh=scan_results["ssh"],
        findings=findings,
        http=scan_results["http"],
    )
# ================= RULES PAGE =================
@app.route("/rules")
def rules():
    from risk_engine.rules import RULES
    return render_template("rules.html", rules=RULES)

if __name__ == "__main__":
    app.run(debug=True)
