from log_analyzer import analyze_logs

result = analyze_logs("sample_security.log")

print("\n===== SECURITY LOG ANALYSIS =====")
print("\nStatistics:")

for name, value in result["statistics"].items():
    print(f"{name}: {value}")

print("\nAlerts:")

for alert in result["alerts"]:
    print(f"\nTitle: {alert['title']}")
    print(f"Severity: {alert['severity']}")
    print(f"Source IP: {alert['source']}")
    print(f"Description: {alert['description']}")
    print(f"Recommendation: {alert['recommendation']}")