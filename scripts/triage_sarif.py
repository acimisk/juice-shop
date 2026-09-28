import json
import sys
from datetime import datetime
from pathlib import Path

SARIF_FILE = "semgrep-results.sarif"
IGNORE_FILE = "security-ignore.json"

def load_json(filepath):
    path = Path(filepath)
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def run_triage():
    sarif_data = load_json(SARIF_FILE)
    if not sarif_data:
        print(f"[!] {SARIF_FILE} bulunamadi.")
        sys.exit(1)

    ignore_data = load_json(IGNORE_FILE) or {"ignored_rules": []}
    
    valid_ignores = {}
    today = datetime.now().date()
    
    for item in ignore_data.get("ignored_rules", []):
        rule_id = item.get("rule_id")
        reason = item.get("reason", "Neden belirtilmedi")
        expires_str = item.get("expires_at")
        
        expires_date = datetime.strptime(expires_str, "%Y-%m-%d").date() if expires_str else None
        
        if expires_date and today > expires_date:
            print(f"⚠️ [EXPIRED TECH DEBT] '{rule_id}' icin taninan muafiyet suresi DOLDU ({expires_str})! Duzeltilmesi gerekiyor.")
        else:
            valid_ignores[rule_id] = {"reason": reason, "expires_at": expires_str}

    runs = sarif_data.get("runs", [])
    if not runs:
        print("[*] Taramada calistirilmis kural bulunamadi.")
        sys.exit(0)

    rules_dict = {}
    for r in runs[0].get("tool", {}).get("driver", {}).get("rules", []):
        rule_id = r.get("id")
        level = r.get("defaultConfiguration", {}).get("level", "warning")
        rules_dict[rule_id] = level

    results = runs[0].get("results", [])
    print(f"[*] Toplam {len(results)} Semgrep bulgusu analiz ediliyor...\n")

    blocking_findings = []
    ignored_count = 0

    for res in results:
        rule_id = res.get("ruleId")
        message = res.get("message", {}).get("text", "")
        
        level = res.get("level", rules_dict.get(rule_id, "warning"))
        
        loc = res.get("locations", [{}])[0].get("physicalLocation", {})
        file_path = loc.get("artifactLocation", {}).get("uri", "unknown")
        line = loc.get("region", {}).get("startLine", "?")

        if rule_id in valid_ignores:
            ignored_count += 1
            continue

        if level == "error":
            blocking_findings.append({
                "rule": rule_id,
                "file": f"{file_path}:{line}",
                "message": message
            })

    if ignored_count > 0:
        print(f"🛡️  [MUTED] {ignored_count} bulgu gecerli muafiyet listesi sayesinde atlandi.")

    if blocking_findings:
        print("\n" + "="*80)
        print(f"❌ PIPELINE BLOKLANDI! {len(blocking_findings)} Adet Kritik (ERROR) Seviye Acik Tespit Edildi.")
        print("="*80)
        for b in blocking_findings:
            print(f"  • Kural   : {b['rule']}")
            print(f"  • Konum   : {b['file']}")
            print(f"  • Detay   : {b['message'][:120]}...\n")
        print("="*80)
        print("Gelistirici Notu: Ya kodu guvenli hale getirin ya da security-ignore.json icine gerekceyle ekleyin.")
        sys.exit(1)
    else:
        print("✅ Pipeline Gecti! Bloklayici kritik zafiyet bulunmuyor.")
        sys.exit(0)

if __name__ == "__main__":
    run_triage()
