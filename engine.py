import hmac
import hashlib
import json
from datetime import datetime
from typing import Dict, Any, List, Set

class ProductionThreatEngine:
    def __init__(self, secret_key: str, domains_filepath: str = "domains.txt"):
        self.secret = secret_key.encode('utf-8')
        self.malicious_domains: Set[str] = self._load_domains(domains_filepath)
        self.flagged_nodes = {"abdellah derissi", "aziz budabouz"}

    def _load_domains(self, filepath: str) -> Set[str]:
        domains = set()
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    clean_line = line.strip().lower()
                    if clean_line and not clean_line.startswith("#"):
                        domains.add(clean_line)
        except FileNotFoundError:
            print(f"[OSTRZEŻENIE] Nie znaleziono pliku {filepath}.")
        return domains

    def evaluate(self, profile: Dict[str, Any], interaction: Dict[str, Any]) -> Dict[str, Any]:
        score = 0.0
        reasons: List[str] = []

        name = profile.get("name", "").strip().lower()
        if name in self.flagged_nodes:
            score += 0.5
            reasons.append(f"Znany bot-node: {name}")

        if profile.get("friends", 100) < 100 and profile.get("avatar", True):
            score += 0.3
            reasons.append("Anomalia metadanych (mało znajomych + domyślny awatar)")

        text = interaction.get("text", "").lower()
        detected = [domain for domain in self.malicious_domains if domain in text]
        
        if detected:
            score += 0.5 * min(len(detected), 2)
            reasons.append(f"Wykryto złośliwe domeny ({len(detected)}): {', '.join(detected)}")

        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "threat_detected": score >= 0.5,
            "threat_score": min(score, 1.0),
            "reasons": reasons,
            "matched_domains": detected
        }

        rep_str = json.dumps(report, sort_keys=True)
        report["hmac_sha256"] = hmac.new(self.secret, rep_str.encode(), hashlib.sha256).hexdigest()
        return report

if __name__ == "__main__":
    engine = ProductionThreatEngine(secret_key="FTIE_SECRET", domains_filepath="domains.txt")
    
    sample_profile = {"name": "Abdellah Derissi", "friends": 68, "avatar": True}
    sample_interaction = {"text": "Kliknij tu: https://wonderluhst.net/artykul"}

    result = engine.evaluate(sample_profile, sample_interaction)
    print(json.dumps(result, indent=4, ensure_ascii=False))
