import time
from collections import defaultdict

BLACKLISTED_IPS = {"192.168.1.50", "10.0.0.99", "185.220.101.5"}

class ThreatDetector:
    # تتبع محاولات الدخول الفاشلة حسب الـ IP والوقت
    failed_logins = defaultdict(list)

    @classmethod
    def calculate_score(cls, source_ip: str, event_type: str) -> tuple[float, str, str]:
        score = 0.0
        reasons = []
        now = time.time()

        # Rule 1: IP في القائمة السوداء (+50)
        if source_ip in BLACKLISTED_IPS:
            score += 50.0
            reasons.append(f"Blacklisted IP ({source_ip})")

        # Rule 2: تكرار محاولات الدخول الفاشلة (+30)
        if event_type in ["failed_login", "login_failed"]:
            cls.failed_logins[source_ip].append(now)
            # احتفاظ بالمحاولات خلال آخر 60 ثانية فقط
            cls.failed_logins[source_ip] = [t for t in cls.failed_logins[source_ip] if now - t <= 60]
            
            if len(cls.failed_logins[source_ip]) >= 5:
                score += 30.0
                reasons.append(f"Brute force attempt ({len(cls.failed_logins[source_ip])} failed logins in 1 min)")

        # Rule 3: فحص المنافذ (+40)
        if event_type in ["port_scan", "unusual_port"]:
            score += 40.0
            reasons.append("Port scanning pattern detected")

        # Rule 4: حظر الحائط الناري (+20)
        if event_type == "firewall_block":
            score += 20.0
            reasons.append("Triggered firewall block rule")

        # تحديد مستوى الخطورة بناءً على النقاط (0-100)
        score = min(score, 100.0)
        if score >= 81:
            severity = "Critical"
        elif score >= 61:
            severity = "High"
        elif score >= 31:
            severity = "Medium"
        else:
            severity = "Low"

        description = " | ".join(reasons) if reasons else "Normal Activity"
        return score, severity, description

    @classmethod
    def analyze_log(cls, log_id: int, source_ip: str, event_type: str, severity: str) -> dict | None:
        score, threat_severity, description = cls.calculate_score(source_ip, event_type)

        # إنشاء تنبيه فقط إذا كانت هناك نقاط تهديد
        if score > 0:
            return {
                "log_id": log_id,
                "threat_type": event_type if event_type != "info" else "Suspicious Behavior",
                "threat_score": score,
                "severity": threat_severity,
                "description": description,
                "is_resolved": False
            }
        return None