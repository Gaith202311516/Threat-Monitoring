import re

class LogParser:
    @staticmethod
    def parse_raw_log(raw_text: str) -> dict:
        # استخراج عناوين الـ IP ونوع الحدث
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, raw_text)
        
        src_ip = ips[0] if len(ips) > 0 else "0.0.0.0"
        dst_ip = ips[1] if len(ips) > 1 else "127.0.0.1"
        
        event_type = "unknown"
        severity = "Low"
        
        raw_upper = raw_text.upper()
        if "FAILED LOGIN" in raw_upper:
            event_type = "failed_login"
            severity = "Medium"
        elif "BLOCK" in raw_upper or "PFSENSE" in raw_upper:
            event_type = "firewall_block"
            severity = "High"
        elif "CONNECT" in raw_upper:
            event_type = "connection"
            severity = "Low"

        return {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "event_type": event_type,
            "severity": severity,
            "raw_message": raw_text,
            "parsed_data": {"extracted_ips": ips}
        }