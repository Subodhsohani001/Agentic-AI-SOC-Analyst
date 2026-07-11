from __future__ import annotations

from typing import Any


class IOCFormatter:
    """
    Creates analyst-safe display versions of IOCs.

    Raw IOCs must still be used internally for:
    - reputation checks
    - blocking
    - correlation
    - validation

    Defanged IOCs are only for:
    - terminal output
    - reports
    - dashboards
    - tickets
    """

    @staticmethod
    def defang_ip(ip: str) -> str:
        return ip.replace(".", "[.]")

    @staticmethod
    def defang_domain(domain: str) -> str:
        return domain.replace(".", "[.]")

    @staticmethod
    def defang_url(url: str) -> str:
        defanged = url

        if defanged.lower().startswith("https://"):
            defanged = "hxxps://" + defanged[8:]
        elif defanged.lower().startswith("http://"):
            defanged = "hxxp://" + defanged[7:]

        return defanged.replace(".", "[.]")

    @staticmethod
    def defang_email(email: str) -> str:
        if "@" not in email:
            return email

        username, domain = email.split("@", 1)
        return f"{username}[@]{domain.replace('.', '[.]')}"

    @staticmethod
    def defang_hash(value: str) -> str:
        # Hashes are not clickable, so preserve them unchanged.
        return value

    def format_facts(self, facts: dict[str, list[str]]) -> dict[str, Any]:
        return {
            "ip_addresses": [
                self.defang_ip(value)
                for value in facts.get("ip_addresses", [])
            ],
            "domains": [
                self.defang_domain(value)
                for value in facts.get("domains", [])
            ],
            "urls": [
                self.defang_url(value)
                for value in facts.get("urls", [])
            ],
            "hashes": [
                self.defang_hash(value)
                for value in facts.get("hashes", [])
            ],
            "file_names": list(facts.get("file_names", [])),
            "process_names": list(facts.get("process_names", [])),
            "event_ids": list(facts.get("event_ids", [])),
            "email_addresses": [
                self.defang_email(value)
                for value in facts.get("email_addresses", [])
            ],
        }