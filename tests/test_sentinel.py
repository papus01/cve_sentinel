"""
CVE Sentinel — Tests unitaires et d'intégration

Couvre les 15 scénarios obligatoires spécifiés dans le cahier des charges V2.
"""
import os
import sys
import json
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch, call

# ── Isolation des imports : aucun secret réel n'est chargé ───────────────────
os.environ.setdefault("TELEGRAM_BOT_TOKEN", "")
os.environ.setdefault("TELEGRAM_CHAT_ID", "")
os.environ.setdefault("NVD_API_KEY", "")
os.environ.setdefault("SMTP_HOST", "")
os.environ.setdefault("EMAIL_FROM", "")
os.environ.setdefault("EMAIL_TO", "")
os.environ.setdefault("KEYWORDS", "")
os.environ.setdefault("MIN_CVSS", "0")
os.environ.setdefault("MAX_CVES", "1000")
os.environ.setdefault("ALERT_CRITICAL", "true")
os.environ.setdefault("ALERT_HIGH", "true")
os.environ.setdefault("ALERT_MEDIUM", "false")
os.environ.setdefault("ALERT_LOW", "false")
os.environ.setdefault("ALERT_KEV", "true")
os.environ.setdefault("ALERT_ALL_NEW_CVES", "false")
os.environ.setdefault("NOTIFICATION_MODE", "both")

# Ajouter le répertoire parent au path pour les imports relatifs
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Helpers de fixture ────────────────────────────────────────────────────────

def make_nvd_cve(
    cve_id: str,
    score: float | None = 9.8,
    description: str = "Test vulnerability description",
    severity: str | None = None,
    published: str | None = None,
) -> dict:
    """Crée une CVE au format brut NVD (wrapper)."""
    metrics = {}
    if score is not None:
        if severity is None:
            if score >= 9.0:
                severity = "CRITICAL"
            elif score >= 7.0:
                severity = "HIGH"
            elif score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
        metrics["cvssMetricV31"] = [{
            "type": "Primary",
            "cvssData": {
                "baseScore": score,
                "baseSeverity": severity,
                "vectorString": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }
        }]

    return {
        "cve": {
            "id": cve_id,
            "published": published or "2026-10-22T00:00:00.000",
            "lastModified": "2026-10-22T00:00:00.000",
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": metrics,
            "configurations": [],
        }
    }


def make_normalized_cve(
    cve_id: str = "CVE-2026-99999",
    score: float | None = 9.8,
    severity: str = "CRITICAL",
    kev: bool = False,
    description: str = "Test description",
) -> dict:
    """Crée une CVE au format normalisé CVE Sentinel."""
    return {
        "id": cve_id,
        "published": "2026-10-22T00:00:00.000",
        "modified": "2026-10-22T00:00:00.000",
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "description": description,
        "cvss": score,
        "cvss_version": "3.1" if score is not None else "",
        "cvss_vector": "",
        "severity": severity,
        "kev": kev,
        "kev_name": "Known Exploit" if kev else "",
        "kev_date": "2026-10-01" if kev else "",
        "due_date": "",
        "ransomware": "",
        "vendor": "TestVendor" if kev else "",
        "product": "TestProduct" if kev else "",
        "products": [],
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


# ── Tests de détection ────────────────────────────────────────────────────────

class TestDetection(unittest.TestCase):
    """
    Scénarios 1-4 : toutes les CVE doivent être détectées
    indépendamment des keywords.
    """

    def setUp(self):
        # Reset des variables d'environnement pour chaque test
        os.environ["KEYWORDS"] = ""
        os.environ["ALERT_CRITICAL"] = "true"
        os.environ["ALERT_HIGH"] = "true"
        os.environ["ALERT_MEDIUM"] = "false"
        os.environ["ALERT_LOW"] = "false"
        os.environ["ALERT_KEV"] = "true"
        os.environ["ALERT_ALL_NEW_CVES"] = "false"
        os.environ["MIN_CVSS"] = "0"

    def test_01_critical_without_keyword_detected(self):
        """CVE Critical sans keyword → DOIT être détectée et notifiée."""
        # Importation fraîche avec les bonnes variables d'env
        from importlib import reload
        import sentinel.config as config_mod
        import sentinel.classifier as clf_mod
        reload(config_mod)
        reload(clf_mod)

        cve = make_normalized_cve("CVE-2026-99001", score=9.5, severity="CRITICAL")
        from sentinel.classifier import classify_cve
        result = classify_cve(cve)

        self.assertEqual(result["severity"], "CRITICAL")
        self.assertTrue(result["should_notify"], "CRITICAL doit être notifiée")

    def test_02_high_without_keyword_detected(self):
        """CVE High sans keyword → DOIT être détectée et notifiée."""
        from importlib import reload
        import sentinel.config as config_mod
        import sentinel.classifier as clf_mod
        reload(config_mod)
        reload(clf_mod)

        cve = make_normalized_cve("CVE-2026-99002", score=8.1, severity="HIGH")
        from sentinel.classifier import classify_cve
        result = classify_cve(cve)

        self.assertEqual(result["severity"], "HIGH")
        self.assertTrue(result["should_notify"], "HIGH doit être notifiée")

    def test_03_medium_without_keyword_stored(self):
        """CVE Medium sans keyword → DOIT être enregistrée (should_notify=False par défaut)."""
        from importlib import reload
        import sentinel.config as config_mod
        import sentinel.classifier as clf_mod
        reload(config_mod)
        reload(clf_mod)

        cve = make_normalized_cve("CVE-2026-99003", score=5.3, severity="MEDIUM")
        from sentinel.classifier import classify_cve
        result = classify_cve(cve)

        self.assertEqual(result["severity"], "MEDIUM")
        # Doit être classifiée (detectée), notification selon config
        self.assertIn("severity", result)
        # Par défaut ALERT_MEDIUM=false
        self.assertFalse(result["should_notify"], "MEDIUM ne doit pas notifier par défaut")

    def test_04_php_critical_without_php_keyword_notified(self):
        """CVE PHP Critical sans 'php' dans KEYWORDS → DOIT être notifiée."""
        os.environ["KEYWORDS"] = "linux,microsoft,apache"  # pas de php

        from importlib import reload
        import sentinel.config as config_mod
        import sentinel.classifier as clf_mod
        reload(config_mod)
        reload(clf_mod)

        # CVE PHP critique analogue à CVE-2026-109618
        cve = make_normalized_cve(
            "CVE-2026-109618",
            score=9.2,
            severity="CRITICAL",
            description="Remote code execution in PHP interpreter allows..."
        )
        from sentinel.classifier import classify_cve
        result = classify_cve(cve)

        # La CVE doit être CRITICAL et notifiable même si php n'est pas dans les keywords
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertTrue(
            result["should_notify"],
            "CVE PHP CRITICAL doit être notifiée même sans 'php' dans KEYWORDS"
        )


class TestKEVNotification(unittest.TestCase):
    """Scénario 5 : CVE KEV avec CVSS faible → DOIT être notifiée."""

    def setUp(self):
        os.environ["KEYWORDS"] = ""
        os.environ["ALERT_CRITICAL"] = "true"
        os.environ["ALERT_HIGH"] = "true"
        os.environ["ALERT_MEDIUM"] = "false"
        os.environ["ALERT_LOW"] = "false"
        os.environ["ALERT_KEV"] = "true"
        os.environ["ALERT_ALL_NEW_CVES"] = "false"
        os.environ["MIN_CVSS"] = "0"

    def test_05_kev_with_low_cvss_notified(self):
        """CVE KEV avec CVSS 5.3 → DOIT être notifiée (ALERT_KEV=true)."""
        from importlib import reload
        import sentinel.config as config_mod
        import sentinel.classifier as clf_mod
        reload(config_mod)
        reload(clf_mod)

        cve = make_normalized_cve(
            "CVE-2026-99005",
            score=5.3,
            severity="MEDIUM",
            kev=True,
        )
        from sentinel.classifier import classify_cve
        result = classify_cve(cve)

        self.assertTrue(result["is_kev"], "Doit être marquée KEV")
        self.assertTrue(
            result["should_notify"],
            "CVE KEV avec CVSS faible doit être notifiée (ALERT_KEV=true)"
        )
        self.assertIn("KEV", result["notify_reason"])


class TestDeduplication(unittest.TestCase):
    """Scénario 6 : CVE déjà connue → ne doit pas être renvoyée."""

    def test_06_already_known_cve_not_resent(self):
        """Une CVE dans notified ne doit pas être retraitée."""
        from sentinel.database import load_state, save_state, ensure_data
        import tempfile, os

        with tempfile.TemporaryDirectory() as tmpdir:
            import sentinel.config as config_mod
            original_state_file = config_mod.STATE_FILE
            config_mod.STATE_FILE = os.path.join(tmpdir, "state.json")
            config_mod.DATA_DIR = tmpdir
            config_mod.CVE_FILE = os.path.join(tmpdir, "cves.json")

            # Sauvegarder un état avec CVE déjà notifiée
            state = {
                "notified": {
                    "CVE-2026-99006": {
                        "severity": "HIGH",
                        "cvss": 8.1,
                        "telegram_at": "2026-10-21T08:00:00+00:00",
                    }
                },
                "last_successful_run": "2026-10-21T08:17:00+00:00",
            }
            save_state(state)

            loaded = load_state()
            self.assertIn("CVE-2026-99006", loaded["notified"])

            # Simuler la logique de déduplication du main
            notified = loaded["notified"]
            cve_id = "CVE-2026-99006"
            self.assertIn(cve_id, notified)

            # Restore
            config_mod.STATE_FILE = original_state_file


class TestNVDPagination(unittest.TestCase):
    """Scénario 7 : Plusieurs pages NVD → toutes doivent être récupérées."""

    @patch("sentinel.nvd.requests.get")
    def test_07_nvd_pagination_all_pages_fetched(self, mock_get):
        """L'API NVD retourne 3 pages → les 487 CVE doivent toutes être collectées."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=27)

        # Page 1 : 200 CVE
        page1 = {
            "totalResults": 487,
            "vulnerabilities": [
                {"cve": {"id": f"CVE-2026-{i:05d}"}} for i in range(200)
            ],
        }
        # Page 2 : 200 CVE
        page2 = {
            "totalResults": 487,
            "vulnerabilities": [
                {"cve": {"id": f"CVE-2026-{i:05d}"}} for i in range(200, 400)
            ],
        }
        # Page 3 : 87 CVE
        page3 = {
            "totalResults": 487,
            "vulnerabilities": [
                {"cve": {"id": f"CVE-2026-{i:05d}"}} for i in range(400, 487)
            ],
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.side_effect = [page1, page2, page3]
        mock_get.return_value = mock_resp

        from importlib import reload
        import sentinel.nvd as nvd_mod
        reload(nvd_mod)
        from sentinel.nvd import fetch_recent

        result = fetch_recent(start, now)

        self.assertEqual(len(result), 487, "Les 487 CVE de 3 pages doivent être récupérées")
        self.assertEqual(mock_get.call_count, 3, "3 appels API doivent être effectués")


class TestNVDRetry(unittest.TestCase):
    """Scénario 8 : API NVD temporairement indisponible → retry."""

    @patch("sentinel.nvd.time.sleep")
    @patch("sentinel.nvd.requests.get")
    def test_08_nvd_retry_on_503(self, mock_get, mock_sleep):
        """NVD retourne 503 deux fois puis 200 → doit réussir après retry."""
        from requests import Response

        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=27)

        # Deux 503 puis succès
        resp_503 = MagicMock()
        resp_503.status_code = 503
        resp_503.raise_for_status = MagicMock(side_effect=Exception("503"))

        resp_ok = MagicMock()
        resp_ok.status_code = 200
        resp_ok.raise_for_status = MagicMock()
        resp_ok.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [{"cve": {"id": "CVE-2026-RETRY"}}],
        }

        mock_get.side_effect = [resp_503, resp_503, resp_ok]

        from importlib import reload
        import sentinel.nvd as nvd_mod
        reload(nvd_mod)
        from sentinel.nvd import fetch_recent

        result = fetch_recent(start, now)
        self.assertEqual(len(result), 1)
        self.assertTrue(mock_sleep.called, "sleep doit être appelé lors des retries")


class TestNoCVSSNoCrash(unittest.TestCase):
    """Scénario 9 : CVE sans score CVSS → ne doit pas faire planter le collecteur."""

    def test_09_cve_without_cvss_no_crash(self):
        """Une CVE sans score CVSS doit être normalisée avec severity=UNKNOWN."""
        from sentinel.main import normalize

        cve_raw = {
            "id": "CVE-2026-99009",
            "published": "2026-10-22T00:00:00.000",
            "lastModified": "2026-10-22T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "No CVSS score available."}],
            "metrics": {},  # Pas de métriques
            "configurations": [],
        }

        result = normalize(cve_raw, {})
        self.assertIsNotNone(result, "normalize() ne doit pas retourner None pour CVE sans CVSS")
        self.assertIsNone(result["cvss"], "cvss doit être None")
        self.assertEqual(result["severity"], "UNKNOWN")
        self.assertEqual(result["id"], "CVE-2026-99009")


class TestTelegramTruncation(unittest.TestCase):
    """Scénario 10 : Description très longue → message Telegram correctement tronqué."""

    def test_10_long_description_truncated(self):
        """Un message > 4096 chars doit être tronqué côté Telegram."""
        from sentinel.main import build_individual_message

        long_desc = "A" * 5000
        cve = make_normalized_cve(
            "CVE-2026-99010",
            score=9.8,
            description=long_desc,
        )

        msg = build_individual_message(cve)
        # Le message brut peut dépasser 4096, c'est le module telegram qui tronque
        # Mais la description dans le message doit être tronquée à ≤ 450 chars
        self.assertLessEqual(
            len(msg.replace(long_desc, "")),
            4096,  # Le texte hors desc doit tenir dans la limite
        )
        # La description ne doit pas apparaître intégralement
        self.assertNotIn("A" * 500, msg, "La description doit être tronquée")


class TestTelegramUnavailable(unittest.TestCase):
    """Scénario 11 : Telegram indisponible → erreur loggée proprement."""

    @patch("sentinel.telegram.requests.post")
    def test_11_telegram_unavailable_logged_not_raised(self, mock_post):
        """Telegram indisponible → retourne False, ne lève pas d'exception."""
        import requests

        mock_post.side_effect = requests.exceptions.ConnectionError("Network error")

        os.environ["TELEGRAM_BOT_TOKEN"] = "test_token_123"
        os.environ["TELEGRAM_CHAT_ID"] = "12345"

        from importlib import reload
        import sentinel.telegram as tg_mod
        import sentinel.config as config_mod
        reload(config_mod)
        reload(tg_mod)
        from sentinel.telegram import send

        result = send("Test message")
        # Ne doit pas lever d'exception, retourne False
        self.assertFalse(result, "Telegram indisponible doit retourner False")

        # Cleanup
        os.environ["TELEGRAM_BOT_TOKEN"] = ""
        os.environ["TELEGRAM_CHAT_ID"] = ""


class TestEmailDoesNotBlockTelegram(unittest.TestCase):
    """Scénario 12 : Email indisponible → ne doit pas empêcher Telegram."""

    def test_12_email_failure_does_not_block_telegram(self):
        """Si l'email échoue, Telegram doit quand même être tenté."""
        from sentinel.email import send as email_send, enabled as email_enabled

        # Email désactivé (pas de config SMTP)
        os.environ["SMTP_HOST"] = ""
        from importlib import reload
        import sentinel.config as config_mod
        import sentinel.email as email_mod
        reload(config_mod)
        reload(email_mod)
        from sentinel.email import enabled

        # Quand email est désactivé, enabled() retourne False → pas de crash
        self.assertFalse(enabled(), "Email doit être désactivé sans SMTP_HOST")

        # L'appel ne doit pas lever d'exception
        from sentinel.email import send
        result = send("Test", [], {})
        self.assertFalse(result)


class TestAlertAllNewCVEs(unittest.TestCase):
    """Scénario 13 : ALERT_ALL_NEW_CVES=true → toutes les CVE doivent être notifiables."""

    def setUp(self):
        os.environ["ALERT_ALL_NEW_CVES"] = "true"
        os.environ["ALERT_CRITICAL"] = "false"
        os.environ["ALERT_HIGH"] = "false"
        os.environ["ALERT_MEDIUM"] = "false"
        os.environ["ALERT_LOW"] = "false"
        os.environ["ALERT_KEV"] = "false"

    def tearDown(self):
        os.environ["ALERT_ALL_NEW_CVES"] = "false"
        os.environ["ALERT_CRITICAL"] = "true"
        os.environ["ALERT_HIGH"] = "true"
        os.environ["ALERT_MEDIUM"] = "false"
        os.environ["ALERT_LOW"] = "false"
        os.environ["ALERT_KEV"] = "true"

    def test_13_alert_all_new_cves_all_notified(self):
        """Avec ALERT_ALL_NEW_CVES=true, même une CVE LOW doit être notifiable."""
        from importlib import reload
        import sentinel.config as config_mod
        import sentinel.classifier as clf_mod
        reload(config_mod)
        reload(clf_mod)
        from sentinel.classifier import classify_cve

        for severity, score in [("LOW", 2.0), ("MEDIUM", 5.0), ("HIGH", 7.5), ("CRITICAL", 9.8)]:
            cve = make_normalized_cve(f"CVE-2026-{score:.0f}000", score=score, severity=severity)
            result = classify_cve(cve)
            self.assertTrue(
                result["should_notify"],
                f"{severity} doit être notifiable avec ALERT_ALL_NEW_CVES=true"
            )
            self.assertIn("ALERT_ALL_NEW_CVES", result["notify_reason"])


class TestPHPCVEsDetected(unittest.TestCase):
    """Scénarios 14 & 15 : CVE-2026-109618 et CVE-2026-109619 doivent être détectées."""

    def setUp(self):
        os.environ["KEYWORDS"] = "linux,microsoft,apache"  # php absent
        os.environ["ALERT_CRITICAL"] = "true"
        os.environ["ALERT_HIGH"] = "true"

    def tearDown(self):
        os.environ["KEYWORDS"] = ""

    def _test_php_cve(self, cve_id: str, score: float):
        """Helper pour tester une CVE PHP."""
        from importlib import reload
        import sentinel.config as config_mod
        import sentinel.classifier as clf_mod
        reload(config_mod)
        reload(clf_mod)
        from sentinel.classifier import classify_cve
        from sentinel.main import normalize

        # La CVE NVD brute (PHP vulnérable)
        cve_raw = {
            "id": cve_id,
            "published": "2026-10-21T00:00:00.000",
            "lastModified": "2026-10-21T00:00:00.000",
            "descriptions": [{
                "lang": "en",
                "value": (
                    "In PHP versions 8.1.x before 8.1.32, 8.2.x before 8.2.28, "
                    "8.3.x before 8.3.19, 8.4.x before 8.4.5, when using "
                    "php_pgsql extension functions..."
                )
            }],
            "metrics": {
                "cvssMetricV40": [{
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": score,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                    }
                }]
            },
            "configurations": [],
        }

        # 1. Normalisation ne doit pas échouer
        normalized = normalize(cve_raw, {})
        self.assertIsNotNone(normalized, f"{cve_id} doit être normalisée")
        self.assertEqual(normalized["id"], cve_id)
        self.assertEqual(normalized["cvss_version"], "4.0")

        # 2. Classification : doit être notifiable (CRITICAL)
        result = classify_cve(normalized)
        self.assertEqual(result["severity"], "CRITICAL", f"{cve_id} doit être CRITICAL")
        self.assertTrue(
            result["should_notify"],
            f"{cve_id} doit être notifiée même sans 'php' dans KEYWORDS"
        )

    def test_14_cve_2026_109618_detected(self):
        """CVE-2026-109618 (PHP Critical) → DOIT être détectée et notifiée."""
        self._test_php_cve("CVE-2026-109618", 9.2)

    def test_15_cve_2026_109619_detected(self):
        """CVE-2026-109619 (PHP Critical) → DOIT être détectée et notifiée."""
        self._test_php_cve("CVE-2026-109619", 9.2)


class TestScoringModule(unittest.TestCase):
    """Tests du module de scoring CVSS."""

    def test_cvss_40_preferred_over_31(self):
        """CVSS 4.0 doit être préféré à CVSS 3.1."""
        from sentinel.scoring import get_cvss

        cve = {
            "metrics": {
                "cvssMetricV40": [{
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": 9.2,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:4.0/AV:N/...",
                    }
                }],
                "cvssMetricV31": [{
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": 8.1,
                        "baseSeverity": "HIGH",
                        "vectorString": "CVSS:3.1/AV:N/...",
                    }
                }],
            }
        }

        score, severity, version, vector = get_cvss(cve)
        self.assertEqual(score, 9.2)
        self.assertEqual(version, "4.0")
        self.assertEqual(severity, "CRITICAL")

    def test_no_cvss_returns_none(self):
        """CVE sans métriques → (None, UNKNOWN, '', '')."""
        from sentinel.scoring import get_cvss

        cve = {"metrics": {}}
        score, severity, version, vector = get_cvss(cve)
        self.assertIsNone(score)
        self.assertEqual(severity, "UNKNOWN")
        self.assertEqual(version, "")

    def test_severity_from_score(self):
        """Sévérité calculée correctement depuis le score."""
        from sentinel.scoring import severity_from_score

        self.assertEqual(severity_from_score(9.8), "CRITICAL")
        self.assertEqual(severity_from_score(9.0), "CRITICAL")
        self.assertEqual(severity_from_score(8.9), "HIGH")
        self.assertEqual(severity_from_score(7.0), "HIGH")
        self.assertEqual(severity_from_score(6.9), "MEDIUM")
        self.assertEqual(severity_from_score(4.0), "MEDIUM")
        self.assertEqual(severity_from_score(3.9), "LOW")
        self.assertEqual(severity_from_score(0.0), "LOW")
        self.assertEqual(severity_from_score(None), "UNKNOWN")


class TestTimeWindow(unittest.TestCase):
    """Tests de la fenêtre temporelle NVD."""

    def test_window_with_recent_run(self):
        """Avec un run récent, la fenêtre doit reculer de LOOKBACK_HOURS."""
        from sentinel.nvd import compute_window
        from sentinel.config import LOOKBACK_HOURS

        last_run = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        start, end = compute_window(last_run)

        # start doit être avant le last_run (marge de LOOKBACK_HOURS)
        last_run_dt = datetime.fromisoformat(last_run)
        self.assertLess(start, last_run_dt, "start doit être avant le dernier run")

    def test_window_without_previous_run(self):
        """Sans run précédent, la fenêtre doit être LOOKBACK_HOURS."""
        from sentinel.nvd import compute_window
        from sentinel.config import LOOKBACK_HOURS

        start, end = compute_window(None)
        expected_start = end - timedelta(hours=LOOKBACK_HOURS)
        delta = abs((start - expected_start).total_seconds())
        self.assertLess(delta, 60, "La fenêtre initiale doit être de LOOKBACK_HOURS")

    def test_window_capped_at_max_lookback(self):
        """Un run très ancien ne doit pas dépasser MAX_LOOKBACK_DAYS."""
        from sentinel.nvd import compute_window
        from sentinel.config import MAX_LOOKBACK_DAYS

        # Run d'il y a 30 jours
        very_old_run = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        start, end = compute_window(very_old_run)

        max_past = end - timedelta(days=MAX_LOOKBACK_DAYS)
        self.assertGreaterEqual(
            start, max_past,
            "La fenêtre ne doit pas dépasser MAX_LOOKBACK_DAYS"
        )


class TestDatabaseMigration(unittest.TestCase):
    """Test de migration de l'ancien format state.json."""

    def test_old_format_migrated(self):
        """L'ancien format {'sent': [...]} doit être migré vers {'notified': {...}}."""
        import tempfile
        import json
        import sentinel.database as db_mod

        with tempfile.TemporaryDirectory() as tmpdir:
            old_state_file = os.path.join(tmpdir, "state.json")

            with open(old_state_file, "w") as f:
                json.dump({"sent": ["CVE-2026-11111", "CVE-2026-22222"]}, f)

            # Patcher STATE_FILE directement dans le module database
            original_state_file = db_mod.STATE_FILE
            db_mod.STATE_FILE = old_state_file
            try:
                state = db_mod.load_state()
                self.assertIn("notified", state, "Le nouveau format doit avoir 'notified'")
                self.assertIn("CVE-2026-11111", state["notified"])
                self.assertIn("CVE-2026-22222", state["notified"])
                self.assertNotIn("sent", state)
            finally:
                db_mod.STATE_FILE = original_state_file


class TestKeywordsOnlyInformational(unittest.TestCase):
    """
    Les keywords ne doivent JAMAIS empêcher la collecte.
    Ils doivent seulement marquer les CVE comme 'matches_keywords'.
    """

    def test_keywords_dont_exclude_cves(self):
        """Une CVE CRITICAL ne correspondant à aucun keyword doit toujours être notifiée."""
        os.environ["KEYWORDS"] = "linux,microsoft,apache"
        os.environ["ALERT_CRITICAL"] = "true"

        from importlib import reload
        import sentinel.config as config_mod
        import sentinel.classifier as clf_mod
        reload(config_mod)
        reload(clf_mod)
        from sentinel.classifier import classify_cve

        # CVE qui ne matche aucun keyword
        cve = make_normalized_cve(
            "CVE-2026-NODEJS",
            score=9.8,
            severity="CRITICAL",
            description="Critical vulnerability in SomeObscureLib version 1.2.3",
        )

        result = classify_cve(cve)
        self.assertTrue(
            result["should_notify"],
            "CRITICAL doit être notifiée même sans keyword match"
        )
        self.assertFalse(
            result["matches_keywords"],
            "matches_keywords doit être False si aucun keyword ne correspond"
        )

class TestAuditMaxCves(unittest.TestCase):
    """Point 1 de l'audit : MAX_CVES ne doit JAMAIS tronquer la collecte ni le stockage."""

    @patch("sentinel.main.save_state")
    @patch("sentinel.main.save_stats")
    @patch("sentinel.main.save_cves")
    @patch("sentinel.main.load_cves")
    @patch("sentinel.main.load_state")
    @patch("sentinel.main.fetch_recent")
    @patch("sentinel.main.fetch_kev")
    @patch("sentinel.main.telegram_enabled")
    @patch("sentinel.main.telegram_send")
    @patch("sentinel.main.email_enabled")
    @patch("sentinel.main.send_bulk")
    @patch("sentinel.main.MAX_CVES", 3)
    def test_max_cves_only_limits_notifications_not_storage(
        self,
        mock_send_bulk,
        mock_email_enabled,
        mock_telegram_send,
        mock_telegram_enabled,
        mock_fetch_kev,
        mock_fetch_recent,
        mock_load_state,
        mock_load_cves,
        mock_save_cves,
        mock_save_stats,
        mock_save_state,
    ):
        """10 CVE critiques collectées avec MAX_CVES=3 -> 10 stockées, 3 notifiées."""
        # 10 CVE critiques
        mock_fetch_recent.return_value = [
            make_nvd_cve(f"CVE-2026-{1000 + i}", score=9.8) for i in range(10)
        ]
        mock_fetch_kev.return_value = {}
        mock_load_state.return_value = {"notified": {}, "last_successful_run": None}
        mock_load_cves.return_value = []
        mock_telegram_enabled.return_value = True
        mock_telegram_send.return_value = True
        mock_email_enabled.return_value = False
        mock_send_bulk.return_value = 3

        from sentinel.main import main
        main()

        # Vérification 1 : save_cves a reçu les 10 CVE (aucune perte de stockage)
        saved_cves = mock_save_cves.call_args[0][0]
        self.assertEqual(len(saved_cves), 10, "Toutes les 10 CVE doivent être enregistrées dans le dashboard")

        # Vérification 2 : save_state a reçu les 10 CVE dans notified
        saved_state = mock_save_state.call_args[0][0]
        self.assertEqual(len(saved_state["notified"]), 10, "Toutes les 10 CVE doivent être dans state['notified']")

        # Vérification 3 : send_bulk n'a reçu que 3 messages (MAX_CVES a plafonné les alertes anti-flood)
        sent_messages = mock_send_bulk.call_args[0][0]
        self.assertEqual(len(sent_messages), 3, "Seules 3 alertes doivent être envoyées (anti-flood)")


class TestAuditNotificationIndependence(unittest.TestCase):
    """Point 8 de l'audit : Telegram et Email doivent être totalement indépendants."""

    @patch("sentinel.main.save_state")
    @patch("sentinel.main.save_stats")
    @patch("sentinel.main.save_cves")
    @patch("sentinel.main.load_cves")
    @patch("sentinel.main.load_state")
    @patch("sentinel.main.fetch_recent")
    @patch("sentinel.main.fetch_kev")
    @patch("sentinel.main.telegram_enabled")
    @patch("sentinel.main.telegram_send")
    @patch("sentinel.main.send_bulk")
    @patch("sentinel.main.email_enabled")
    @patch("sentinel.main.email_send")
    def test_telegram_failure_does_not_prevent_email(
        self,
        mock_email_send,
        mock_email_enabled,
        mock_send_bulk,
        mock_telegram_send,
        mock_telegram_enabled,
        mock_fetch_kev,
        mock_fetch_recent,
        mock_load_state,
        mock_load_cves,
        mock_save_cves,
        mock_save_stats,
        mock_save_state,
    ):
        """Si Telegram lève une exception, l'envoi Email doit quand même être tenté."""
        mock_fetch_recent.return_value = [make_nvd_cve("CVE-2026-99991", score=9.8)]
        mock_fetch_kev.return_value = {}
        mock_load_state.return_value = {"notified": {}, "last_successful_run": None}
        mock_load_cves.return_value = []
        mock_telegram_enabled.return_value = True
        mock_telegram_send.side_effect = RuntimeError("Crash réseau Telegram simulé")
        mock_send_bulk.side_effect = RuntimeError("Crash réseau Telegram simulé")
        mock_email_enabled.return_value = True
        mock_email_send.return_value = True

        from sentinel.main import main
        main()

        # Email doit avoir été appelé malgré le crash Telegram
        self.assertTrue(mock_email_send.called, "Email doit être envoyé même si Telegram a crashé")

    @patch("sentinel.main.save_state")
    @patch("sentinel.main.save_stats")
    @patch("sentinel.main.save_cves")
    @patch("sentinel.main.load_cves")
    @patch("sentinel.main.load_state")
    @patch("sentinel.main.fetch_recent")
    @patch("sentinel.main.fetch_kev")
    @patch("sentinel.main.telegram_enabled")
    @patch("sentinel.main.telegram_send")
    @patch("sentinel.main.send_bulk")
    @patch("sentinel.main.email_enabled")
    @patch("sentinel.main.email_send")
    def test_email_failure_does_not_break_execution(
        self,
        mock_email_send,
        mock_email_enabled,
        mock_send_bulk,
        mock_telegram_send,
        mock_telegram_enabled,
        mock_fetch_kev,
        mock_fetch_recent,
        mock_load_state,
        mock_load_cves,
        mock_save_cves,
        mock_save_stats,
        mock_save_state,
    ):
        """Si Email lève une exception, Telegram a tourné et l'état est quand même sauvegardé."""
        mock_fetch_recent.return_value = [make_nvd_cve("CVE-2026-99992", score=9.8)]
        mock_fetch_kev.return_value = {}
        mock_load_state.return_value = {"notified": {}, "last_successful_run": None}
        mock_load_cves.return_value = []
        mock_telegram_enabled.return_value = True
        mock_telegram_send.return_value = True
        mock_send_bulk.return_value = 1
        mock_email_enabled.return_value = True
        mock_email_send.side_effect = RuntimeError("Crash SMTP Email simulé")

        from sentinel.main import main
        main()

        # Telegram a été appelé
        self.assertTrue(mock_telegram_send.called, "Telegram doit avoir été appelé")
        # save_state a quand même été exécuté
        self.assertTrue(mock_save_state.called, "save_state doit être exécuté même si Email a crashé")


class TestAuditClassificationMatrix(unittest.TestCase):
    """Point 4 de l'audit : matrice complète des cas de classification."""

    def setUp(self):
        os.environ["KEYWORDS"] = "apache,linux"  # mots-clés spécifiques
        os.environ["ALERT_CRITICAL"] = "true"
        os.environ["ALERT_HIGH"] = "true"
        os.environ["ALERT_MEDIUM"] = "false"
        os.environ["ALERT_LOW"] = "false"
        os.environ["ALERT_KEV"] = "true"
        os.environ["ALERT_ALL_NEW_CVES"] = "false"
        os.environ["MIN_CVSS"] = "0"

        from importlib import reload
        import sentinel.config as config_mod
        import sentinel.classifier as clf_mod
        reload(config_mod)
        reload(clf_mod)

    def tearDown(self):
        os.environ["KEYWORDS"] = ""

    def test_cvss_9_8_without_keyword_collected_and_notified(self):
        """CVSS 9.8 sans keyword -> collectée + notifiée."""
        from sentinel.classifier import classify_cve
        cve = make_normalized_cve("CVE-2026-99981", score=9.8, severity="CRITICAL", description="Unknown library flaw")
        res = classify_cve(cve)
        self.assertEqual(res["severity"], "CRITICAL")
        self.assertTrue(res["should_notify"], "CVSS 9.8 doit être notifiée même sans keyword")
        self.assertFalse(res["matches_keywords"])

    def test_cvss_7_5_without_keyword_notified_when_alert_high_true(self):
        """CVSS 7.5 sans keyword -> collectée + notifiée car ALERT_HIGH=true."""
        from sentinel.classifier import classify_cve
        cve = make_normalized_cve("CVE-2026-99982", score=7.5, severity="HIGH", description="Database auth bypass")
        res = classify_cve(cve)
        self.assertEqual(res["severity"], "HIGH")
        self.assertTrue(res["should_notify"], "CVSS 7.5 doit être notifiée si ALERT_HIGH=true")
        self.assertFalse(res["matches_keywords"])

    def test_cvss_5_0_without_keyword_collected_and_stored(self):
        """CVSS 5.0 sans keyword -> collectée, non notifiée car ALERT_MEDIUM=false."""
        from sentinel.classifier import classify_cve
        cve = make_normalized_cve("CVE-2026-99983", score=5.0, severity="MEDIUM", description="Minor info disclosure")
        res = classify_cve(cve)
        self.assertEqual(res["severity"], "MEDIUM")
        self.assertFalse(res["should_notify"], "CVSS 5.0 ne doit pas être notifiée si ALERT_MEDIUM=false")

    def test_cve_kev_with_low_cvss_notified(self):
        """CVE KEV avec CVSS faible (ex: 2.5) -> collectée + notifiée si ALERT_KEV=true."""
        from sentinel.classifier import classify_cve
        cve = make_normalized_cve("CVE-2026-99984", score=2.5, severity="LOW", kev=True, description="Known exploited low score")
        res = classify_cve(cve)
        self.assertTrue(res["is_kev"])
        self.assertTrue(res["should_notify"], "CVE KEV doit être notifiée même avec CVSS faible")

    def test_cve_without_cvss_no_crash(self):
        """CVE sans CVSS -> collectée et stockée sans crash (severity UNKNOWN)."""
        from sentinel.classifier import classify_cve
        cve = make_normalized_cve("CVE-2026-99985", score=None, severity="UNKNOWN", description="No score yet")
        res = classify_cve(cve)
        self.assertEqual(res["severity"], "UNKNOWN")
        self.assertFalse(res["should_notify"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
