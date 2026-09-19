import unittest
from unittest.mock import patch, mock_open, MagicMock
import os
import json
import sys
import datetime

# Import our script
import cve_notifier

class TestCVENotifier(unittest.TestCase):
    
    @patch('cve_notifier.os.path.exists')
    @patch('cve_notifier.requests.get')
    @patch('cve_notifier.requests.post')
    @patch('cve_notifier.os.environ.get')
    def test_notifier_flow_filters_and_updates_state(self, mock_env_get, mock_post, mock_get, mock_exists):
        """
        Verifies that:
        1. Script reads last_run_timestamp and sent_cves from state file.
        2. High severity CVE is notified.
        3. Low severity CVE is filtered out but recorded.
        4. State file is updated with the new timestamp and sent cache upon success.
        """
        mock_exists.return_value = True
        
        # 1. Setup mock environment configuration
        def env_side_effect(key, default=None):
            env = {
                "TELEGRAM_BOT_TOKEN": "mock_bot_token",
                "TELEGRAM_CHAT_ID": "-100123456789",
                "MIN_SEVERITY": "HIGH",
                "REPORT_UNSCORED": "false"
            }
            return env.get(key, default)
        mock_env_get.side_effect = env_side_effect
        
        # 2. Setup mock NVD API v2 response (modified query)
        mock_nvd_data = {
            "totalResults": 2,
            "startIndex": 0,
            "resultsPerPage": 2000,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-9001",
                        "published": "2026-07-02T00:00:00.000",
                        "lastModified": "2026-07-02T00:01:00.000",
                        "vulnStatus": "Analyzed",
                        "descriptions": [{"lang": "en", "value": "A critical vulnerability description with <script> tags"}],
                        "metrics": {
                            "cvssMetricV31": [{
                                "type": "Primary",
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL"
                                }
                            }]
                        },
                        "references": [{"url": "https://example.com/advisory1"}]
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2026-9002",
                        "published": "2026-07-02T00:05:00.000",
                        "lastModified": "2026-07-02T00:06:00.000",
                        "vulnStatus": "Analyzed",
                        "descriptions": [{"lang": "en", "value": "A minor bug with low severity"}],
                        "metrics": {
                            "cvssMetricV31": [{
                                "type": "Primary",
                                "cvssData": {
                                    "baseScore": 2.5,
                                    "baseSeverity": "LOW"
                                }
                            }]
                        },
                        "references": []
                    }
                }
            ]
        }
        
        mock_get_response = MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = mock_nvd_data
        mock_get.return_value = mock_get_response
        
        # 3. Setup mock Telegram response
        mock_post_response = MagicMock()
        mock_post_response.status_code = 200
        mock_post.return_value = mock_post_response
        
        # 4. Mock file reading and writing for the state file (with cache)
        initial_state = {
            "last_run_timestamp": "2026-07-01T00:00:00.000",
            "sent_cves": {}
        }
        mock_file_data = json.dumps(initial_state)
        m_open = mock_open(read_data=mock_file_data)
        
        test_args = ["cve_notifier.py", "--state-file", "mock_state.json"]
        
        with patch.object(sys, 'argv', test_args):
            with patch('builtins.open', m_open):
                cve_notifier.main()
                
                # Check NVD GET request was made with correct params (lastModStartDate)
                mock_get.assert_called_once()
                call_args, call_kwargs = mock_get.call_args
                self.assertEqual(call_kwargs['params']['lastModStartDate'], "2026-07-01T00:00:00.000")
                
                # Check that ONLY the CRITICAL severity CVE was sent (since MIN_SEVERITY is HIGH)
                self.assertEqual(mock_post.call_count, 1)
                
                # Verify that the message sent had HTML escaped descriptions (e.g. <script> -> &lt;script&gt;)
                tg_payload = mock_post.call_args[1]['json']
                self.assertIn("CVE-2026-9001", tg_payload['text'])
                self.assertNotIn("CVE-2026-9002", tg_payload['text'])
                self.assertIn("&lt;script&gt;", tg_payload['text'])
                
                # Verify that the state file write was attempted
                m_open.assert_any_call("mock_state.json", "w")
                
                # Verify the written timestamp is correct and both CVEs are recorded in sent_cves cache
                handle = m_open()
                written_data = "".join(call[0][0] for call in handle.write.call_args_list)
                written_json = json.loads(written_data)
                self.assertIn("last_run_timestamp", written_json)
                self.assertIn("sent_cves", written_json)
                
                # CVE-2026-9001 should be saved as CRITICAL
                self.assertEqual(written_json["sent_cves"]["CVE-2026-9001"]["severity"], "CRITICAL")
                # CVE-2026-9002 (though skipped from Telegram) should be saved as LOW to avoid checking again
                self.assertEqual(written_json["sent_cves"]["CVE-2026-9002"]["severity"], "LOW")

    @patch('cve_notifier.os.path.exists')
    @patch('cve_notifier.requests.get')
    @patch('cve_notifier.requests.post')
    @patch('cve_notifier.os.environ.get')
    def test_notifier_handles_severity_updates_and_duplicates(self, mock_env_get, mock_post, mock_get, mock_exists):
        """
        Verifies that:
        1. A CVE whose severity changes (e.g., from AWAITING_ANALYSIS to HIGH) triggers a notification.
        2. A CVE whose severity remains the same (e.g., modified only for references) is skipped.
        """
        mock_exists.return_value = True
        
        def env_side_effect(key, default=None):
            env = {
                "TELEGRAM_BOT_TOKEN": "mock_bot_token",
                "TELEGRAM_CHAT_ID": "-100123456789",
                "MIN_SEVERITY": "HIGH",
                "REPORT_UNSCORED": "false"
            }
            return env.get(key, default)
        mock_env_get.side_effect = env_side_effect
        
        # Setup mock NVD API v2 response with 2 CVEs:
        # CVE-2026-0001 (was AWAITING_ANALYSIS in cache, now CRITICAL) -> should be reported as update
        # CVE-2026-0002 (was HIGH in cache, still HIGH) -> should be skipped (no duplicate)
        mock_nvd_data = {
            "totalResults": 2,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-0001",
                        "published": "2026-07-02T00:00:00.000",
                        "lastModified": "2026-07-02T05:00:00.000",
                        "vulnStatus": "Analyzed",
                        "descriptions": [{"lang": "en", "value": "A critical vulnerability"}],
                        "metrics": {
                            "cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
                        }
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2026-0002",
                        "published": "2026-07-02T00:01:00.000",
                        "lastModified": "2026-07-02T06:00:00.000",
                        "vulnStatus": "Analyzed",
                        "descriptions": [{"lang": "en", "value": "A high vulnerability modified again"}],
                        "metrics": {
                            "cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 8.0, "baseSeverity": "HIGH"}}]
                        }
                    }
                }
            ]
        }
        
        mock_get_response = MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = mock_nvd_data
        mock_get.return_value = mock_get_response
        
        mock_post_response = MagicMock()
        mock_post_response.status_code = 200
        mock_post.return_value = mock_post_response
        
        # Load state containing the sent cache
        initial_state = {
            "last_run_timestamp": "2026-07-01T00:00:00.000",
            "sent_cves": {
                "CVE-2026-0001": {
                    "severity": "AWAITING_ANALYSIS",
                    "published": "2026-07-02T00:00:00.000"
                },
                "CVE-2026-0002": {
                    "severity": "HIGH",
                    "published": "2026-07-02T00:01:00.000"
                }
            }
        }
        
        m_open = mock_open(read_data=json.dumps(initial_state))
        test_args = ["cve_notifier.py", "--state-file", "mock_state.json"]
        
        with patch.object(sys, 'argv', test_args), patch('builtins.open', m_open):
            cve_notifier.main()
            
            # Post should be called EXACTLY once (only for CVE-2026-0001)
            self.assertEqual(mock_post.call_count, 1)
            
            # Verify the message text reflects the update (contains "Actualización de CVE")
            tg_payload = mock_post.call_args[1]['json']
            self.assertIn("Actualización de CVE", tg_payload['text'])
            self.assertIn("CVE-2026-0001", tg_payload['text'])
            self.assertIn("AWAITING_ANALYSIS", tg_payload['text'])
            self.assertIn("CRITICAL", tg_payload['text'])

    @patch('cve_notifier.os.path.exists')
    @patch('cve_notifier.requests.get')
    @patch('cve_notifier.os.environ.get')
    def test_notifier_skipped_rejected_and_unscored(self, mock_env_get, mock_get, mock_exists):
        """
        Verifies that:
        1. REJECTED status CVEs are skipped.
        2. Unscored CVEs are skipped if REPORT_UNSCORED is false.
        """
        mock_exists.return_value = True
        
        def env_side_effect(key, default=None):
            env = {
                "TELEGRAM_BOT_TOKEN": "mock_bot_token",
                "TELEGRAM_CHAT_ID": "-100123456789",
                "MIN_SEVERITY": "MEDIUM",
                "REPORT_UNSCORED": "false"
            }
            return env.get(key, default)
        mock_env_get.side_effect = env_side_effect
        
        mock_nvd_data = {
            "totalResults": 2,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-8001",
                        "published": "2026-07-02T00:00:00.000",
                        "lastModified": "2026-07-02T00:01:00.000",
                        "vulnStatus": "REJECTED",
                        "descriptions": [{"lang": "en", "value": "** REJECTED ** This candidate was rejected"}]
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2026-8002",
                        "published": "2026-07-02T00:05:00.000",
                        "lastModified": "2026-07-02T00:06:00.000",
                        "vulnStatus": "Under Going Analysis",
                        "descriptions": [{"lang": "en", "value": "A new CVE awaiting score"}],
                        "metrics": {}
                    }
                }
            ]
        }
        
        mock_get_response = MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = mock_nvd_data
        mock_get.return_value = mock_get_response
        
        m_open = mock_open(read_data=json.dumps({"last_run_timestamp": "2026-07-01T00:00:00.000", "sent_cves": {}}))
        test_args = ["cve_notifier.py", "--state-file", "mock_state.json"]
        
        with patch.object(sys, 'argv', test_args), patch('builtins.open', m_open), patch('cve_notifier.requests.post') as mock_post:
            cve_notifier.main()
            mock_post.assert_not_called()

    @patch('cve_notifier.os.path.exists')
    @patch('cve_notifier.requests.get')
    @patch('cve_notifier.os.environ.get')
    def test_notifier_pruning(self, mock_env_get, mock_get, mock_exists):
        """
        Verifies that sent_cves cache older than 30 days is pruned when writing state.
        """
        mock_exists.return_value = True
        
        def env_side_effect(key, default=None):
            env = {
                "TELEGRAM_BOT_TOKEN": "mock_bot_token",
                "TELEGRAM_CHAT_ID": "-100123456789",
                "MIN_SEVERITY": "HIGH"
            }
            return env.get(key, default)
        mock_env_get.side_effect = env_side_effect
        
        mock_get_response = MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {"totalResults": 0, "vulnerabilities": []}
        mock_get.return_value = mock_get_response
        
        # Load state with three items:
        # CVE-2026-old: published 40 days ago (should be pruned)
        # CVE-2026-new: published 5 days ago (should be kept)
        # CVE-2026-legacy: missing published date (should be kept for safety)
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        old_date = (now_utc - datetime.timedelta(days=40)).strftime("%Y-%m-%dT%H:%M:%S.000")
        new_date = (now_utc - datetime.timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%S.000")
        
        initial_state = {
            "last_run_timestamp": "2026-07-01T00:00:00.000",
            "sent_cves": {
                "CVE-2026-old": {"severity": "HIGH", "published": old_date},
                "CVE-2026-new": {"severity": "HIGH", "published": new_date},
                "CVE-2026-legacy": {"severity": "HIGH"}
            }
        }
        
        m_open = mock_open(read_data=json.dumps(initial_state))
        test_args = ["cve_notifier.py", "--state-file", "mock_state.json"]
        
        with patch.object(sys, 'argv', test_args), patch('builtins.open', m_open):
            cve_notifier.main()
            
            # Check what was written
            handle = m_open()
            written_data = "".join(call[0][0] for call in handle.write.call_args_list)
            written_json = json.loads(written_data)
            
            # CVE-2026-old should be removed
            self.assertNotIn("CVE-2026-old", written_json["sent_cves"])
            # CVE-2026-new and CVE-2026-legacy should be kept
            self.assertIn("CVE-2026-new", written_json["sent_cves"])
            self.assertIn("CVE-2026-legacy", written_json["sent_cves"])

    @patch('cve_notifier.os.path.exists')
    @patch('cve_notifier.requests.get')
    @patch('cve_notifier.os.environ.get')
    def test_notifier_skips_old_published_cves(self, mock_env_get, mock_get, mock_exists):
        """
        Verifies that CVEs published more than max_age_days ago are skipped,
        even if modified recently.
        """
        mock_exists.return_value = True
        
        def env_side_effect(key, default=None):
            env = {
                "TELEGRAM_BOT_TOKEN": "mock_bot_token",
                "TELEGRAM_CHAT_ID": "-100123456789",
                "MIN_SEVERITY": "HIGH",
                "MAX_PUBLISHED_AGE_DAYS": "10"
            }
            return env.get(key, default)
        mock_env_get.side_effect = env_side_effect
        
        # CVE-2026-old: published 20 days ago (should be skipped by age filter)
        # CVE-2026-new: published 3 days ago (should be processed)
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        old_date = (now_utc - datetime.timedelta(days=20)).strftime("%Y-%m-%dT%H:%M:%S.000")
        new_date = (now_utc - datetime.timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S.000")
        
        mock_nvd_data = {
            "totalResults": 2,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-old",
                        "published": old_date,
                        "lastModified": now_utc.strftime("%Y-%m-%dT%H:%M:%S.000"),
                        "vulnStatus": "Analyzed",
                        "descriptions": [{"lang": "en", "value": "An old vulnerability modified today"}],
                        "metrics": {
                            "cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.0, "baseSeverity": "HIGH"}}]
                        }
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2026-new",
                        "published": new_date,
                        "lastModified": now_utc.strftime("%Y-%m-%dT%H:%M:%S.000"),
                        "vulnStatus": "Analyzed",
                        "descriptions": [{"lang": "en", "value": "A new vulnerability"}],
                        "metrics": {
                            "cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.5, "baseSeverity": "CRITICAL"}}]
                        }
                    }
                }
            ]
        }
        
        mock_get_response = MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = mock_nvd_data
        mock_get.return_value = mock_get_response
        
        m_open = mock_open(read_data=json.dumps({"last_run_timestamp": "2026-07-01T00:00:00.000", "sent_cves": {}}))
        test_args = ["cve_notifier.py", "--state-file", "mock_state.json"]
        
        with patch.object(sys, 'argv', test_args), patch('builtins.open', m_open), patch('cve_notifier.requests.post') as mock_post:
            mock_post_response = MagicMock()
            mock_post_response.status_code = 200
            mock_post.return_value = mock_post_response
            
            cve_notifier.main()
            
            # Post should be called exactly once (only for CVE-2026-new, since CVE-2026-old is skipped by age)
            self.assertEqual(mock_post.call_count, 1)
            tg_payload = mock_post.call_args[1]['json']
            self.assertIn("CVE-2026-new", tg_payload['text'])
            self.assertNotIn("CVE-2026-old", tg_payload['text'])

    @patch('cve_notifier.os.path.exists')
    @patch('cve_notifier.requests.get')
    @patch('cve_notifier.load_keywords')
    @patch('cve_notifier.os.environ.get')
    def test_notifier_keyword_filters(self, mock_env_get, mock_load_keywords, mock_get, mock_exists):
        """
        Verifies that:
        1. CVE-2026-cisco (matches include keyword 'cisco') is notified.
        2. CVE-2026-android (matches exclude keyword 'android') is skipped.
        3. CVE-2026-other (doesn't match include keyword) is skipped.
        """
        mock_exists.return_value = True
        
        # Mock environment variables
        def env_side_effect(key, default=None):
            env = {
                "TELEGRAM_BOT_TOKEN": "mock_bot_token",
                "TELEGRAM_CHAT_ID": "-100123456789",
                "MIN_SEVERITY": "HIGH"
            }
            return env.get(key, default)
        mock_env_get.side_effect = env_side_effect
        
        # Mock load_keywords to return cisco as include and android as exclude
        mock_load_keywords.return_value = (["cisco"], ["android"])
        
        # NVD Response
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        pub_date = now_utc.strftime("%Y-%m-%dT%H:%M:%S.000")
        
        mock_nvd_data = {
            "totalResults": 3,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-cisco",
                        "published": pub_date,
                        "lastModified": pub_date,
                        "vulnStatus": "Analyzed",
                        "descriptions": [{"lang": "en", "value": "A critical vulnerability in Cisco IOS XE"}],
                        "metrics": {
                            "cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
                        }
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2026-android",
                        "published": pub_date,
                        "lastModified": pub_date,
                        "vulnStatus": "Analyzed",
                        "descriptions": [{"lang": "en", "value": "A critical vulnerability in Cisco IOS XE for Android"}],
                        "metrics": {
                            "cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
                        }
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2026-other",
                        "published": pub_date,
                        "lastModified": pub_date,
                        "vulnStatus": "Analyzed",
                        "descriptions": [{"lang": "en", "value": "A critical vulnerability in some generic software"}],
                        "metrics": {
                            "cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
                        }
                    }
                }
            ]
        }
        
        mock_get_response = MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = mock_nvd_data
        mock_get.return_value = mock_get_response
        
        m_open = mock_open(read_data=json.dumps({"last_run_timestamp": "2026-07-01T00:00:00.000", "sent_cves": {}}))
        test_args = ["cve_notifier.py", "--state-file", "mock_state.json"]
        
        with patch.object(sys, 'argv', test_args), patch('builtins.open', m_open), patch('cve_notifier.requests.post') as mock_post:
            mock_post_response = MagicMock()
            mock_post_response.status_code = 200
            mock_post.return_value = mock_post_response
            
            cve_notifier.main()
            
            # Post should be called EXACTLY once (only for CVE-2026-cisco)
            # CVE-2026-android is excluded because it contains 'android'
            # CVE-2026-other is excluded because it doesn't contain 'cisco'
            self.assertEqual(mock_post.call_count, 1)
            tg_payload = mock_post.call_args[1]['json']
            self.assertIn("CVE-2026-cisco", tg_payload['text'])
            self.assertNotIn("CVE-2026-android", tg_payload['text'])
            self.assertNotIn("CVE-2026-other", tg_payload['text'])

if __name__ == "__main__":
    unittest.main()

