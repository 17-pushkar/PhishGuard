
import unittest

from detector import analyze_url, analyze_email


class TestPhishGuardURL(unittest.TestCase):

    def test_normal_example_url(self):
        score, findings, assessment = analyze_url(
            "https://example.com"
        )
        self.assertEqual(score, 0)
        self.assertEqual(assessment, "Lower risk")

    def test_http_url_is_flagged(self):
        score, findings, assessment = analyze_url(
            "http://example.com"
        )
        self.assertGreater(score, 0)
        self.assertTrue(
            any("HTTPS" in finding for finding in findings)
        )

    def test_ip_address_is_flagged(self):
        score, findings, assessment = analyze_url(
            "http://192.168.1.10/login"
        )
        self.assertGreaterEqual(score, 25)
        self.assertTrue(
            any("IP address" in finding for finding in findings)
        )

    def test_shortener_is_flagged(self):
        score, findings, assessment = analyze_url(
            "https://bit.ly/example"
        )
        self.assertTrue(
            any("shortening service" in finding for finding in findings)
        )

    def test_empty_url(self):
        score, findings, assessment = analyze_url("")
        self.assertEqual(assessment, "No assessment")


class TestPhishGuardEmail(unittest.TestCase):

    def test_normal_email(self):
        score, findings, assessment = analyze_email(
            "Hi Sam, our meeting is tomorrow at 10 AM."
        )
        self.assertEqual(score, 0)
        self.assertEqual(assessment, "Lower risk")

    def test_urgent_email_is_flagged(self):
        score, findings, assessment = analyze_email(
            "URGENT! Verify your account immediately."
        )
        self.assertGreater(score, 0)
        self.assertTrue(
            any("Urgency" in finding for finding in findings)
        )

    def test_prize_message_is_flagged(self):
        score, findings, assessment = analyze_email(
            "You have won a free gift. Claim your prize."
        )
        self.assertGreater(score, 0)
        self.assertTrue(
            any("Prize" in finding for finding in findings)
        )

    def test_empty_email(self):
        score, findings, assessment = analyze_email("")
        self.assertEqual(assessment, "No assessment")


if __name__ == "__main__":
    unittest.main(verbosity=2)
