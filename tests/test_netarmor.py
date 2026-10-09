"""
Comprehensive End-to-End Test Suite for NetArmor-AI
===================================================
Tests all 5 architectural tiers:
1. ML Pipeline, Heuristics & Feature Extraction
2. FastAPI REST APIs (URL, Email, Smishing, PDF, Upload, Health)
3. Cybersecurity Boundaries (Malicious executables, disguised headers, injections)
4. Chrome Extension Manifest V3 & Integration
5. Firestore Security Rules & Frontend Integrity
"""

import os
import io
import json
import unittest
from pypdf import PdfWriter
from starlette.testclient import TestClient

# Ensure root directory is in sys.path
import sys
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.app import app, extract_url_features, is_trusted_legitimate_domain

class TestNetArmorComprehensive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    # -------------------------------------------------------------
    # TIER 1: Feature Extraction & ML Domain Logic
    # -------------------------------------------------------------
    def test_01_url_feature_extraction_vector(self):
        """Test URL feature extraction generates expected 7-dimensional vector."""
        url = "https://secure-login.bank.example.com/verify@admin"
        features = extract_url_features(url)
        self.assertIsInstance(features, list)
        self.assertEqual(len(features), 7, "Feature vector must contain exactly 7 features")

    def test_02_url_lexical_anomalies(self):
        """Test extraction correctly flags raw IP, @ symbol, and suspicious keywords."""
        ip_url = "http://192.168.1.1/login"
        feats = extract_url_features(ip_url)
        self.assertEqual(feats[2], 1, "Raw IP address must be flagged")
        self.assertEqual(feats[5], 0, "HTTP (insecure) must be 0")
        self.assertEqual(feats[6], 1, "Keyword 'login' must be flagged")

        at_url = "https://legit-site.com@phishing.org/banking"
        feats_at = extract_url_features(at_url)
        self.assertEqual(feats_at[1], 1, "@ obfuscation symbol must be flagged")
        self.assertEqual(feats_at[6], 1, "Keyword 'banking' must be flagged")

    def test_03_trusted_domain_verifier(self):
        """Test domain whitelist correctly recognizes top safe authority domains."""
        self.assertTrue(is_trusted_legitimate_domain("https://google.com"))
        self.assertTrue(is_trusted_legitimate_domain("https://www.google.com/search?q=cyber"))
        self.assertTrue(is_trusted_legitimate_domain("https://github.com/manishpradhan50"))
        self.assertTrue(is_trusted_legitimate_domain("https://en.wikipedia.org/wiki/Phishing"))
        
        # Spoofed domains must NOT pass as trusted
        self.assertFalse(is_trusted_legitimate_domain("http://google.com@evil-attacker.ru"))
        self.assertFalse(is_trusted_legitimate_domain("http://192.168.1.1/google.com"))

    # -------------------------------------------------------------
    # TIER 2: FastAPI REST API Endpoints
    # -------------------------------------------------------------
    def test_04_health_endpoint(self):
        """Verify GET /api/health returns operational status."""
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("status"), "online")
        self.assertIn("NetArmor", data.get("system", ""))

    def test_05_predict_url_safe_authority_site(self):
        """Verify popular authority sites are correctly classified as Safe (eliminating false positives)."""
        safe_urls = [
            "https://google.com",
            "https://github.com",
            "https://wikipedia.org"
        ]
        for url in safe_urls:
            res = self.client.post("/api/predict-url", json={"url": url})
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["verdict"], "Safe / Legitimate")
            self.assertLess(data["risk_percentage"], 20.0, f"{url} should have low risk score")

    def test_06_predict_url_phishing_attack(self):
        """Verify dangerous phishing URL with @ and raw IP is correctly classified as Malicious."""
        malicious_url = "http://192.168.1.100/verify-account@login.ru"
        res = self.client.post("/api/predict-url", json={"url": malicious_url})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["verdict"], "Phishing / Malicious")
        self.assertGreaterEqual(data["risk_percentage"], 50.0)
        self.assertTrue(len(data["flags"]) > 0)

    def test_07_predict_url_validation_rejection(self):
        """Verify empty and whitespace URLs return HTTP 400."""
        res = self.client.post("/api/predict-url", json={"url": "   "})
        self.assertEqual(res.status_code, 400)

    def test_08_predict_email_phishing(self):
        """Verify email NLP scanner flags urgent credential harvesting."""
        phish_email = "URGENT: Your account has been suspended! Click the link below to verify your password immediately or account will be terminated in 24 hours."
        res = self.client.post("/api/predict-email", json={"text": phish_email})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["verdict"], "Phishing / Spam")
        self.assertGreaterEqual(data["risk_percentage"], 50.0)

    def test_09_predict_email_safe(self):
        """Verify email NLP scanner classifies standard conversational email as Safe."""
        safe_email = "Hi team, let's meet tomorrow at 10 AM to discuss the project schedule. Best regards."
        res = self.client.post("/api/predict-email", json={"text": safe_email})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["verdict"], "Safe / Legitimate")
        self.assertLess(data["risk_percentage"], 50.0)

    def test_10_predict_message_smishing(self):
        """Verify mobile SMS/smishing scanner catches OTP/KYC urgency vectors."""
        smish_msg = "URGENT: Your bank account is BLOCKED due to pending KYC. Update OTP at http://bit.ly/bank-auth"
        res = self.client.post("/api/predict-message", json={"message": smish_msg})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["verdict"], "Phishing / Smishing Threat")
        self.assertGreaterEqual(data["risk_percentage"], 50.0)
        self.assertIn("extracted_urls", data)
        self.assertGreater(len(data["extracted_urls"]), 0)

    def test_11_scan_document_valid_pdf(self):
        """Verify PDF document scanner parses valid PDF without errors."""
        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        stream = io.BytesIO()
        writer.write(stream)
        stream.seek(0)

        res = self.client.post("/api/scan-document", files={"file": ("report.pdf", stream, "application/pdf")})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["filename"], "report.pdf")
        self.assertIn("verdict", data)

    def test_12_scan_document_invalid_pdf_rejection(self):
        """Verify PDF document scanner rejects corrupted or disguised PDF file."""
        fake_pdf = io.BytesIO(b"NOT_A_REAL_PDF_CONTENT")
        res = self.client.post("/api/scan-document", files={"file": ("fake.pdf", fake_pdf, "application/pdf")})
        self.assertEqual(res.status_code, 400)

    # -------------------------------------------------------------
    # TIER 3: Security & File Boundary Defenses
    # -------------------------------------------------------------
    def test_13_upload_evidence_valid_image(self):
        """Verify evidence upload accepts authentic PNG images and performs cleanup."""
        # Minimal valid 1x1 PNG image
        png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
        stream = io.BytesIO(png_bytes)
        res = self.client.post("/api/upload-evidence", files={"file": ("screenshot.png", stream, "image/png")})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("status"), "success")
        
        # Cleanup uploaded test artifact
        saved_file = os.path.join(BASE_DIR, "uploads", "evidence", data["filename"])
        if os.path.exists(saved_file):
            try:
                os.remove(saved_file)
            except Exception:
                pass

    def test_14_upload_evidence_blocks_executable_files(self):
        """Verify evidence upload rejects forbidden executable file extensions."""
        bad_files = ["malware.exe", "script.bat", "exploit.sh", "backdoor.py"]
        for fname in bad_files:
            stream = io.BytesIO(b"malicious payload")
            res = self.client.post("/api/upload-evidence", files={"file": (fname, stream, "application/octet-stream")})
            self.assertEqual(res.status_code, 400, f"Expected 400 for {fname}")

    def test_15_upload_evidence_blocks_disguised_executable(self):
        """Verify security boundary blocks executable disguised as .png (magic bytes check)."""
        disguised_exe = io.BytesIO(b"MZ\x90\x00\x03\x00\x00\x00DisguisedWindowsBinary")
        res = self.client.post("/api/upload-evidence", files={"file": ("fake_image.png", disguised_exe, "image/png")})
        self.assertEqual(res.status_code, 400, "Must reject executable disguised as image")

    # -------------------------------------------------------------
    # TIER 4: Client & Chrome Extension Configuration
    # -------------------------------------------------------------
    def test_16_chrome_extension_manifest(self):
        """Verify Chrome Extension manifest strictly complies with Manifest V3 specification."""
        manifest_path = os.path.join(BASE_DIR, "chrome_extension", "manifest.json")
        self.assertTrue(os.path.exists(manifest_path), "manifest.json must exist")
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        self.assertEqual(manifest.get("manifest_version"), 3)
        self.assertIn("activeTab", manifest.get("permissions", []))
        self.assertIn("popup.html", manifest.get("action", {}).get("default_popup", ""))

    # -------------------------------------------------------------
    # TIER 5: Database Security Rules & Frontend Integrity
    # -------------------------------------------------------------
    def test_17_firestore_rules_integrity(self):
        """Verify Firestore security rules enforce authentication constraints."""
        rules_path = os.path.join(BASE_DIR, "firestore.rules")
        self.assertTrue(os.path.exists(rules_path), "firestore.rules must exist")
        with open(rules_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("request.auth != null", content, "Firestore rules must require authentication")
        self.assertIn("complaints", content, "Rules must cover complaints collection")

    def test_18_frontend_assets_present(self):
        """Verify core dashboard and detection frontend files are intact."""
        core_files = [
            "frontend/dashboard.html",
            "frontend/dashboard.js",
            "frontend/admin-dashboard.html",
            "frontend/detect.html",
            "frontend/detect.js",
            "frontend/login.html",
            "frontend/firebase-config.js"
        ]
        for fpath in core_files:
            full_path = os.path.join(BASE_DIR, fpath)
            self.assertTrue(os.path.exists(full_path), f"Missing frontend asset: {fpath}")

    # -------------------------------------------------------------
    # TIER 6: Public Suffix List, Brand Impersonation & Robustness
    # -------------------------------------------------------------
    def test_19_psl_domain_extraction(self):
        """Verify PSL-aware registered domain and subdomain separation."""
        from ml_pipeline.domain_analysis import normalize_url, extract_domain_info

        # Deceptive subdomain under standard domain
        norm1 = normalize_url("https://google.com.example.com")
        info1 = extract_domain_info(norm1)
        self.assertEqual(info1["hostname"], "google.com.example.com")
        self.assertEqual(info1["registered_domain"], "example.com")
        self.assertEqual(info1["subdomain"], "google.com")

        # Multi-part ccTLD (amazon.in, google.co.uk)
        norm2 = normalize_url("https://www.google.co.uk/search")
        info2 = extract_domain_info(norm2)
        self.assertEqual(info2["registered_domain"], "google.co.uk")
        self.assertEqual(info2["subdomain"], "www")

        # Deceptive multi-part ccTLD subdomain
        norm3 = normalize_url("https://amazon.in.example.com")
        info3 = extract_domain_info(norm3)
        self.assertEqual(info3["registered_domain"], "example.com")
        self.assertEqual(info3["subdomain"], "amazon.in")

    def test_20_brand_impersonation_test_urls(self):
        """Verify all 8 test URLs from specification with expected verdicts and risk scoring."""
        # Official domains must be Safe
        official_urls = [
            "https://google.com",
            "https://www.google.com"
        ]
        for u in official_urls:
            res = self.client.post("/api/predict-url", json={"url": u})
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["verdict"], "Safe / Legitimate", f"{u} should be Safe")
            self.assertLess(data["risk_percentage"], 20.0, f"{u} must have low risk percentage")
            self.assertTrue(data.get("is_official_domain"), f"{u} must be flagged as official")

        # Impersonation & deceptive subdomain URLs must be Suspicious / High Risk
        impersonation_urls = [
            "https://google.com.example.com",
            "https://google-login.example.com",
            "https://paypal.com.example.com",
            "https://microsoft.com.example.com",
            "https://amazon.in.example.com",
            "https://apple.com.example.com"
        ]
        for u in impersonation_urls:
            res = self.client.post("/api/predict-url", json={"url": u})
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(
                data["verdict"],
                "Suspicious / Brand Impersonation",
                f"{u} must be flagged as Suspicious / Brand Impersonation"
            )
            self.assertGreaterEqual(
                data["risk_percentage"],
                75.0,
                f"{u} threat probability must be >= 75%"
            )
            self.assertFalse(data.get("is_official_domain"), f"{u} must not be flagged as official")
            self.assertIsNotNone(data.get("brand_detected"), f"{u} should detect impersonated brand")
            self.assertEqual(data.get("registered_domain"), "example.com")

    def test_21_brand_official_domains_not_false_positives(self):
        """Verify legitimate brand domains are recognized and not flagged as impersonations."""
        legit_brands = [
            "https://amazon.in",
            "https://apple.com",
            "https://paypal.com",
            "https://microsoft.com",
            "https://github.com"
        ]
        for u in legit_brands:
            res = self.client.post("/api/predict-url", json={"url": u})
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["verdict"], "Safe / Legitimate", f"{u} must be Safe")
            self.assertLess(data["risk_percentage"], 25.0)
            self.assertTrue(data.get("is_official_domain"))

    def test_22_https_alone_does_not_legitimize_suspicious_url(self):
        """Verify that using HTTPS on suspicious hostnames cannot mark them safe."""
        # Both HTTP and HTTPS versions of google.com.example.com must be flagged
        res_https = self.client.post("/api/predict-url", json={"url": "https://google.com.example.com"})
        res_http = self.client.post("/api/predict-url", json={"url": "http://google.com.example.com"})
        self.assertEqual(res_https.status_code, 200)
        self.assertEqual(res_http.status_code, 200)
        
        self.assertGreaterEqual(res_https.json()["risk_percentage"], 75.0)
        self.assertGreaterEqual(res_http.json()["risk_percentage"], 75.0)
        self.assertEqual(res_https.json()["verdict"], "Suspicious / Brand Impersonation")

    def test_23_encoded_urls_and_normalization(self):
        """Verify URL normalization handles percent-encoding and mixed case safely."""
        # Percent-encoded dot '%2e'
        res = self.client.post("/api/predict-url", json={"url": "https://google%2ecom.example.com"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["hostname"], "google.com.example.com")
        self.assertEqual(data["verdict"], "Suspicious / Brand Impersonation")

        # Upper case URL
        res_case = self.client.post("/api/predict-url", json={"url": "HTTPS://GOOGLE.COM/PATH"})
        self.assertEqual(res_case.status_code, 200)
        self.assertEqual(res_case.json()["verdict"], "Safe / Legitimate")

    def test_24_ip_and_port_edge_cases(self):
        """Verify raw IP addresses and unusual ports are flagged appropriately."""
        res_ip = self.client.post("/api/predict-url", json={"url": "http://192.168.1.1/login"})
        self.assertEqual(res_ip.status_code, 200)
        data_ip = res_ip.json()
        self.assertGreaterEqual(data_ip["risk_percentage"], 75.0)
        self.assertEqual(data_ip["verdict"], "Phishing / Malicious")

        # Non-standard port on safe site
        res_port = self.client.post("/api/predict-url", json={"url": "https://google.com:8443"})
        self.assertEqual(res_port.status_code, 200)
        self.assertEqual(res_port.json()["verdict"], "Safe / Legitimate")

    def test_25_malformed_urls_do_not_crash(self):
        """Verify malformed or invalid inputs return HTTP 400 without crashing."""
        malformed_inputs = [
            "",
            "   ",
            "\t\n",
            "://",
            "http://"
        ]
        for bad_input in malformed_inputs:
            res = self.client.post("/api/predict-url", json={"url": bad_input})
            self.assertIn(res.status_code, [400, 422], f"Input '{bad_input}' must return 400 or 422")

    def test_26_false_positive_prevention_on_normal_sites(self):
        """Verify standard, non-brand websites are not falsely classified as malicious."""
        normal_urls = [
            "https://example.com",
            "https://my-university.edu/student-portal",
            "https://opensource-project.org/docs"
        ]
        for u in normal_urls:
            res = self.client.post("/api/predict-url", json={"url": u})
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["verdict"], "Safe / Legitimate", f"{u} must be Safe / Legitimate")
            self.assertLess(data["risk_percentage"], 35.0, f"{u} risk score must be low")

    # -------------------------------------------------------------
    # TIER 7: Advanced URL Encoding & Multi-Signal Redirect Risk Engine (need.txt Cases A-G)
    # -------------------------------------------------------------
    def test_27_case_a_normal_encoded_url(self):
        """Case A: Normal encoded URL -> Low risk / legitimate. Do NOT flag simply because % exists."""
        url = "https://example.com/search?q=hello%20world"
        res = self.client.post("/api/predict-url", json={"url": url})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get("encoding_detected"), "Percent encoding must be detected")
        self.assertEqual(data.get("decoded_content"), "hello world")
        self.assertEqual(data.get("verdict"), "Safe / Legitimate")
        self.assertLess(data.get("risk_percentage"), 25.0, "Must be low risk")
        self.assertFalse(data.get("double_encoding_detected"))
        self.assertFalse(data.get("external_destination_detected"))

    def test_28_case_b_normal_login(self):
        """Case B: Normal login -> Low risk or moderate risk. Do NOT classify as phishing only because login exists."""
        url = "https://example.com/login"
        res = self.client.post("/api/predict-url", json={"url": url})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("verdict"), "Safe / Legitimate")
        self.assertLess(data.get("risk_percentage"), 35.0, "Login alone must not cause high risk")
        self.assertEqual(data.get("decoded_path"), "/login")
        self.assertIn("login", " ".join(data.get("flags", [])).lower())

    def test_29_case_c_encoded_login(self):
        """Case C: Encoded login -> Decodes to /login. Encoding detected, but encoding alone does not cause high risk."""
        url = "https://example.com/%6c%6f%67%69%6e"
        res = self.client.post("/api/predict-url", json={"url": url})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get("encoding_detected"), "Encoding must be detected")
        self.assertEqual(data.get("decoded_path"), "/login")
        self.assertEqual(data.get("decoded_url"), "https://example.com/login")
        self.assertEqual(data.get("verdict"), "Safe / Legitimate")
        self.assertLess(data.get("risk_percentage"), 35.0, "Encoding alone must not cause high risk")

    def test_30_case_d_encoded_internal_redirect(self):
        """Case D: Encoded internal redirect -> Decoded redirect remains on same domain; not external phishing."""
        url = "https://example.com/login?redirect=%2Faccount%2Fverify"
        res = self.client.post("/api/predict-url", json={"url": url})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get("encoding_detected"))
        self.assertTrue(data.get("encoded_redirect_detected"))
        self.assertFalse(data.get("external_destination_detected"), "Internal redirect must not be external")
        self.assertEqual(data.get("verdict"), "Safe / Legitimate")
        self.assertLess(data.get("risk_percentage"), 35.0)

    def test_31_case_e_encoded_external_redirect(self):
        """Case E: Encoded external redirect -> Decodes to https://google.com, external destination detected, NOT confirmed phishing."""
        url = "https://example.com/verify?next=https%3A%2F%2Fgoogle.com"
        res = self.client.post("/api/predict-url", json={"url": url})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get("encoding_detected"))
        self.assertTrue(data.get("encoded_redirect_detected"))
        self.assertTrue(data.get("external_destination_detected"))
        self.assertEqual(data.get("destination_domain"), "google.com")
        self.assertEqual(data.get("destination_registered_domain"), "google.com")
        self.assertEqual(data.get("verdict"), "Safe / Legitimate")
        self.assertLess(data.get("risk_percentage"), 50.0, "Benign external redirect must not be marked phishing")

    def test_32_case_f_suspicious_external_redirect(self):
        """Case F: Suspicious external redirect -> Decodes redirect, extracts reg dom, subdomain, brand impersonation detected, substantially higher risk (>= 75%)."""
        url = "https://example.com/login?redirect=https%3A%2F%2Fgoogle.com.example.com%2Flogin"
        res = self.client.post("/api/predict-url", json={"url": url})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get("encoding_detected"))
        self.assertTrue(data.get("encoded_redirect_detected"))
        self.assertTrue(data.get("external_destination_detected"))
        self.assertEqual(data.get("destination_domain"), "google.com.example.com")
        self.assertEqual(data.get("destination_registered_domain"), "example.com")
        self.assertEqual(data.get("destination_subdomain"), "google.com")
        self.assertEqual(data.get("destination_brand"), "Google")
        self.assertTrue(data.get("destination_brand_impersonation"), "Must detect brand impersonation in redirect destination")
        self.assertGreaterEqual(data.get("risk_percentage"), 75.0, "Overall risk must be substantially higher")
        self.assertEqual(data.get("verdict"), "Suspicious / Brand Impersonation")

    def test_33_case_g_double_encoded_url(self):
        """Case G: Double encoded URL -> Detect double encoding (2 layers), safely decode to login, do NOT classify as phishing solely because double encoded."""
        url = "https://example.com/%256c%256f%2567%2569%256e"
        res = self.client.post("/api/predict-url", json={"url": url})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get("encoding_detected"))
        self.assertTrue(data.get("double_encoding_detected"), "Double encoding must be detected")
        self.assertEqual(data.get("encoding_layers"), 2, "Must identify exactly 2 encoding layers")
        self.assertEqual(data.get("decoded_path"), "/login")
        self.assertEqual(data.get("verdict"), "Safe / Legitimate", "Double encoding alone on clean domain must not be phishing")
        self.assertLess(data.get("risk_percentage"), 50.0)

    def test_34_categorized_ui_explanation(self):
        """Verify categorized explanation structure across URL Encoding, Authentication, Redirect, Brand, Domain, and Risk."""
        url = "https://example.com/%6c%6f%67%69%6e"
        res = self.client.post("/api/predict-url", json={"url": url})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        cats = data.get("categorized_analysis", {})
        self.assertIn("url_encoding", cats)
        self.assertIn("authentication", cats)
        self.assertIn("redirect_analysis", cats)
        self.assertIn("brand_analysis", cats)
        self.assertIn("domain_analysis", cats)
        self.assertIn("risk_assessment", cats)
        self.assertTrue(any("Percent encoding detected" in s for s in cats["url_encoding"]))
        self.assertTrue(any("Login endpoint detected" in s for s in cats["authentication"]))
        self.assertTrue(any("No external redirect detected" in s for s in cats["redirect_analysis"]))
        self.assertTrue(any("No brand impersonation detected" in s for s in cats["brand_analysis"]))
        self.assertTrue(any("Registered domain: example.com" in s for s in cats["domain_analysis"]))
        self.assertTrue(any("Low Risk" in s for s in cats["risk_assessment"]))

if __name__ == "__main__":
    unittest.main(verbosity=2)


