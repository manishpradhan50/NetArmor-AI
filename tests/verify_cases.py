"""
Verification script for Cases A through G under need.txt specification.
"""
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
import unittest
from backend.app import app
from starlette.testclient import TestClient

client = TestClient(app)

cases = [
    ("Case A", "https://example.com/search?q=hello%20world"),
    ("Case B", "https://example.com/login"),
    ("Case C", "https://example.com/%6c%6f%67%69%6e"),
    ("Case D", "https://example.com/login?redirect=%2Faccount%2Fverify"),
    ("Case E", "https://example.com/verify?next=https%3A%2F%2Fgoogle.com"),
    ("Case F", "https://example.com/login?redirect=https%3A%2F%2Fgoogle.com.example.com%2Flogin"),
    ("Case G", "https://example.com/%256c%256f%2567%2569%256e"),
]

for name, u in cases:
    res = client.post("/api/predict-url", json={"url": u})
    data = res.json()
    print(f"=== {name}: {u} ===")
    print(f"  Risk: {data.get('risk_percentage')}% | Verdict: {data.get('verdict')}")
    print(f"  Encoding: detected={data.get('encoding_detected')}, layers={data.get('encoding_layers')}, double={data.get('double_encoding_detected')}")
    print(f"  Decoded: url={data.get('decoded_url')}, path={data.get('decoded_path')}, query={data.get('decoded_query')}")
    print(f"  Redirect: ext_detected={data.get('external_destination_detected')}, dest_dom={data.get('destination_domain')}, dest_reg={data.get('destination_registered_domain')}, dest_sub={data.get('destination_subdomain')}, dest_brand={data.get('destination_brand')}, dest_brand_impers={data.get('destination_brand_impersonation')}")
    print(f"  Flags: {data.get('flags')}")
    print()
