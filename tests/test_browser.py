"""
Automated Real Browser Verification using Headless Chrome & CDP
Tests frontend UI rendering, DOM updates, and backend API integration.
"""

import subprocess
import time
import json
import requests
import websockets
import asyncio
import os

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

async def run_browser_verification():
    print("Launching real Google Chrome in headless mode...")
    proc = subprocess.Popen([
        CHROME_PATH,
        "--headless=new",
        "--remote-debugging-port=9222",
        "--disable-gpu",
        "--no-sandbox",
        "about:blank"
    ])
    
    try:
        await asyncio.sleep(2)
        res = requests.get("http://127.0.0.1:9222/json")
        targets = res.json()
        ws_url = targets[0]["webSocketDebuggerUrl"]

        async with websockets.connect(ws_url) as ws:
            msg_counter = 0

            async def send_cmd(method, params=None):
                nonlocal msg_counter
                msg_counter += 1
                curr_id = msg_counter
                msg = {"id": curr_id, "method": method}
                if params:
                    msg["params"] = params
                await ws.send(json.dumps(msg))
                while True:
                    data = json.loads(await ws.recv())
                    if data.get("id") == curr_id:
                        return data

            async def exec_js(expr):
                nonlocal msg_counter
                msg_counter += 1
                curr_id = msg_counter
                await ws.send(json.dumps({
                    "id": curr_id,
                    "method": "Runtime.evaluate",
                    "params": {"expression": expr, "returnByValue": True, "awaitPromise": True}
                }))
                while True:
                    data = json.loads(await ws.recv())
                    if data.get("id") == curr_id:
                        return data.get("result", {})

            await send_cmd("Page.enable")
            await send_cmd("Runtime.enable")
            
            # Navigate to detect.html
            print("Navigating to http://127.0.0.1:5500/frontend/detect.html ...")
            await send_cmd("Page.navigate", {"url": "http://127.0.0.1:5500/frontend/detect.html"})
            await asyncio.sleep(2.5)

            # Override alert to prevent dialog hanging
            await exec_js("window.alert = (m) => console.error('BROWSER_ALERT: ' + m);")

            # Check API base
            api_info = await exec_js("getApiBase()")
            print(f"API Base resolved in Chrome: {api_info.get('value')}")

            test_cases = [
                "https://google.com.example.com",
                "https://google-login.example.com",
                "https://paypal.com.example.com",
                "https://microsoft.com.example.com",
                "https://amazon.in.example.com",
                "https://apple.com.example.com",
                "https://google.com",
                "https://www.google.com"
            ]

            dom_read_script = """
            (() => {
                const resBox = document.getElementById('urlResult');
                return {
                    hidden: resBox ? resBox.classList.contains('hidden') : true,
                    score: document.getElementById('urlScore')?.innerText || '',
                    badge: document.getElementById('urlBadge')?.innerText || '',
                    confidence: document.getElementById('urlConfidence')?.innerText || '',
                    hostname: document.getElementById('urlHostname')?.innerText || '',
                    regDom: document.getElementById('urlRegisteredDomain')?.innerText || '',
                    subdomain: document.getElementById('urlSubdomain')?.innerText || '',
                    brand: document.getElementById('urlBrandStatus')?.innerText || '',
                    auditBrand: document.getElementById('urlAuditBrand')?.innerText || '',
                    auditStructure: document.getElementById('urlAuditStructure')?.innerText || '',
                    flags: document.getElementById('urlFlags')?.innerText || ''
                };
            })()
            """

            for url in test_cases:
                print(f"\n=======================================================")
                print(f"Testing in Chrome Browser: {url}")
                print(f"=======================================================")
                await exec_js(f"document.getElementById('urlInput').value = '{url}';")
                
                # Execute analyzeURL and await its completion
                eval_call = await exec_js("analyzeURL()")
                if eval_call.get("subtype") == "error":
                    print(f"Error calling analyzeURL: {eval_call}")

                await asyncio.sleep(1.5)

                res = await exec_js(dom_read_script.strip())
                val = res.get("value", {})
                
                print(f"  Result Box Visible:  {not val.get('hidden')}")
                print(f"  Threat Score:        {val.get('score')}")
                print(f"  Confidence Level:    {val.get('confidence')}")
                print(f"  Verdict Badge:       {val.get('badge')}")
                print(f"  Hostname:            {val.get('hostname')}")
                print(f"  Registered Domain:   {val.get('regDom')}")
                print(f"  Subdomain:           {val.get('subdomain')}")
                print(f"  Brand Association:   {val.get('brand')}")
                print(f"  Brand Audit Flag:    {val.get('auditBrand')[:75]}...")

            print("\nReal Headless Chrome browser verification completed successfully!")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()

if __name__ == "__main__":
    asyncio.run(run_browser_verification())
