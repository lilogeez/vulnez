# Playwright login helper
import json, time
from pathlib import Path
from playwright.sync_api import sync_playwright

def login_and_capture(target, outdir):
    outdir = Path(outdir); outdir.mkdir(parents=True, exist_ok=True)
    auth_file = outdir/"auth.json"
    creds = {}
    if auth_file.exists():
        creds = json.loads(auth_file.read_text())
    else:
        print("[AUTH] Create auth.json in output dir or enter interactively.")
        login_url = input("Login URL: ").strip()
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        uname_sel = input("Username CSS selector: ").strip()
        pass_sel = input("Password CSS selector: ").strip()
        submit_sel = input("Submit selector (optional): ").strip()
        creds={"login_url":login_url,"username":username,"password":password,"username_selector":uname_sel,"password_selector":pass_sel,"submit_selector":submit_sel}
        auth_file.write_text(json.dumps(creds,indent=2))
    cookies_file = outdir/"cookies.json"
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(creds["login_url"], timeout=60000)
            page.fill(creds["username_selector"], creds["username"])
            page.fill(creds["password_selector"], creds["password"])
            if creds.get("submit_selector"): page.click(creds["submit_selector"])
            else: page.keyboard.press("Enter")
            page.wait_for_load_state("networkidle", timeout=20000)
            context = browser.contexts[0]
            cookies = context.cookies()
            cookies_file.write_text(json.dumps(cookies, indent=2))
            browser.close()
        return {"tool_name":"PLAYWRIGHT_AUTH","start_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),"end_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),"result":f"Saved cookies to {cookies_file}","cookies_file":str(cookies_file),"status":"success","error_message":""}
    except Exception as e:
        return {"tool_name":"PLAYWRIGHT_AUTH","start_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),"end_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),"result":"","cookies_file":"","status":"error","error_message":str(e)}
