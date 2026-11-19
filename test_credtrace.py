"""CREDTRACE API smoke tests. Requires installed requirements and env vars."""
import os, unittest, secrets
os.environ.setdefault("ADMIN_PASSWORD", "test-admin-password-2026")
os.environ.setdefault("COMPANY_PASSWORD", "test-company-password-2026")
os.environ.setdefault("APP_SECRET", "test-secret-value-long-enough-for-demo-only")
os.environ.setdefault("DATABASE_URL", "sqlite:///./credtrace_test.db")

try:
    from fastapi.testclient import TestClient
    import credtrace_phase1 as c
except Exception as e:
    TestClient = None
    import_error = e

@unittest.skipIf(TestClient is None, "Dependencies not installed: " + str(globals().get("import_error", "unknown")))
class CredTraceSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client=TestClient(c.app)
        r=cls.client.post("/api/login",json={"username":"company","password":os.environ["COMPANY_PASSWORD"]})
        assert r.status_code==200
        cls.company_csrf=r.json().get("csrf")
        r=cls.client.post("/api/company/credentials",json={"label":"unittest synthetic"})
        assert r.status_code==200
        cls.secret=r.json()["secret_once"]
        cls.cid=r.json()["credential_id"]
        cls.device="test-device-"+secrets.token_hex(3)
        r=cls.client.post("/api/login",json={"username":"investigator","password":os.environ["ADMIN_PASSWORD"]})
        assert r.status_code==200

    def test_routes_and_health(self):
        for route in ("/","/company","/attacker","/investigator"):
            self.assertEqual(self.client.get(route).status_code,200)
        self.assertEqual(self.client.get("/health").json()["status"],"ok")

    def test_simulation_actions_and_export_denial(self):
        # Issue a fresh credential because the revocation test intentionally disables its original.
        self.client.post("/api/login",json={"username":"company","password":os.environ["COMPANY_PASSWORD"]})
        fresh=self.client.post("/api/company/credentials",json={"label":"sim action test"}).json()["secret_once"]
        self.client.post("/api/login",json={"username":"investigator","password":os.environ["ADMIN_PASSWORD"]})
        for action in ("VALIDATE","READ_RECORDS","LIST_VENDORS","RESTRICTED_EXPORT"):
            r=self.client.post("/api/sim/action",json={"credential":fresh,"device_id":self.device,"action":action})
            self.assertEqual(r.status_code,200)
            if action=="RESTRICTED_EXPORT": self.assertEqual(r.json()["event"]["outcome"],"DENIED")
            else: self.assertEqual(r.json()["event"]["outcome"],"ALLOWED")

    def test_risk_alerts_and_hash_integrity(self):
        self.assertEqual(self.client.get("/api/investigator/events").status_code,200)
        self.assertEqual(self.client.get("/api/investigator/alerts").status_code,200)
        risk=self.client.get("/api/investigator/risk/"+self.cid).json()
        self.assertGreaterEqual(risk["score"],25)
        self.assertIn("formula",risk)
        self.assertEqual(self.client.get("/api/investigator/integrity").json()["status"],"VERIFIED")
        custody=self.client.get("/api/investigator/custody").json()
        self.assertEqual(custody["integrity"]["status"],"VERIFIED")
        self.assertEqual(self.client.get("/api/investigator/mitre").status_code,200)
        self.assertEqual(self.client.get("/api/investigator/graph").status_code,200)

    def test_revocation_blocks_future_request(self):
        r=self.client.patch(f"/api/investigator/credentials/{self.cid}/REVOKED")
        self.assertEqual(r.status_code,200)
        denied=self.client.post("/api/sim/action",json={"credential":self.secret,"device_id":self.device,"action":"READ_RECORDS"})
        self.assertEqual(denied.status_code,403)


    def test_alert_acknowledge_and_report_pdf(self):
        alerts=self.client.get("/api/investigator/alerts").json()
        if alerts:
            updated=self.client.patch("/api/investigator/alerts/"+alerts[0]["id"],json={"status":"ACKNOWLEDGED","assigned_to":"test-investigator"})
            self.assertEqual(updated.status_code,200)
            self.assertEqual(updated.json()["status"],"ACKNOWLEDGED")
        pdf=self.client.get("/api/investigator/report.pdf")
        self.assertEqual(pdf.status_code,200)
        self.assertEqual(pdf.headers.get("content-type"),"application/pdf")
        self.assertTrue(pdf.content.startswith(b"%PDF"))

    def test_websocket_command_ack(self):
        self.client.post("/api/login",json={"username":"company","password":os.environ["COMPANY_PASSWORD"]})
        fresh=self.client.post("/api/company/credentials",json={"label":"websocket test"}).json()["secret_once"]
        self.client.post("/api/login",json={"username":"investigator","password":os.environ["ADMIN_PASSWORD"]})
        action=self.client.post("/api/sim/action",json={"credential":fresh,"device_id":"ws-test-device","action":"VALIDATE"}).json()
        sid=action["event"]["session_id"]
        token=action["sim_ws_token"]
        with self.client.websocket_connect(f"/ws/simulator/{sid}?token={token}") as websocket:
            ready=websocket.receive_json()
            self.assertEqual(ready["type"],"ready")
            sent=self.client.post("/api/investigator/commands",json={"command":"SHOW_SECURITY_NOTICE","session_id":sid})
            self.assertEqual(sent.status_code,200)
            cmd=websocket.receive_json()
            self.assertEqual(cmd["command"],"SHOW_SECURITY_NOTICE")
            websocket.send_json({"type":"ack","command_id":cmd["id"],"message":"notice displayed"})
        command_rows=self.client.get("/api/investigator/commands").json()
        self.assertTrue(any(row["status"]=="ACKNOWLEDGED" for row in command_rows))

    def test_incident_creation(self):
        r=self.client.post("/api/investigator/incidents",json={"title":"Unit test case","description":"Synthetic test incident","severity":"LOW"})
        self.assertEqual(r.status_code,200)
        self.assertEqual(r.json()["status"],"OPEN")

if __name__=="__main__": unittest.main()
