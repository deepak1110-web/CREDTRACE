"""Dependency-free structural checks for generated CREDTRACE sources."""
import ast, pathlib, re, unittest, subprocess, shutil, tempfile
SOURCE=pathlib.Path(__file__).with_name("credtrace_phase1.py")
TEXT=SOURCE.read_text(encoding="utf-8")
TREE=ast.parse(TEXT)

class StaticProjectChecks(unittest.TestCase):
    def test_python_parse(self):
        self.assertTrue(TREE)
    def test_required_routes_present(self):
        for route in ('"/"','"/company"','"/attacker"','"/investigator"','"/ws/investigator"','"/ws/simulator/{session_id}"'):
            self.assertIn(route,TEXT)
    def test_advanced_modules_defined(self):
        for phrase in ("def risk_for", "def verify_chain", "def verify_custody_chain", "def report_pdf", "def create_incident", "def set_credential_state", "def mitre", "def graph"):
            self.assertIn(phrase,TEXT)
    def test_pages_embedded(self):
        found={}
        for node in TREE.body:
            if isinstance(node,ast.Assign):
                for target in node.targets:
                    if isinstance(target,ast.Name) and target.id in {"HOME","COMPANY_PAGE","ATTACKER_PAGE","INVESTIGATOR_PAGE"}:
                        found[target.id]=ast.literal_eval(node.value)
        self.assertEqual(set(found),{"HOME","COMPANY_PAGE","ATTACKER_PAGE","INVESTIGATOR_PAGE"})
        for page in found.values():
            self.assertIn("<html",page)
    def test_embedded_javascript_syntax(self):
        node=shutil.which("node")
        if not node: self.skipTest("Node.js not available")
        for node_ast in TREE.body:
            if isinstance(node_ast,ast.Assign):
                for target in node_ast.targets:
                    if isinstance(target,ast.Name) and target.id in {"HOME","COMPANY_PAGE","ATTACKER_PAGE","INVESTIGATOR_PAGE"}:
                        html=ast.literal_eval(node_ast.value).replace("{{","{").replace("}}","}").replace("{STYLE}","").replace("{DEMO_CASE}","CR-26-047").replace("{COMPANY}","Harbor & Finch Freight Pvt. Ltd.")
                        for script in re.findall(r"<script>(.*?)</script>",html,re.S):
                            with tempfile.NamedTemporaryFile("w",suffix=".js",delete=False,encoding="utf-8") as f: f.write(script); path=f.name
                            result=subprocess.run([node,"--check",path],capture_output=True,text=True)
                            self.assertEqual(result.returncode,0,result.stderr)
    def test_no_real_target_integrations(self):
        for forbidden in ("subprocess", "os.system(", "eval(", "exec("):
            self.assertNotIn(forbidden,TEXT)

if __name__=="__main__": unittest.main()
