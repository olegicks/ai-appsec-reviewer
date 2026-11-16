export const LANGUAGES = [
  { value: 'python', label: 'Python', ext: 'py' },
  { value: 'javascript', label: 'JavaScript', ext: 'js' },
  { value: 'typescript', label: 'TypeScript', ext: 'ts' },
  { value: 'java', label: 'Java', ext: 'java' },
  { value: 'cpp', label: 'C++', ext: 'cpp' },
  { value: 'go', label: 'Go', ext: 'go' },
];

export const CONFIG_LANGUAGE = { value: 'config', label: 'Config', ext: 'yaml' };

export const EXAMPLES = [
  {
    id: 'python-sqli',
    label: 'SQL Injection',
    language: 'python',
    code: `import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/user")
def get_user():
    username = request.args.get("name")
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    # User input is formatted straight into the query
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return {"rows": cursor.fetchall()}
`,
  },
  {
    id: 'js-xss',
    label: 'DOM XSS',
    language: 'javascript',
    code: `const params = new URLSearchParams(window.location.search);
const name = params.get('name');

// Untrusted query parameter rendered as HTML
document.getElementById('greeting').innerHTML = 'Hello, ' + name;
`,
  },
  {
    id: 'java-secrets',
    label: 'Hardcoded Secrets',
    language: 'java',
    code: `public class Config {
    private static final String AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
    private static final String DB_PASS = "super_secret_db_123";

    public static String connectionString() {
        return "jdbc:postgresql://prod-db:5432/app?user=admin&password=" + DB_PASS;
    }
}
`,
  },
  {
    id: 'cpp-overflow',
    label: 'Buffer Overflow',
    language: 'cpp',
    code: `#include <cstring>

void copyData(const char *input) {
    char buffer[10];
    // No bounds check on attacker-controlled input
    strcpy(buffer, input);
}
`,
  },
  {
    id: 'python-cmd',
    label: 'Command Injection',
    language: 'python',
    code: `import os
import pickle

def ping(host):
    # host comes from an HTTP form field
    os.system("ping -c 1 " + host)

def load_session(raw_cookie):
    return pickle.loads(raw_cookie)
`,
  },
  {
    id: "smart-grid",
    label: "Smart grid gateway (fictional)",
    language: "python",
    code: "\"\"\"FICTIONAL demo: gateway for the imaginary \"Northfield 110/20 kV\" substation.\n\nDeliberately insecure training sample. Do not deploy.\n\"\"\"\nimport telnetlib\n\nimport paho.mqtt.client as mqtt\nimport requests\nfrom pymodbus.client import ModbusTcpClient\n\nRTU_IP = \"10.40.2.15\"\nMODBUS_PORT = 502\nRTU_USER = \"admin\"\nRTU_PASSWORD = \"admin\"\n\nplc = ModbusTcpClient(RTU_IP, port=MODBUS_PORT)\n\n\ndef on_message(client, userdata, msg):\n    # Operator setpoints arrive over MQTT and go straight to the feeder breaker controller.\n    setpoint = int(msg.payload)\n    plc.write_register(40010, setpoint, slave=1)\n\n\ndef push_to_historian(payload):\n    requests.post(\"https://historian.grid.local/api/ingest\", json=payload, verify=False, timeout=5)\n\n\ndef reset_rtu():\n    session = telnetlib.Telnet(RTU_IP, 23)\n    session.write(RTU_USER.encode() + b\"\\n\" + RTU_PASSWORD.encode() + b\"\\n\")\n\n\nbroker = mqtt.Client(client_id=\"substation-gw\")\nbroker.on_message = on_message\nbroker.connect(\"broker.grid.local\", 1883)\nbroker.subscribe(\"grid/#\")\nbroker.loop_forever()\n",
  },
  {
    id: "dockerfile",
    label: "Dockerfile",
    language: "config",
    code: "FROM python:latest\nARG GITHUB_TOKEN\nENV DB_PASSWORD=SuperSecret123\nADD https://example.com/agent.tar.gz /opt/agent.tar.gz\nRUN curl -fsSL https://get.example.com/install.sh | sh\nCOPY . /app\nCMD [\"python\", \"/app/main.py\"]\n",
  },
  {
    id: "compose",
    label: "docker-compose",
    language: "config",
    code: "services:\n  db:\n    image: postgres:16\n    ports:\n      - \"5432:5432\"\n    environment:\n      POSTGRES_PASSWORD: example-password\n  scada-hmi:\n    image: example/hmi:2.1\n    privileged: true\n    network_mode: host\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n    restart: unless-stopped\n    healthcheck:\n      test: [\"CMD\", \"curl\", \"-f\", \"http://localhost:8080/health\"]\n",
  },
  {
    id: "k8s",
    label: "Kubernetes Deployment",
    language: "config",
    code: "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: substation-gateway\nspec:\n  replicas: 1\n  selector:\n    matchLabels:\n      app: gateway\n  template:\n    metadata:\n      labels:\n        app: gateway\n    spec:\n      hostNetwork: true\n      containers:\n        - name: gateway\n          image: example/gateway:latest\n          securityContext:\n            privileged: true\n            allowPrivilegeEscalation: true\n            runAsNonRoot: false\n",
  },
  {
    id: "requirements",
    label: "requirements.txt",
    language: "config",
    code: "requests==2.19.0\npyyaml==5.3\nflask>=2.0.0\n",
  },
];
