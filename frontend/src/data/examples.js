export const LANGUAGES = [
  { value: 'python', label: 'Python', ext: 'py' },
  { value: 'javascript', label: 'JavaScript', ext: 'js' },
  { value: 'typescript', label: 'TypeScript', ext: 'ts' },
  { value: 'java', label: 'Java', ext: 'java' },
  { value: 'cpp', label: 'C++', ext: 'cpp' },
  { value: 'go', label: 'Go', ext: 'go' },
];

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
];
