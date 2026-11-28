const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync, existsSync, mkdtempSync, writeFileSync, rmSync, mkdirSync, chmodSync, statSync } = require('node:fs');
const { resolve, join } = require('node:path');
const { spawnSync } = require('node:child_process');
const { tmpdir } = require('node:os');

const ROOT = resolve(__dirname, '..');

function read(relPath) {
  return readFileSync(resolve(ROOT, relPath), 'utf8');
}

function runPython(code, extraArgs = []) {
  for (const bin of ['python3', 'python']) {
    const res = spawnSync(bin, ['-c', code, ...extraArgs], {
      cwd: ROOT,
      encoding: 'utf8',
    });
    if (!res.error || res.error.code !== 'ENOENT') {
      return res;
    }
  }
  throw new Error('Neither python3 nor python is available in PATH');
}

function hasRealBash() {
  const res = spawnSync('bash', ['-c', 'command -v awk >/dev/null && command -v sqlite3 >/dev/null'], {
    encoding: 'utf8',
  });
  return res.status === 0;
}

test('setup-mailserver.sh replaces sed -i with literal awk ENVIRON + atomic temp file, validates args, sets ownership, passes -- to mail, and clears SMTP_USER/SMTP_PASSWORD', () => {
  const script = read('deploy/setup-mailserver.sh');
  const setEnvMatch = script.match(/set_env\(\)\s*\{[\s\S]*?\n\}/);
  assert.ok(setEnvMatch, 'set_env function must exist');
  const setEnvBody = setEnvMatch[0];

  assert.equal(/\bsed\s+-i\b/.test(setEnvBody), false, 'set_env must not use sed -i');
  assert.match(setEnvBody, /\bawk\b/, 'set_env must use awk');
  assert.match(setEnvBody, /ENVIRON/, 'set_env must pass key/value via ENVIRON');
  assert.match(setEnvBody, /mktemp/, 'set_env must use an atomic temp file via mktemp');
  assert.match(setEnvBody, /\bmv\b/, 'set_env must atomically move temp file into place');

  // Strict validation of CLI flags
  assert.match(script, /MAIL_HOSTNAME.*=~|valid_domain.*MAIL_HOSTNAME|valid_host.*MAIL_HOSTNAME/, 'must strictly validate --hostname');
  assert.match(script, /FROM.*=~|valid_email.*FROM/, 'must strictly validate --from');
  assert.match(script, /PUBLIC_URL.*=~|valid_url.*PUBLIC_URL/, 'must strictly validate --public-url');
  assert.match(script, /SERVER_IP.*=~|valid_ipv4.*SERVER_IP/, 'must strictly validate --ip');
  assert.match(script, /TEST_TO.*=~|valid_email.*TEST_TO/, 'must strictly validate --test-to');

  // Option injection guard in mail invocation
  assert.match(script, /mail\s+[^\n]*--\s+"\$TEST_TO"/, 'mail must pass -- before "$TEST_TO"');

  // Ownership matching parent dir / SUDO_USER + chmod 600
  assert.match(script, /SUDO_USER/, 'must handle SUDO_USER ownership for SERES_ENV');
  assert.match(script, /chown/, 'must set ownership on SERES_ENV');
  assert.match(script, /chmod\s+600/, 'must enforce chmod 600 on SERES_ENV');

  // Clear SMTP_USER / SMTP_PASSWORD for unauthenticated local Postfix
  assert.match(script, /SMTP_USER/, 'must clear/remove SMTP_USER for local Postfix');
  assert.match(script, /SMTP_PASSWORD/, 'must clear/remove SMTP_PASSWORD for local Postfix');
});

test('setup-mailserver.sh set_env/remove_env behavior handles special characters literally when bash is available', { skip: !hasRealBash() }, () => {
  const script = read('deploy/setup-mailserver.sh');
  const dir = mkdtempSync(join(tmpdir(), 'seres-mail-'));
  try {
    const envFile = join(dir, '.env');
    writeFileSync(envFile, 'SMTP_USER=olduser\nSMTP_PASSWORD=oldpass\nKEEP=1\nMAIL_FROM=old');
    // Extract functions from setup-mailserver.sh up to "# ------------------------------------------------------------ SereS .env" helpers
    const setEnvFn = script.match(/set_env\(\)\s*\{[\s\S]*?\n\}/)?.[0] || '';
    const removeEnvFn = script.match(/(?:remove_env|unset_env|clear_env)\(\)\s*\{[\s\S]*?\n\}/)?.[0] || '';
    assert.ok(setEnvFn && removeEnvFn, 'both set_env and remove_env helpers must exist');

    const cmd = `
      set -euo pipefail
      ${setEnvFn}
      ${removeEnvFn}
      set_env "${envFile.replace(/\\/g, '/')}" MAIL_FROM '"SereS & Co | \\1 <no-reply@example.com>"'
      set_env "${envFile.replace(/\\/g, '/')}" NEW_KEY 'a&b|c\\1$HOME'
      ${removeEnvFn.match(/^([a-z_]+)\(/)[1]} "${envFile.replace(/\\/g, '/')}" SMTP_USER
      ${removeEnvFn.match(/^([a-z_]+)\(/)[1]} "${envFile.replace(/\\/g, '/')}" SMTP_PASSWORD
    `;
    const res = spawnSync('bash', ['-c', cmd], { encoding: 'utf8' });
    assert.equal(res.status, 0, res.stderr);
    const content = readFileSync(envFile, 'utf8');
    assert.match(content, /^MAIL_FROM="SereS & Co \| \\1 <no-reply@example\.com>"$/m);
    assert.match(content, /^NEW_KEY=a&b\|c\\1\$HOME$/m);
    assert.equal(/^SMTP_USER=/m.test(content), false);
    assert.equal(/^SMTP_PASSWORD=/m.test(content), false);
    assert.match(content, /^KEEP=1$/m);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('install.sh hardens coturn, NodeSource TLS, /etc/turnserver.conf creation, pm2 secret handling & permissions, and reverse proxy docs', () => {
  const script = read('deploy/install.sh');

  assert.match(script, /--proto\s+'=https'\s+--tlsv1\.2/, 'NodeSource curl must require HTTPS and TLS 1.2');
  assert.match(script, /TURN_MAX_PORT=50160/, 'relay port range must expand to 49160-50160');
  assert.match(script, /^user-quota=6$/m, 'user-quota must be lowered to 6');
  assert.match(script, /^no-tcp-relay$/m, 'coturn config must enable no-tcp-relay');
  assert.match(script, /^no-loopback-peers$/m, 'coturn config must enable no-loopback-peers');
  assert.match(script, /64:ff9b::-64:ff9b::ffff:ffff/, 'coturn must deny NAT64 64:ff9b::/96');
  assert.match(script, /240\.0\.0\.0-255\.255\.255\.255/, 'coturn must deny 240.0.0.0-255.255.255.255');
  assert.match(script, /192\.0\.2\.0/, 'coturn must deny RFC 5737 TEST-NET-1');
  assert.match(script, /198\.51\.100\.0/, 'coturn must deny RFC 5737 TEST-NET-2');
  assert.match(script, /203\.0\.113\.0/, 'coturn must deny RFC 5737 TEST-NET-3');
  assert.match(script, /2001:db8::/, 'coturn must deny RFC 3849 2001:db8::/32');
  assert.match(script, /denied-peer-ip=\$[A-Za-z_]+/, 'coturn must dynamically deny host public IPs');
  assert.match(script, /install\s+-m\s+640\s+-o\s+root\s+-g\s+turnserver/, 'must create /etc/turnserver.conf with install -m 640 -o root -g turnserver before writing secret');

  assert.equal(/^\s*export\s+[^\n]*SERES_PM2_TURN_SECRET=/m.test(script), false, 'SERES_PM2_TURN_SECRET must not be exported into the shell');
  assert.match(script, /chmod\s+700\s+["']?\$RUN_HOME\/\.pm2["']?/, 'must chmod 700 ~/.pm2');
  assert.match(script, /chmod\s+600\s+["']?\$RUN_HOME\/\.pm2\/dump\.pm2["']?/, 'must chmod 600 ~/.pm2/dump.pm2');
  assert.match(script, /CF-Connecting-IP/, 'install.sh notes must document clearing CF-Connecting-IP for Nginx/Caddy');
});

test('deploy/backup/backup.sh and Dockerfile enforce umask 077, chmod 600, positive int validation, mktemp+trap, sqlite3 timeout, signal-trapped sleep, and non-root container', () => {
  const backupSh = read('deploy/backup/backup.sh');
  const dockerfile = read('deploy/backup/Dockerfile');

  assert.match(backupSh, /\bumask\s+077\b/);
  assert.match(backupSh, /\bchmod\s+600\b/);
  assert.match(backupSh, /\bmktemp\b/);
  assert.match(backupSh, /\btrap\b/);
  assert.match(backupSh, /sqlite3\s+-cmd\s+"\.timeout\s+15000"/);
  assert.match(backupSh, /sleep\s+3600\s*&/);
  assert.match(backupSh, /\bwait\s+"?\$!?/);
  assert.match(backupSh, /-lt\s+1|-ge\s+1|positive/i, 'must validate DAYS and KEEP as positive integers >= 1');

  assert.match(dockerfile, /^COPY\s+--chmod=755\s+backup\.sh\b/m);
  assert.match(dockerfile, /^USER\s+1000:1000\b/m);
});

test('backup.sh validates DAYS/KEEP >= 1 and sets 0600 permissions on backups when bash+sqlite3 are available', { skip: !hasRealBash() }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'seres-bak-'));
  try {
    const dbPath = join(dir, 'users.db');
    const bakDir = join(dir, 'backups');
    mkdirSync(bakDir);
    const mkDb = spawnSync('sqlite3', [dbPath, 'CREATE TABLE t(x INT); INSERT INTO t VALUES (1);'], { encoding: 'utf8' });
    assert.equal(mkDb.status, 0, mkDb.stderr);

    for (const badDays of ['0', '-1', 'abc']) {
      const r = spawnSync('sh', [resolve(ROOT, 'deploy/backup/backup.sh'), 'now'], {
        env: { ...process.env, BACKUP_DB: dbPath, BACKUP_DIR: bakDir, BACKUP_DAYS: badDays, BACKUP_KEEP: '2' },
        encoding: 'utf8',
      });
      assert.notEqual(r.status, 0, `BACKUP_DAYS=${badDays} must fail`);
    }
    for (const badKeep of ['0', '-2', 'xyz']) {
      const r = spawnSync('sh', [resolve(ROOT, 'deploy/backup/backup.sh'), 'now'], {
        env: { ...process.env, BACKUP_DB: dbPath, BACKUP_DIR: bakDir, BACKUP_DAYS: '7', BACKUP_KEEP: badKeep },
        encoding: 'utf8',
      });
      assert.notEqual(r.status, 0, `BACKUP_KEEP=${badKeep} must fail`);
    }

    const okRun = spawnSync('sh', [resolve(ROOT, 'deploy/backup/backup.sh'), 'now'], {
      env: { ...process.env, BACKUP_DB: dbPath, BACKUP_DIR: bakDir, BACKUP_DAYS: '1', BACKUP_KEEP: '2' },
      encoding: 'utf8',
    });
    assert.equal(okRun.status, 0, okRun.stderr);
    const files = require('node:fs').readdirSync(bakDir).filter((f) => f.endsWith('.db.gz'));
    assert.equal(files.length, 1);
    const mode = statSync(join(bakDir, files[0])).mode & 0o777;
    assert.equal(mode, 0o600, `backup archive must have 0600 permissions, got ${mode.toString(8)}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('repo hygiene: removes committed attachment, ignores runtime/key artifacts, and pins requirements.txt', () => {
  assert.equal(existsSync(resolve(ROOT, 'src/backend/files/a3f4b5c1df8e455a83ddb4f16bc4aaac')), false, 'committed sample file must be removed');

  const gitignoreLines = read('.gitignore').split(/\r?\n/).map((l) => l.trim());
  for (const entry of [
    'src/backend/files/',
    'src/backend/user_data/',
    'src/backend/group_avatars/',
    'src/backend/chats/',
    'src/backend/friends/',
    '*.p8',
    '*.db',
    '*.db-wal',
    '*.db-shm',
    '*.db.gz',
  ]) {
    assert.ok(gitignoreLines.includes(entry), `.gitignore must contain ${entry}`);
  }

  const dockerignoreLines = read('.dockerignore').split(/\r?\n/).map((l) => l.trim());
  assert.ok(dockerignoreLines.includes('*.p8'), '.dockerignore must contain *.p8');

  const reqLines = read('requirements.txt').split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  assert.ok(reqLines.length >= 6);
  for (const line of reqLines) {
    assert.match(line, />=|==/, `requirements.txt entry "${line}" must pin a minimum version`);
  }
});

test('mailer.py fails closed on unrecognized SMTP_SECURITY, defaults empty values safely, and handles empty SMTP_PORT', () => {
  const py = `
import os, sys, smtplib
sys.path.insert(0, os.path.abspath("src/backend"))
import mailer

calls = []
class DummySMTP:
    def __init__(self, host, port, timeout=None, context=None):
        calls.append(("smtp", host, port))
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def starttls(self, context=None): calls.append(("starttls",))
    def login(self, u, p): calls.append(("login", u))
    def send_message(self, m): calls.append(("send",))

smtplib.SMTP = DummySMTP
smtplib.SMTP_SSL = DummySMTP

os.environ["MAIL_DEBUG"] = "0"
os.environ["SMTP_HOST"] = "smtp.example.com"
os.environ["SMTP_PORT"] = ""
os.environ["SMTP_SECURITY"] = ""
msg = mailer.build_message("user@example.com", "Test", "Hello")
mailer.deliver(msg)
assert calls[0] == ("smtp", "smtp.example.com", 587), f"unexpected calls: {calls}"
assert ("starttls",) in calls, f"empty SMTP_SECURITY must default to starttls: {calls}"

calls.clear()
for bad in ("tls", "invalid", "STARTTLS_INVALID"):
    os.environ["SMTP_SECURITY"] = bad
    try:
        mailer.deliver(msg)
        raise AssertionError(f"Expected ValueError for SMTP_SECURITY={bad!r}")
    except ValueError:
        pass
assert calls == [], f"unrecognized SMTP_SECURITY must fail closed before connecting: {calls}"
print("MAILER_OK")
`;
  const res = runPython(py);
  assert.equal(res.status, 0, `${res.stderr}\n${res.stdout}`);
  assert.match(res.stdout, /MAILER_OK/);
});

test('app.py tightens EMAIL_RE and guards totp_enable with AND totp_pending=? and rowcount==1', () => {
  const py = `
import os, sys, types, tempfile, sqlite3
sys.path.insert(0, os.path.abspath("src/backend"))

# Stub third-party packages if not installed in this Python runtime
def ensure_stub(name, attrs):
    if name in sys.modules:
        return
    try:
        __import__(name)
    except ImportError:
        mod = types.ModuleType(name)
        for k, v in attrs.items():
            setattr(mod, k, v)
        sys.modules[name] = mod

class FakeFlask:
    def __init__(self, *a, **k): self.config = {}
    def route(self, *a, **k): return lambda f: f
    def before_request(self, f): return f
    def after_request(self, f): return f
    def teardown_appcontext(self, f): return f
    def send_static_file(self, *a, **k): return ""

ensure_stub("dotenv", {"load_dotenv": lambda *a, **k: None})
ensure_stub("flask", {
    "Flask": FakeFlask,
    "g": types.SimpleNamespace(),
    "request": types.SimpleNamespace(headers={}, cookies={}, method="POST", path="/", remote_addr="127.0.0.1", host="localhost", is_secure=False, get_json=lambda **k: {}),
    "make_response": lambda x: x,
    "abort": lambda x: (_ for _ in ()).throw(RuntimeError("abort")),
})
ensure_stub("webauthn", {})
ensure_stub("webauthn.helpers", {})
class FakePH:
    def __init__(self, *a, **k): pass
    def hash(self, v): return "h:" + v
    def verify(self, a, b): return True
ensure_stub("argon2", {"PasswordHasher": FakePH})
ensure_stub("argon2.exceptions", {"InvalidHashError": Exception, "VerificationError": Exception, "VerifyMismatchError": Exception})
ensure_stub("PIL", {"Image": object, "UnidentifiedImageError": Exception})

tmp = tempfile.mkdtemp()
os.environ["SERES_DATA_DIR"] = tmp
import app, db, totp

for good in ("alice@example.com", "a.b+tag@sub.example.co.uk"):
    assert app.EMAIL_RE.match(good), f"should accept {good!r}"

for bad in (
    "a,b@example.com",
    "<alice@example.com>",
    "alice@example.com>",
    "alice\\r\\n@example.com",
    "alice@example.com\\nBcc:evil@x.org",
    "alice\\x00@example.com",
    "alice @example.com",
    "alice@-example.com",
    "alice@example..com",
):
    assert not app.EMAIL_RE.match(bad), f"EMAIL_RE must reject {bad!r}"

# Behavioral check on totp_enable race guard
conn = db.connect(os.path.join(tmp, "users.db"))
db.init_schema(conn)
secret = totp.new_secret()
conn.execute(
    "INSERT INTO users (id, email, username, passwd, auth_version, totp_pending) VALUES (?, ?, ?, ?, 1, ?)",
    ("u1", "u1@example.com", "u1", "h:pw", secret),
)
conn.commit()
user_row = conn.execute("SELECT * FROM users WHERE id = 'u1'").fetchone()

# Simulate concurrent disable/change clearing totp_pending right before UPDATE
conn.execute("UPDATE users SET totp_pending = NULL WHERE id = 'u1'")
conn.commit()

code = totp.code_at(secret, totp.current_step())
app.current_user = lambda: user_row
app.get_db = lambda: conn
app.rate_limited = lambda *a, **k: False
app.json_body = lambda: {"code": code}

res, status = app.totp_enable()
assert status != 200 and not res.get("success"), f"totp_enable must fail when totp_pending changed concurrently: {(res, status)}"
row = conn.execute("SELECT totp_secret, totp_pending FROM users WHERE id = 'u1'").fetchone()
assert row["totp_secret"] is None, "totp_secret must stay NULL after concurrent clear"
conn.close()
print("APP_OK")
`;
  const res = runPython(py);
  assert.equal(res.status, 0, `${res.stderr}\n${res.stdout}`);
  assert.match(res.stdout, /APP_OK/);
});

test('legacy_migration.py safely handles malformed JSON types and SQLite errors without crashing', () => {
  const py = `
import os, sys, tempfile, sqlite3
sys.path.insert(0, os.path.abspath("src/backend"))
import db, legacy_migration

tmp = tempfile.mkdtemp()
conn = db.connect(os.path.join(tmp, "users.db"))
db.init_schema(conn)
conn.execute("INSERT INTO users (id, email, username, passwd) VALUES ('u1', 'u1@example.com', 'u1', 'p')")
conn.execute("INSERT INTO users (id, email, username, passwd) VALUES ('u2', 'u2@example.com', 'u2', 'p')")
conn.commit()

ud = os.path.join(tmp, "user_data")
cd = os.path.join(tmp, "chats")
os.makedirs(os.path.join(ud, "u1"))
os.makedirs(os.path.join(ud, "u2"))
os.makedirs(os.path.join(cd, "bad_list"))
os.makedirs(os.path.join(cd, "bad_db"))

# Malformed JSON root types & non-list fields
with open(os.path.join(ud, "u1", "friends.json"), "w") as f: f.write('["u2"]')
with open(os.path.join(ud, "u1", "pending_friends.json"), "w") as f: f.write('{"pending": "not-a-list"}')
with open(os.path.join(ud, "u2", "friends.json"), "w") as f: f.write('{"friends": 123}')
with open(os.path.join(ud, "u2", "pending_friends.json"), "w") as f: f.write('123')
with open(os.path.join(cd, "bad_list", "users.json"), "w") as f: f.write('["u1", "u2"]')
with open(os.path.join(cd, "bad_db", "users.json"), "w") as f: f.write('{"users": ["u1", "u2"]}')
with open(os.path.join(cd, "bad_db", "history.db"), "wb") as f: f.write(b"not a sqlite file")

legacy_migration.migrate_legacy_files(conn, ud, cd)
assert db.get_meta(conn, legacy_migration.MIGRATION_KEY) is not None
assert conn.execute("SELECT COUNT(*) FROM chats").fetchone()[0] == 1
conn.close()
print("MIGRATION_OK")
`;
  const res = runPython(py);
  assert.equal(res.status, 0, `${res.stderr}\n${res.stdout}`);
  assert.match(res.stdout, /MIGRATION_OK/);
});
