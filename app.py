from flask import Flask, render_template, request, redirect, session, jsonify
import sqlite3
import random
import hashlib
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
import numpy as np

# ─────────────────────────────────────────
# BRUTE FORCE TRACKER (in-memory)
# ─────────────────────────────────────────
failed_attempts = {}  # username -> {'count': N, 'locked_until': datetime}
MAX_ATTEMPTS = 3
LOCKOUT_MINUTES = 5

SECURITY_QUESTIONS = {
    "alice":   {"question": "What is your pet's name?",          "answer": "fluffy"},
    "bob":     {"question": "What is your mother's maiden name?", "answer": "sharma"},
    "charlie": {"question": "What was your first school name?",   "answer": "greenwood"},
}
def delete_bangalore_charlie():
    conn = db()
    c = conn.cursor()

    c.execute("""
        DELETE FROM logins
        WHERE username = 'charlie'
        AND location LIKE '%Bengaluru%'
    """)

    conn.commit()
    conn.close()
    print("✅ Deleted all Bengaluru logs for Charlie")

def is_locked(username):
    if username not in failed_attempts:
        return False, 0
    data = failed_attempts[username]
    if data.get('locked_until') and datetime.now() < data['locked_until']:
        remaining = int((data['locked_until'] - datetime.now()).total_seconds() / 60) + 1
        return True, remaining
    return False, 0

def record_failure(username):
    if username not in failed_attempts:
        failed_attempts[username] = {'count': 0, 'locked_until': None}
    failed_attempts[username]['count'] += 1
    if failed_attempts[username]['count'] >= MAX_ATTEMPTS:
        failed_attempts[username]['locked_until'] = datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)
        failed_attempts[username]['count'] = 0

def clear_failures(username):
    if username in failed_attempts:
        failed_attempts[username] = {'count': 0, 'locked_until': None}

app = Flask(__name__)
app.secret_key = "cns_digital_twin_2026"

# ─────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────
def db():
    conn = sqlite3.connect("security.db")
    conn.row_factory = sqlite3.Row
    return conn

def setup():
    conn = db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY,
        password TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS logins(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        date TEXT,
        time TEXT,
        hour INTEGER,
        device TEXT,
        location TEXT,
        ip TEXT,
        risk INTEGER,
        action TEXT
    )""")
    conn.commit()
    conn.close()

setup()

# ─────────────────────────────────────────
# SEED DEMO DATA (run once)
# ─────────────────────────────────────────
def seed_demo():
    conn = db()
    c = conn.cursor()

    # Create demo users
    users = [
        ("alice",   hashlib.sha256("alice123".encode()).hexdigest()),
        ("bob",     hashlib.sha256("bob123".encode()).hexdigest()),
        ("charlie", hashlib.sha256("charlie123".encode()).hexdigest()),
    ]
    for u, p in users:
        try:
            c.execute("INSERT INTO users VALUES (?,?)", (u, p))
        except:
            pass

    # Alice logs in from Bangalore (so first login = Allow)
    alice_logins = [
        ("alice","2026-04-20","09:15",9,"Mozilla/5.0 (Windows NT 10.0) Chrome/120","Bengaluru, Karnataka, IN","49.207.10.11",10,"Allow Login"),
        ("alice","2026-04-21","10:30",10,"Mozilla/5.0 (Windows NT 10.0) Chrome/120","Bengaluru, Karnataka, IN","49.207.10.12",10,"Allow Login"),
        ("alice","2026-04-22","09:45",9,"Mozilla/5.0 (Windows NT 10.0) Chrome/120","Bengaluru, Karnataka, IN","49.207.10.13",10,"Allow Login"),
        ("alice","2026-04-23","11:00",11,"Mozilla/5.0 (Windows NT 10.0) Chrome/120","Bengaluru, Karnataka, IN","49.207.10.14",10,"Allow Login"),
        ("alice","2026-04-24","10:15",10,"Mozilla/5.0 (Windows NT 10.0) Chrome/120","Bengaluru, Karnataka, IN","49.207.10.15",10,"Allow Login"),
        ("alice","2026-04-25","09:30",9,"Mozilla/5.0 (Windows NT 10.0) Chrome/120","Bengaluru, Karnataka, IN","49.207.10.16",10,"Allow Login"),
        ("alice","2026-04-26","10:45",10,"Mozilla/5.0 (Windows NT 10.0) Chrome/120","Bengaluru, Karnataka, IN","49.207.10.17",10,"Allow Login"),
    ]

    # Charlie always logs in from London, 3-5 PM
    charlie_logins = [
        ("charlie","2026-04-20","15:00",15,"Mozilla/5.0 (Windows NT 10.0) Chrome/120","London, England, GB","185.12.45.21",10,"Allow Login"),
        ("charlie","2026-04-21","16:30",16,"Mozilla/5.0 (Windows NT 10.0) Chrome/120","London, England, GB","185.12.45.22",10,"Allow Login"),
        ("charlie","2026-04-22","15:45",15,"Mozilla/5.0 (Windows NT 10.0) Chrome/120","London, England, GB","185.12.45.21",10,"Allow Login"),
        ("charlie","2026-04-23","16:00",16,"Mozilla/5.0 (Windows NT 10.0) Chrome/120","London, England, GB","185.12.45.23",10,"Allow Login"),
        ("charlie","2026-04-24","15:30",15,"Mozilla/5.0 (Windows NT 10.0) Chrome/120","London, England, GB","185.12.45.21",10,"Allow Login"),
        ("charlie","2026-04-25","16:15",16,"Mozilla/5.0 (Windows NT 10.0) Chrome/120","London, England, GB","185.12.45.24",10,"Allow Login"),
        ("charlie","2026-04-26","15:00",15,"Mozilla/5.0 (Windows NT 10.0) Chrome/120","London, England, GB","185.12.45.21",10,"Allow Login"),
    ]

    # Bob always logs in from Mumbai, 2-4 PM, Mac
    bob_logins = [
        ("bob","2026-04-20","14:00",14,"Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/537","Mumbai, Maharashtra, IN","49.36.100.21",10,"Allow Login"),
        ("bob","2026-04-21","15:30",15,"Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/537","Mumbai, Maharashtra, IN","49.36.100.22",10,"Allow Login"),
        ("bob","2026-04-22","14:45",14,"Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/537","Mumbai, Maharashtra, IN","49.36.100.21",10,"Allow Login"),
        ("bob","2026-04-23","15:00",15,"Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/537","Mumbai, Maharashtra, IN","49.36.100.23",10,"Allow Login"),
        ("bob","2026-04-24","14:30",14,"Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/537","Mumbai, Maharashtra, IN","49.36.100.21",10,"Allow Login"),
        ("bob","2026-04-25","15:15",15,"Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/537","Mumbai, Maharashtra, IN","49.36.100.24",10,"Allow Login"),
        ("bob","2026-04-26","14:00",14,"Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/537","Mumbai, Maharashtra, IN","49.36.100.21",10,"Allow Login"),
    ]

    for row in alice_logins + bob_logins + charlie_logins:
        c.execute("""INSERT OR IGNORE INTO logins
            (username,date,time,hour,device,location,ip,risk,action) VALUES
            (?,?,?,?,?,?,?,?,?)""", row)

    conn.commit()
    conn.close()

seed_demo()

# ─────────────────────────────────────────
# ML MODEL
# ─────────────────────────────────────────
def encode_row(time_str, device, location):
    hour = int(time_str.split(":")[0])
    device_val = 1 if "Windows" in device else (2 if "Mac" in device else 0)
    location_val = hash(location.split(",")[-2].strip() if "," in location else location) % 100
    return [hour, device_val, location_val]

def train_model(username):
    conn = db()
    c = conn.cursor()
    c.execute("SELECT time, device, location FROM logins WHERE username=?", (username,))
    rows = c.fetchall()
    conn.close()
    if len(rows) < 5:
        return None
    X = np.array([encode_row(r[0], r[1], r[2]) for r in rows])
    model = IsolationForest(contamination=0.2, random_state=42)
    model.fit(X)
    return model

def get_anomaly_score(model, current_vec):
    if model is None:
        return 0, "Normal"
    score = model.decision_function([current_vec])[0]  # negative = more anomalous
    prediction = model.predict([current_vec])[0]
    label = "Suspicious" if prediction == -1 else "Normal"
    return score, label

# ─────────────────────────────────────────
# RISK ENGINE
# ─────────────────────────────────────────
def compute_risk(ml_label, hour, location, username):
    risk = 0
    factors = []

    if ml_label == "Suspicious":
        risk += 20
        factors.append("Behavioral anomaly detected by AI model")

    if hour < 6 or hour > 22:
        risk += 10
        factors.append(f"Unusual login time ({hour}:00 hrs)")

    # Check last known location
    conn = db()
    c = conn.cursor()
    c.execute("SELECT location FROM logins WHERE username=? ORDER BY id DESC LIMIT 1", (username,))
    last = c.fetchone()
    conn.close()
    if last and last[0] != "Unknown":
        last_city = last[0].split(",")[0].strip()
        curr_city = location.split(",")[0].strip()
        if last_city and curr_city and last_city != curr_city:
            risk += 70
            factors.append(f"Location changed: {last_city} → {curr_city}")

    if risk == 0:
        factors.append("All behavioral patterns match digital twin")

    if risk >= 70:
        action = "Block Login"
    elif risk >= 35:
        action = "OTP Required"
    else:
        action = "Allow Login"

    return min(risk, 95), action, factors

# ─────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────
@app.route('/')
def home():
    return render_template("login.html")

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        u = request.form['username']
        p = hashlib.sha256(request.form['password'].encode()).hexdigest()
        conn = db()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users VALUES (?,?)", (u, p))
            conn.commit()
            conn.close()
            return redirect("/")
        except:
            conn.close()
            return render_template("signup.html", error="Username already exists!")
    return render_template("signup.html")

@app.route('/login', methods=['POST'])
def login():
    u = request.form['username']
    demo_mode = 'normal'  # no longer used, kept for compatibility

    # ── BRUTE FORCE CHECK ──
    locked, remaining = is_locked(u)
    if locked:
        return render_template("login.html",
            error=f"🔒 Account LOCKED! Too many failed attempts. Try again in {remaining} min.",
            locked=True)

    p = hashlib.sha256(request.form['password'].encode()).hexdigest()
    conn = db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (u, p))
    if not c.fetchone():
        conn.close()
        record_failure(u)
        attempts = failed_attempts.get(u, {}).get('count', 1)
        remaining_tries = MAX_ATTEMPTS - attempts
        if remaining_tries <= 0:
            return render_template("login.html",
                error=f"🔒 Account LOCKED for {LOCKOUT_MINUTES} mins after {MAX_ATTEMPTS} failed attempts!",
                locked=True)
        return render_template("login.html",
            error=f"❌ Invalid credentials! {remaining_tries} attempt(s) remaining before lockout.")

    # ── CLEAR FAILURES ON SUCCESS ──
    clear_failures(u)

    now = datetime.now()
    date_now = now.strftime("%Y-%m-%d")
    device = request.headers.get('User-Agent', 'Unknown')

    # All users login from Bangalore (where you actually are)
    # alice  → history Delhi   → medium anomaly → OTP
    # bob    → history Mumbai  → medium anomaly → OTP  
    # charlie→ history London  → severe anomaly → BLOCK
    # alice  → 2nd login same day → Bangalore now in history → Allow
    location = "Bengaluru, Karnataka, IN"
    time_now = now.strftime("%H:%M")
    hour = now.hour
    ip = "49.207.x.x"

    # ML
    model = train_model(u)
    current_vec = encode_row(time_now, device, location)
    score, ml_label = get_anomaly_score(model, current_vec)

    # Risk
    risk, action, factors = compute_risk(ml_label, hour, location, u)

    # Save login
    c.execute("""INSERT INTO logins(username,date,time,hour,device,location,ip,risk,action)
                 VALUES(?,?,?,?,?,?,?,?,?)""",
              (u, date_now, time_now, hour, device, location, ip, risk, action))
    conn.commit()

    # History
    c.execute("SELECT date, time, location, risk, action FROM logins WHERE username=? ORDER BY id DESC LIMIT 6", (u,))
    history = [dict(r) for r in c.fetchall()]
    c.execute("SELECT COUNT(*) as cnt FROM logins WHERE username=?", (u,))
    count = c.fetchone()['cnt']
    conn.close()

    if action == "Block Login":
        # Instead of hard block — offer security question as emergency 2FA
        sq = SECURITY_QUESTIONS.get(u)
        if sq:
            session['blocked_user'] = u
            session['blocked_data'] = {
                'ip': ip, 'device': device[:60], 'location': location,
                'date': date_now, 'time': time_now,
                'ml_label': ml_label, 'risk': risk, 'action': action,
                'factors': factors, 'count': count, 'history': history
            }
            return render_template("security_question.html",
                username=u, risk=risk,
                question=sq['question'], factors=factors)
        # No security question set — hard block
        return render_template("blocked.html", username=u, risk=risk, factors=factors)
        otp = str(random.randint(1000, 9999))
        session['otp'] = otp
        session['user'] = u
        session['pending_data'] = {
            'ip': ip, 'device': device[:60], 'location': location,
            'date': date_now, 'time': time_now,
            'ml_label': ml_label, 'risk': risk, 'action': action,
            'factors': factors, 'count': count, 'history': history
        }
        return render_template("otp.html", otp=otp, username=u, risk=risk)

    return render_template("dashboard.html",
        username=u, ip=ip, device=device[:80],
        location=location, date=date_now, time=time_now,
        ml_label=ml_label, risk=risk, action=action,
        factors=factors, count=count, history=history
    )

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    entered = request.form['otp']
    if entered == session.get('otp'):
        d = session.get('pending_data', {})
        u = session.get('user')
        return render_template("dashboard.html",
            username=u, **d
        )
    return render_template("otp.html",
        otp=session.get('otp'),
        username=session.get('user'),
        risk=session.get('pending_data', {}).get('risk', 50),
        error="Wrong OTP! Try again."
    )

@app.route('/verify_security', methods=['POST'])
def verify_security():
    u = session.get('blocked_user')
    answer = request.form.get('answer', '').strip().lower()
    sq = SECURITY_QUESTIONS.get(u, {})
    d = session.get('blocked_data', {})
    risk = d.get('risk', 80)

    if answer == sq.get('answer', ''):
        return render_template("dashboard.html", username=u, **d)
    return render_template("security_question.html",
        username=u, risk=risk,
        question=sq.get('question',''),
        factors=d.get('factors',[]),
        error="❌ Wrong answer! Access still denied.")

@app.route('/logout')
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    delete_bangalore_charlie()
    app.run(debug=True)  