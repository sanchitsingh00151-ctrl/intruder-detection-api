import sqlite3

conn = sqlite3.connect("logs.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    attack_type TEXT,
    log_line TEXT
)
""")

conn.commit()

def insert_detection(ip, attack_type, log_line):
    cursor.execute(
        "INSERT INTO detections (ip, attack_type, log_line) VALUES (?, ?, ?)",
        (ip, attack_type, log_line)
    )
    conn.commit()

def fetch_stats():
    cursor.execute("""
        SELECT attack_type, COUNT(*) FROM detections GROUP BY attack_type
    """)
    return dict(cursor.fetchall())
