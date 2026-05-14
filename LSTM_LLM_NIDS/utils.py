import sqlite3
import time
from threading import Lock

DB_PATH = "nids_alerts.db"
db_lock = Lock()

def init_db():
    """Initializes the SQLite database to store detected anomalies/alerts."""
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                packet_id TEXT,
                classification TEXT,
                risk_level TEXT,
                threat_probability TEXT,
                reason TEXT
            )
        ''')
        conn.commit()
        conn.close()

def store_alert(packet_id, classification, risk_level, threat_prob, reason):
    """Saves a flagged packet's LLM analysis to the database securely."""
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts (timestamp, packet_id, classification, risk_level, threat_probability, reason)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (time.strftime("%Y-%m-%d %H:%M:%S"), packet_id, classification, risk_level, threat_prob, reason))
        conn.commit()
        conn.close()

def get_recent_alerts(limit=50):
    """Fetches the latest alerts for the dashboard."""
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT timestamp, packet_id, classification, risk_level, threat_probability, reason FROM alerts ORDER BY id DESC LIMIT ?', (limit,))
        rows = cursor.fetchall()
        conn.close()
        
        results = []
        for row in rows:
            results.append({
                "Timestamp": row[0],
                "Packet ID": row[1],
                "Classification": row[2],
                "Risk Level": row[3],
                "Threat Prob": row[4],
                "Reason": row[5]
            })
        return results
