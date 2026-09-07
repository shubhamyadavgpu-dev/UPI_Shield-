import sqlite3
import os
import json

from datetime import datetime, timezone


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DATABASE_PATH = os.path.join(
    BASE_DIR,
    "upi_shield.db"
)


# ============================================================
# CONNECTION
# ============================================================

def get_connection():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    return connection


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def init_db():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            transaction_id TEXT UNIQUE NOT NULL,

            message TEXT NOT NULL,

            amount REAL,

            recipient TEXT,

            source TEXT,

            risk_score INTEGER,

            risk_level TEXT,

            confidence INTEGER,

            decision TEXT,

            signals TEXT,

            reasons TEXT,

            recommended_action TEXT,

            created_at TEXT NOT NULL

        )
    """)

    connection.commit()

    connection.close()


# ============================================================
# SAVE ANALYSIS
# ============================================================

def save_analysis(
    transaction,
    analysis,
    decision=None
):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT OR REPLACE INTO transactions (

            transaction_id,
            message,
            amount,
            recipient,
            source,
            risk_score,
            risk_level,
            confidence,
            decision,
            signals,
            reasons,
            recommended_action,
            created_at

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (

        transaction.get(
            "transaction_id"
        ),

        transaction.get(
            "message"
        ),

        transaction.get(
            "amount"
        ),

        transaction.get(
            "recipient"
        ),

        transaction.get(
            "source"
        ),

        analysis.get(
            "risk_score"
        ),

        analysis.get(
            "risk_level"
        ),

        analysis.get(
            "confidence"
        ),

        decision,

        json.dumps(
            analysis.get(
                "signals",
                []
            )
        ),

        json.dumps(
            analysis.get(
                "reasons",
                []
            )
        ),

        analysis.get(
            "recommended_action"
        ),

        datetime.now(
            timezone.utc
        ).isoformat()

    ))

    connection.commit()

    connection.close()


# ============================================================
# RECENT TRANSACTIONS
# ============================================================

def get_recent_transactions(
    limit=20
):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            transaction_id,
            amount,
            recipient,
            source,
            risk_score,
            risk_level,
            confidence,
            decision,
            created_at

        FROM transactions

        ORDER BY id DESC

        LIMIT ?
    """, (
        limit,
    ))

    rows = cursor.fetchall()

    connection.close()

    return [
        dict(row)
        for row in rows
    ]


# ============================================================
# STATISTICS
# ============================================================

def get_statistics():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM transactions
    """)

    total = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM transactions
        WHERE risk_level IN ('HIGH', 'CRITICAL')
    """)

    high_risk = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM transactions
        WHERE decision = 'BLOCK'
    """)

    blocked = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM transactions
        WHERE decision = 'WARN'
    """)

    warned = cursor.fetchone()[0]

    cursor.execute("""
        SELECT AVG(risk_score)
        FROM transactions
    """)

    average_score = cursor.fetchone()[0]

    connection.close()

    return {

        "total_transactions": total,

        "high_risk_transactions": high_risk,

        "blocked_transactions": blocked,

        "warned_transactions": warned,

        "average_risk_score": round(
            average_score or 0,
            2
        )

    }