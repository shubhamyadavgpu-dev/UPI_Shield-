from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import math

app = Flask(__name__)

# Allow your local frontend to communicate with Flask.
CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "http://127.0.0.1:5500",
                "http://localhost:5500"
            ]
        }
    }
)

# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

MAX_MESSAGE_LENGTH = 5000
MAX_CONTEXT_LENGTH = 3000
MAX_RECIPIENT_LENGTH = 200


# ---------------------------------------------------------
# UTILITY FUNCTIONS
# ---------------------------------------------------------

def clean_text(value, max_length):
    """Safely normalize user-provided text."""
    if value is None:
        return ""

    if not isinstance(value, str):
        value = str(value)

    value = value.strip()

    return value[:max_length]


def clamp(value, minimum=0, maximum=100):
    return max(minimum, min(maximum, value))


def normalize_amount(value):
    """Convert payment amount into a safe numeric value."""
    if value is None or value == "":
        return 0.0

    try:
        amount = float(value)

        if not math.isfinite(amount):
            return 0.0

        return max(0.0, amount)

    except (TypeError, ValueError):
        return 0.0


def contains_any(text, keywords):
    text = text.lower()

    return any(
        keyword.lower() in text
        for keyword in keywords
    )


def keyword_hits(text, keywords):
    text = text.lower()

    return sum(
        1
        for keyword in keywords
        if keyword.lower() in text
    )


# ---------------------------------------------------------
# CONTEXTUAL NLP SIGNALS
# ---------------------------------------------------------

URGENCY_WORDS = [
    "immediately",
    "urgent",
    "urgently",
    "now",
    "today",
    "within",
    "minutes",
    "deadline",
    "last chance",
    "do not delay",
    "act now",
    "as soon as possible"
]

THREAT_WORDS = [
    "disconnect",
    "disconnection",
    "blocked",
    "block",
    "suspend",
    "suspended",
    "legal action",
    "police",
    "case",
    "fine",
    "penalty",
    "arrest",
    "court",
    "restriction",
    "restricted",
    "cancelled",
    "returned",
    "shut down"
]

IMPERSONATION_WORDS = [
    "bank",
    "bank officer",
    "support",
    "customer care",
    "electricity department",
    "electricity board",
    "police",
    "government",
    "authority",
    "officer",
    "delivery desk",
    "courier",
    "verification team",
    "official"
]

PAYMENT_WORDS = [
    "pay",
    "payment",
    "transfer",
    "upi",
    "send money",
    "₹",
    "rs",
    "inr",
    "amount"
]

SECRECY_WORDS = [
    "confidential",
    "secret",
    "do not tell",
    "don't tell",
    "keep this private",
    "nobody should know"
]

VERIFICATION_WORDS = [
    "verify",
    "verification",
    "official website",
    "official app",
    "official number",
    "customer care",
    "receipt"
]


# ---------------------------------------------------------
# SIGNAL ANALYSIS
# ---------------------------------------------------------

def calculate_signals(message, context, amount, recipient, scenario):
    combined = f"{message} {context}".lower()

    # -----------------------------
    # URGENCY
    # -----------------------------

    urgency_hits = keyword_hits(combined, URGENCY_WORDS)

    urgency = 20 + (urgency_hits * 14)

    if re.search(r"\b\d+\s*(minute|minutes|hour|hours)\b", combined):
        urgency += 15

    if contains_any(combined, ["today", "immediately", "now"]):
        urgency += 12

    urgency = clamp(urgency)

    # -----------------------------
    # THREAT LANGUAGE
    # -----------------------------

    threat_hits = keyword_hits(combined, THREAT_WORDS)

    threat = 15 + (threat_hits * 16)

    if contains_any(
        combined,
        [
            "legal action",
            "police case",
            "disconnect today",
            "account blocked",
            "arrest"
        ]
    ):
        threat += 20

    threat = clamp(threat)

    # -----------------------------
    # IMPERSONATION
    # -----------------------------

    impersonation_hits = keyword_hits(
        combined,
        IMPERSONATION_WORDS
    )

    impersonation = 20 + (impersonation_hits * 15)

    if recipient:
        recipient_lower = recipient.lower()

        suspicious_domains = [
            "gmail.com",
            "yahoo.com",
            "outlook.com",
            "hotmail.com"
        ]

        if any(
            domain in recipient_lower
            for domain in suspicious_domains
        ):
            impersonation += 12

    impersonation = clamp(impersonation)

    # -----------------------------
    # CONTEXT MISMATCH
    # -----------------------------

    context_mismatch = 20

    payment_detected = contains_any(
        combined,
        PAYMENT_WORDS
    )

    secrecy_detected = contains_any(
        combined,
        SECRECY_WORDS
    )

    verification_detected = contains_any(
        combined,
        VERIFICATION_WORDS
    )

    if payment_detected:
        context_mismatch += 20

    if secrecy_detected:
        context_mismatch += 18

    if amount > 0:
        context_mismatch += 8

    if recipient:
        context_mismatch += 8

    if verification_detected and payment_detected:
        context_mismatch += 12

    # Scenario-specific contextual mismatch.
    if scenario == "electricity":
        if contains_any(
            combined,
            [
                "electricity",
                "power",
                "connection",
                "bill",
                "disconnection"
            ]
        ):
            context_mismatch += 12

    elif scenario == "bank":
        if contains_any(
            combined,
            [
                "bank",
                "account",
                "verification",
                "kyc"
            ]
        ):
            context_mismatch += 12

    elif scenario == "delivery":
        if contains_any(
            combined,
            [
                "parcel",
                "delivery",
                "courier",
                "shipment"
            ]
        ):
            context_mismatch += 12

    elif scenario == "police":
        if contains_any(
            combined,
            [
                "police",
                "authority",
                "case",
                "legal"
            ]
        ):
            context_mismatch += 12

    context_mismatch = clamp(context_mismatch)

    return {
        "urgency": int(urgency),
        "threat": int(threat),
        "impersonation": int(impersonation),
        "context": int(context_mismatch)
    }


# ---------------------------------------------------------
# RISK CALCULATION
# ---------------------------------------------------------

def calculate_risk(signals, message, context, amount, recipient):
    """
    Weighted contextual risk model.

    This is a deterministic prototype model intended for
    the hackathon demonstration. It is not a production
    banking fraud model.
    """

    risk = (
        signals["urgency"] * 0.25 +
        signals["threat"] * 0.30 +
        signals["impersonation"] * 0.20 +
        signals["context"] * 0.25
    )

    combined = f"{message} {context}".lower()

    # Strong coercion indicators.
    if contains_any(
        combined,
        [
            "pay immediately",
            "transfer immediately",
            "legal action",
            "disconnect today",
            "account blocked",
            "arrest",
            "police case"
        ]
    ):
        risk += 7

    # Secrecy is a strong social-engineering signal.
    if contains_any(combined, SECRECY_WORDS):
        risk += 5

    # Payment request without recipient verification.
    if amount > 0 and recipient:
        if signals["urgency"] >= 70:
            risk += 4

    risk = round(clamp(risk))

    return risk


# ---------------------------------------------------------
# RISK LEVEL
# ---------------------------------------------------------

def get_risk_level(risk):
    if risk >= 90:
        return "CRITICAL RISK"

    if risk >= 70:
        return "HIGH RISK"

    if risk >= 45:
        return "MEDIUM RISK"

    return "LOW RISK"


# ---------------------------------------------------------
# CONFIDENCE
# ---------------------------------------------------------

def calculate_confidence(signals, risk):
    values = list(signals.values())

    average = sum(values) / len(values)

    spread = max(values) - min(values)

    confidence = 70 + (average * 0.25)

    # Consistent signals increase confidence.
    if spread < 25:
        confidence += 8

    if risk >= 90:
        confidence += 5

    return int(clamp(round(confidence), 50, 99))


# ---------------------------------------------------------
# REASONS
# ---------------------------------------------------------

def generate_reasons(
    signals,
    message,
    context,
    amount,
    recipient
):
    combined = f"{message} {context}".lower()

    reasons = []

    if signals["urgency"] >= 70:
        reasons.append(
            "Artificial urgency or time pressure detected"
        )

    if signals["threat"] >= 70:
        reasons.append(
            "Threat or coercive language detected"
        )

    if signals["impersonation"] >= 70:
        reasons.append(
            "Possible impersonation of an official or trusted entity"
        )

    if signals["context"] >= 70:
        reasons.append(
            "Payment request appears inconsistent with normal context"
        )

    if amount > 0:
        if amount >= 5000:
            reasons.append(
                "Payment amount increases the potential impact"
            )
        else:
            reasons.append(
                "A payment request was detected"
            )

    if recipient:
        reasons.append(
            "Recipient/payment destination should be independently verified"
        )

    if contains_any(combined, SECRECY_WORDS):
        reasons.append(
            "Secrecy instruction is a strong social-engineering indicator"
        )

    if not reasons:
        reasons.append(
            "No strong contextual threat indicators were detected"
        )

    # Keep API response concise.
    return reasons[:6]


# ---------------------------------------------------------
# RECOMMENDATION
# ---------------------------------------------------------

def get_recommendation(risk):
    if risk >= 90:
        return (
            "Pause the payment immediately. Do not transfer money "
            "under pressure. Independently verify the request using "
            "an official channel."
        )

    if risk >= 70:
        return (
            "Do not authorize immediately. Verify the sender, "
            "recipient and reason for payment through an independent "
            "official source."
        )

    if risk >= 45:
        return (
            "Proceed carefully. Review the payment context and "
            "verify the recipient before authorizing."
        )

    return (
        "No major contextual warning was detected. Still verify "
        "the recipient and payment purpose before authorization."
    )


# ---------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "success": True,
        "status": "UPI-Shield backend is running",
        "service": "contextual-threat-analyzer"
    })


# ---------------------------------------------------------
# ANALYZE API
# ---------------------------------------------------------

@app.route("/api/analyze", methods=["POST"])
def analyze():
    try:
        if not request.is_json:
            return jsonify({
                "success": False,
                "error": "Request must contain JSON data."
            }), 400

        payload = request.get_json(silent=True)

        if not isinstance(payload, dict):
            return jsonify({
                "success": False,
                "error": "Invalid JSON payload."
            }), 400

        # -----------------------------
        # INPUTS
        # -----------------------------

        message = clean_text(
            payload.get("message"),
            MAX_MESSAGE_LENGTH
        )

        context = clean_text(
            payload.get("context"),
            MAX_CONTEXT_LENGTH
        )

        recipient = clean_text(
            payload.get("recipient"),
            MAX_RECIPIENT_LENGTH
        )

        scenario = clean_text(
            payload.get("scenario"),
            50
        ).lower()

        amount = normalize_amount(
            payload.get("amount")
        )

        # -----------------------------
        # VALIDATION
        # -----------------------------

        if not message:
            return jsonify({
                "success": False,
                "error": "Message is required."
            }), 400

        allowed_scenarios = {
            "electricity",
            "bank",
            "delivery",
            "police"
        }

        if scenario not in allowed_scenarios:
            scenario = "electricity"

        # -----------------------------
        # ANALYSIS
        # -----------------------------

        signals = calculate_signals(
            message=message,
            context=context,
            amount=amount,
            recipient=recipient,
            scenario=scenario
        )

        risk = calculate_risk(
            signals=signals,
            message=message,
            context=context,
            amount=amount,
            recipient=recipient
        )

        risk_level = get_risk_level(risk)

        confidence = calculate_confidence(
            signals,
            risk
        )

        reasons = generate_reasons(
            signals=signals,
            message=message,
            context=context,
            amount=amount,
            recipient=recipient
        )

        recommendation = get_recommendation(
            risk
        )

        # -----------------------------
        # RESPONSE
        # -----------------------------

        return jsonify({
            "success": True,
            "data": {
                "risk_score": risk,
                "risk_level": risk_level,
                "confidence": confidence,

                "signals": {
                    "urgency": signals["urgency"],
                    "threat": signals["threat"],
                    "impersonation": signals["impersonation"],
                    "context": signals["context"]
                },

                "reasons": reasons,

                "recommended_action": recommendation,

                "analysis": {
                    "scenario": scenario,
                    "amount": amount,
                    "recipient_provided": bool(recipient),
                    "context_provided": bool(context)
                }
            }
        }), 200

    except Exception as error:
        app.logger.exception(
            "Unexpected analysis error"
        )

        return jsonify({
            "success": False,
            "error": "Unable to analyze the request.",
            "details": str(error)
        }), 500


# ---------------------------------------------------------
# ERROR HANDLERS
# ---------------------------------------------------------

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": "API endpoint not found."
    }), 404


@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        "success": False,
        "error": "HTTP method not allowed."
    }), 405


# ---------------------------------------------------------
# START SERVER
# ---------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("UPI-Shield Contextual Threat Analyzer")
    print("=" * 60)
    print("Backend: http://127.0.0.1:5000")
    print("Health : http://127.0.0.1:5000/api/health")
    print("API    : http://127.0.0.1:5000/api/analyze")
    print("=" * 60)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )