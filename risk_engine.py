import re


# ============================================================
# SIGNAL CONFIGURATION
# ============================================================

SIGNAL_WEIGHTS = {
    "urgency": 24,
    "threat": 26,
    "impersonation": 20,
    "payment_request": 14,
    "verification_bypass": 10,
    "authority_pressure": 18,
    "credential_request": 22,
    "context_mismatch": 12
}


# ============================================================
# NLP PATTERNS
# ============================================================

PATTERNS = {

    "urgency": [
        r"\bimmediately\b",
        r"\burgent\b",
        r"\bnow\b",
        r"\bright now\b",
        r"\bwithin\s+\d+\s*(minutes?|hours?)\b",
        r"\bexpires?\b",
        r"\blast warning\b",
        r"\bact quickly\b",
        r"\bdo not delay\b"
    ],

    "threat": [
        r"\bdisconnect(ed|ion)?\b",
        r"\bblocked?\b",
        r"\bsuspend(ed)?\b",
        r"\blegal action\b",
        r"\barrest\b",
        r"\bpenalty\b",
        r"\bfine\b",
        r"\bcancelled?\b",
        r"\baccount.*closed\b",
        r"\bpolice\b"
    ],

    "impersonation": [
        r"\bbank officer\b",
        r"\bbank manager\b",
        r"\bcustomer care\b",
        r"\bsupport team\b",
        r"\bgovernment\b",
        r"\bpolice officer\b",
        r"\belectricity department\b",
        r"\belectricity board\b",
        r"\bofficial\b",
        r"\bverification team\b"
    ],

    "payment_request": [
        r"\bpay\b",
        r"\bpayment\b",
        r"\btransfer\b",
        r"\bsend\b",
        r"\bupi\b",
        r"\brs\.?\s*\d+\b",
        r"\b₹\s*\d+\b",
        r"\binr\s*\d+\b"
    ],

    "verification_bypass": [
        r"\bdon'?t call\b",
        r"\bdo not call\b",
        r"\bdo not verify\b",
        r"\bno need to verify\b",
        r"\bskip verification\b",
        r"\bkeep this confidential\b",
        r"\bdon'?t tell anyone\b"
    ],

    "authority_pressure": [
        r"\bpolice\b",
        r"\bcourt\b",
        r"\bgovernment\b",
        r"\blegal\b",
        r"\bauthority\b",
        r"\bfine\b",
        r"\barrest\b",
        r"\bcase will be filed\b"
    ],

    "credential_request": [
        r"\botp\b",
        r"\bpin\b",
        r"\bpassword\b",
        r"\bcard number\b",
        r"\bcvv\b",
        r"\baccount number\b",
        r"\bverification code\b"
    ]
}


# ============================================================
# TEXT NORMALIZATION
# ============================================================

def normalize_text(text):

    text = str(text or "")

    text = text.lower()

    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


# ============================================================
# PATTERN MATCHING
# ============================================================

def detect_signal(text, patterns):

    matches = []

    for pattern in patterns:

        result = re.search(
            pattern,
            text,
            flags=re.IGNORECASE
        )

        if result:
            matches.append(
                result.group(0)
            )

    return matches


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score):

    if score >= 85:
        return "CRITICAL"

    if score >= 65:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


# ============================================================
# CONTEXT ANALYSIS
# ============================================================

def analyze_context(transaction):

    message = normalize_text(
        transaction.get(
            "message",
            ""
        )
    )

    amount = transaction.get(
        "amount"
    )

    recipient = transaction.get(
        "recipient"
    )

    detected = {}

    for signal, patterns in PATTERNS.items():

        matches = detect_signal(
            message,
            patterns
        )

        detected[signal] = matches

    # --------------------------------------------------------
    # Context mismatch
    # --------------------------------------------------------

    context_mismatch = False

    if (
        detected["threat"]
        and detected["payment_request"]
    ):
        context_mismatch = True

    detected["context_mismatch"] = (
        ["payment requested under threat"]
        if context_mismatch
        else []
    )

    # --------------------------------------------------------
    # Calculate score
    # --------------------------------------------------------

    raw_score = 0

    signal_results = []

    for signal, matches in detected.items():

        if not matches:
            continue

        weight = SIGNAL_WEIGHTS.get(
            signal,
            0
        )

        raw_score += weight

        signal_results.append({
            "name": signal.replace(
                "_",
                " "
            ).title(),

            "severity": (
                "HIGH"
                if weight >= 20
                else "MEDIUM"
            ),

            "weight": weight,

            "evidence": matches[:5]
        })

    # --------------------------------------------------------
    # Amount-based contextual modifier
    # --------------------------------------------------------

    if amount is not None:

        try:

            numeric_amount = float(
                amount
            )

            if numeric_amount >= 10000:

                raw_score += 8

            elif numeric_amount >= 5000:

                raw_score += 5

        except (ValueError, TypeError):

            pass

    # --------------------------------------------------------
    # Recipient verification
    # --------------------------------------------------------

    if recipient:

        suspicious_domains = [
            "verify",
            "urgent",
            "support",
            "refund",
            "official"
        ]

        recipient_text = str(
            recipient
        ).lower()

        if any(
            item in recipient_text
            for item in suspicious_domains
        ):

            raw_score += 6

            signal_results.append({

                "name": "Recipient anomaly",

                "severity": "MEDIUM",

                "weight": 6,

                "evidence": [
                    "Recipient identifier contains suspicious context"
                ]

            })

    # --------------------------------------------------------
    # Score normalization
    # --------------------------------------------------------

    risk_score = min(
        raw_score,
        100
    )

    risk_level = get_risk_level(
        risk_score
    )

    # --------------------------------------------------------
    # Reasons
    # --------------------------------------------------------

    reasons = []

    if detected["urgency"]:

        reasons.append(
            "The message creates pressure to act immediately."
        )

    if detected["threat"]:

        reasons.append(
            "Threatening consequences are used to influence the payment decision."
        )

    if detected["impersonation"]:

        reasons.append(
            "The sender appears to impersonate an organization or authority."
        )

    if detected["payment_request"]:

        reasons.append(
            "The message directly connects the request to a financial transfer."
        )

    if detected["verification_bypass"]:

        reasons.append(
            "The message discourages independent verification."
        )

    if detected["credential_request"]:

        reasons.append(
            "Sensitive authentication information appears to be requested."
        )

    if context_mismatch:

        reasons.append(
            "The payment request is combined with a threatening or coercive context."
        )

    if not reasons:

        reasons.append(
            "No major contextual scam indicators were detected."
        )

    # --------------------------------------------------------
    # Recommended action
    # --------------------------------------------------------

    if risk_level == "CRITICAL":

        recommended_action = (
            "Do not authorize the payment. "
            "Verify the request through an independent official channel."
        )

    elif risk_level == "HIGH":

        recommended_action = (
            "Pause the payment and independently verify "
            "the recipient and reason for payment."
        )

    elif risk_level == "MEDIUM":

        recommended_action = (
            "Review the payment details carefully before authorizing."
        )

    else:

        recommended_action = (
            "No strong contextual threat detected. "
            "Continue to review normal payment details."
        )

    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    signal_count = len(signal_results)

    confidence = min(
        99,
        60 + (signal_count * 6)
    )

    return {

        "risk_score": risk_score,

        "risk_level": risk_level,

        "confidence": confidence,

        "signals": signal_results,

        "reasons": reasons,

        "recommended_action": recommended_action,

        "authentication_status": "VALID",

        "context_status": (
            "SUSPICIOUS"
            if risk_score >= 40
            else "NORMAL"
        )
    }