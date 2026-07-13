import re
import logging
import json
from groq import Groq

logger = logging.getLogger(__name__)

# --- Checksum Validation Algorithms ---

# Verhoeff Tables for Aadhaar validation
VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
]
VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
]
VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]

def validate_verhoeff(number_str: str) -> bool:
    """Validates a string of digits using the Verhoeff checksum algorithm (used for Aadhaar)."""
    try:
        clean_num = "".join(c for c in number_str if c.isdigit())
        if len(clean_num) != 12:
            return False
        digits = [int(x) for x in reversed(clean_num)]
        c = 0
        for i, digit in enumerate(digits):
            c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]]
        return c == 0
    except Exception:
        return False

def validate_luhn(card_number: str) -> bool:
    """Validates a credit card number using the Luhn check digit algorithm."""
    try:
        digits = [int(c) for c in card_number if c.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = sum(odd_digits)
        for d in even_digits:
            double = d * 2
            checksum += double if double < 10 else double - 9
        return checksum % 10 == 0
    except Exception:
        return False


# --- Regex Patterns ---
REGEX_PATTERNS = {
    "Email Address": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "PAN Number": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
    # Aadhaar patterns (match spaced, hyphenated, and unspaced versions)
    "Aadhaar Number": r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b",
    # Credit Card general regex
    "Credit Card Number": r"\b(?:\d[ \s-]?){13,19}\b",
    # Indian & Global phone number formats
    "Phone Number": r"\b(?:\+?\d{1,3}[\s.-]?)?\(?[6-9]\d{2}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b",
    # IFSC code
    "IFSC Code": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
    # Generic bank account indicators (matches numbers in proximity of bank-related terms)
    "Bank Account Details": r"(?:a/c|acc|account|acct|saving|current)\s*(?:no|number|num)?[:\s-]*\b(\d{9,18})\b",
    # Common API Keys (GCP, Slack, AWS Access Key, Stripe, Bearer tokens)
    "API Key": r"(?:gsk_[a-zA-Z0-9]{48}|AIzaSy[a-zA-Z0-9\-_]{33}|AKIA[A-Z0-9]{16}|sk_(?:live|test)_[a-zA-Z0-9]{24}|Bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*)",
    # Employee ID common patterns
    "Employee ID": r"\b(?:EMP|ID|STAFF)[\s-]?\d{3,6}\b"
}

def detect_regex(text: str) -> list[dict]:
    """Runs regex checks on text, running Luhn/Verhoeff checksums on specific hits."""
    findings = []
    
    for label, pattern in REGEX_PATTERNS.items():
        # Using re.IGNORECASE for bank context and general matching
        flags = re.IGNORECASE if label in ["Bank Account Details", "Employee ID"] else 0
        matches = re.finditer(pattern, text, flags=flags)
        
        for m in matches:
            val = m.group(0)
            start, end = m.span()
            
            # Context snippet extraction (60 chars before and after)
            context_start = max(0, start - 60)
            context_end = min(len(text), end + 60)
            context = text[context_start:context_end].strip().replace("\n", " ")

            # Apply checksum validation for Aadhaar
            if label == "Aadhaar Number":
                if not validate_verhoeff(val):
                    continue
                # Normalize format to remove hyphens/spaces
                val = "".join(c for c in val if c.isdigit())
            
            # Apply checksum validation for Credit Cards
            elif label == "Credit Card Number":
                clean_cc = "".join(c for c in val if c.isdigit())
                if not validate_luhn(clean_cc):
                    continue
                val = clean_cc

            # For Bank Account Details, capture the specific group containing digits
            elif label == "Bank Account Details":
                # Find the digits in the match
                digit_match = re.search(r"\b\d{9,18}\b", val)
                if digit_match:
                    val = digit_match.group(0)
                else:
                    continue

            findings.append({
                "type": label,
                "value": val,
                "context": f"...{context}...",
                "start": start,
                "end": end,
                "source": "Regex Pattern Matching",
                "confidence": "High"
            })
            
    return findings

def detect_with_groq(text: str, api_key: str, regex_findings: list[dict]) -> tuple[list[dict], list[dict]]:
    """
    Leverages Groq to:
    1. Identify unstructured sensitive data (Confidential Business Info, passwords, keys).
    2. Review and validate regex findings to eliminate false positives.
    
    Returns:
        - validated_regex_findings: list of regex findings confirmed or corrected by LLM.
        - llm_findings: list of new sensitive findings detected purely by semantic analysis.
    """
    if not api_key or api_key == "YOUR_GROQ_API_KEY_HERE":
        logger.warning("Groq API key is not configured. Returning raw regex findings.")
        return regex_findings, []

    # Format regex findings for the prompt
    regex_summary = []
    for idx, f in enumerate(regex_findings):
        regex_summary.append({
            "temp_id": idx,
            "type": f["type"],
            "value": f["value"],
            "context": f["context"]
        })
        
    prompt = f"""
    You are an expert security compliance audit agent.
    Your task is to analyze the document text below and perform two operations:
    
    1. VALIDATE REGEX HITS: Review the pre-detected potential sensitive data entries (Regex Hits) below.
       Decide whether each hit is indeed sensitive/confidential in this context or if it is a false positive (e.g., a random product model number detected as a phone number or a serial code as a PAN number).
       Only approve them if they look genuinely like PII or bank details. Return a list of APPROVED 'temp_id' values.
       
    2. SEMANTIC FINDINGS: Identify any unstructured sensitive data that regex might have missed:
       - Passwords / Access Credentials / Secrets
       - Confidential Business Information (e.g., intellectual property, mergers/acquisitions, proprietary financial figures, trade secrets, sensitive strategy documents)
       - Employee ID, bank details, or credit cards that did not match the strict regexes.
       For each semantic finding, extract the exact sensitive value, its entity type, a short context snippet, and the confidence level (High/Medium/Low).
       
    Document Text:
    ---
    {text}
    ---
    
    Regex Hits:
    ---
    {json.dumps(regex_summary, indent=2)}
    ---
    
    Respond STRICTLY in JSON format with two root keys:
    - "approved_regex_ids": List of integers corresponding to the approved 'temp_id's.
    - "semantic_findings": List of objects, each containing:
        - "type": (e.g., "Confidential Business Information", "Password / Credential", "API Key", "Bank Account Details")
        - "value": The exact sensitive string from the text.
        - "context": The immediate context sentence.
        - "confidence": "High", "Medium", or "Low".

    Do not include any explanations or conversational text. Return only the raw JSON.
    """
    
    try:
        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"}
        )
        response_text = response.choices[0].message.content.strip()
        
        result = json.loads(response_text)
        
        approved_ids = result.get("approved_regex_ids", [])
        raw_semantic = result.get("semantic_findings", [])
        
        # Filter regex findings
        validated_regex = []
        for idx, f in enumerate(regex_findings):
            if idx in approved_ids:
                validated_regex.append(f)
            else:
                logger.info(f"Filtered out false positive regex hit: {f['type']} - {f['value']}")
                
        # Parse semantic findings
        llm_findings = []
        for s in raw_semantic:
            val = s.get("value", "")
            # Find offsets in text if possible
            start = text.find(val)
            end = start + len(val) if start != -1 else -1
            
            llm_findings.append({
                "type": s.get("type", "Confidential Business Information"),
                "value": val,
                "context": s.get("context", ""),
                "start": start,
                "end": end,
                "source": "AI Semantic Analysis",
                "confidence": s.get("confidence", "Medium")
            })
            
        return validated_regex, llm_findings
        
    except Exception as e:
        logger.error(f"Groq verification failed: {e}. Falling back to unverified regex findings.")
        return regex_findings, []

def detect_sensitive_data(text: str, api_key: str = None) -> list[dict]:
    """
    Detects all sensitive data using a hybrid approach:
    1. Runs rule-based regex detection.
    2. Uses Groq to validate regex findings and extract semantic sensitive entities.
    """
    regex_findings = detect_regex(text)
    
    if api_key and api_key != "YOUR_GROQ_API_KEY_HERE":
        validated_regex, llm_findings = detect_with_groq(text, api_key, regex_findings)
        return validated_regex + llm_findings
    else:
        # Without API Key, return all regex findings directly
        return regex_findings
