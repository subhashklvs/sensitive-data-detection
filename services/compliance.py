import logging
import json
from groq import Groq

logger = logging.getLogger(__name__)

# Weight mapping for programmatic risk scoring
SEVERITY_WEIGHTS = {
    "API Key": 25,
    "Credit Card Number": 20,
    "Bank Account Details": 20,
    "Confidential Business Information": 25,
    "Aadhaar Number": 15,
    "PAN Number": 15,
    "Phone Number": 5,
    "Email Address": 5,
    "Employee ID": 5
}

def calculate_base_risk(findings: list[dict]) -> tuple[int, str]:
    """Calculates a numerical risk score (0-100) and risk level based on findings."""
    if not findings:
        return 0, "Low"
        
    total_score = 0
    # Keep track of counts of each type to prevent a single type from bloating the score excessively
    # We cap counts at 3 for scoring purposes
    type_counts = {}
    
    for f in findings:
        f_type = f.get("type", "Other")
        weight = SEVERITY_WEIGHTS.get(f_type, 10)
        
        type_counts[f_type] = type_counts.get(f_type, 0) + 1
        if type_counts[f_type] <= 3:
            total_score += weight
            
    # Cap score at 100
    risk_score = min(total_score, 100)
    
    if risk_score <= 20:
        risk_level = "Low"
    elif risk_score <= 60:
        risk_level = "Medium"
    else:
        risk_level = "High"
        
    return risk_score, risk_level

def generate_compliance_report(text: str, findings: list[dict], api_key: str = None) -> dict:
    """
    Generates compliance observations, security risks, and suggested remediation steps.
    Uses Groq API if available, otherwise generates a standard programmatic response.
    """
    risk_score, risk_level = calculate_base_risk(findings)
    
    # Programmatic fallback when Groq key is missing
    fallback_report = {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "observations": [],
        "risks": [],
        "remediation": []
    }

    if not findings:
        fallback_report["observations"].append("No sensitive personal data or API keys were detected in the document.")
        fallback_report["risks"].append("Negligible data security risk identified from this document.")
        fallback_report["remediation"].append("No specific actions required. Maintain standard data handling hygiene.")
        return fallback_report

    # If no API key, build standard static compliance findings based on detected types
    if not api_key or api_key == "YOUR_GROQ_API_KEY_HERE":
        logger.warning("Groq API key not configured. Generating template compliance summary.")
        types_found = set(f["type"] for f in findings)
        
        # Observations
        if "Aadhaar Number" in types_found or "PAN Number" in types_found:
            fallback_report["observations"].append("Contains national identifiers subject to the India Digital Personal Data Protection (DPDP) Act.")
        if "Email Address" in types_found or "Phone Number" in types_found:
            fallback_report["observations"].append("Contains personal contact details governed by general PII regulations (GDPR / DPDP).")
        if "Credit Card Number" in types_found or "Bank Account Details" in types_found:
            fallback_report["observations"].append("Contains financial identifiers subject to PCI-DSS compliance and financial sector audits.")
        if "API Key" in types_found:
            fallback_report["observations"].append("Contains exposed API Keys or credentials which violate security best practices.")
            
        # Risks
        if "API Key" in types_found or "Confidential Business Information" in types_found:
            fallback_report["risks"].append("Potential unauthorized access, service hijacking, or intellectual property leakage.")
        if "Credit Card Number" in types_found or "Bank Account Details" in types_found:
            fallback_report["risks"].append("High exposure to financial fraud, chargebacks, and corporate account takeover.")
        if "Aadhaar Number" in types_found or "PAN Number" in types_found or "Email Address" in types_found:
            fallback_report["risks"].append("Risk of target phishing, social engineering, and identity theft attacks against subjects.")
            
        # Remediation
        fallback_report["remediation"].append("Redact all PII and sensitive identifiers before sharing or storing this document.")
        if "API Key" in types_found:
            fallback_report["remediation"].append("Immediately rotate any exposed API keys, check audit logs for unauthorized usage, and store keys in a secure secret manager.")
        if "Credit Card Number" in types_found or "Bank Account Details" in types_found:
            fallback_report["remediation"].append("Enforce PCI-DSS tokenization; do not store full primary account numbers (PAN) or bank details in plain text files.")
        
        fallback_report["remediation"].append("Restrict read access to this document to authorized compliance and security officers only.")
        return fallback_report

    # LLM-based audit generation
    logger.info("Generating AI compliance audit using Groq...")
    
    findings_summary = {}
    for f in findings:
        f_type = f["type"]
        findings_summary[f_type] = findings_summary.get(f_type, 0) + 1
        
    prompt = f"""
    You are a professional Data Privacy and Compliance Auditor.
    Analyze the document text and the summarized sensitive findings below to generate a compliance report.
    
    Document Text Sample:
    ---
    {text[:5000]}  # Read up to first 5000 characters
    ---
    
    Detected Sensitive Data Summary:
    ---
    {json.dumps(findings_summary, indent=2)}
    ---
    
    Your report should address major privacy and security regulations such as GDPR, HIPAA, PCI-DSS, and the India DPDP Act where applicable.
    
    Respond STRICTLY in JSON format with three list fields:
    {{
        "observations": [
            "List specific compliance observations (e.g. 'Contains Aadhaar numbers which violate DPDP Act regulations unless secured', 'Exposes API keys in plaintext...')"
        ],
        "risks": [
            "List key security threats if this document is leaked (e.g. 'Identity theft due to exposed Aadhaar and PAN details', 'Potential API service abuse and financial loss...')"
        ],
        "remediation": [
            "Provide specific, actionable steps to secure this data (e.g. 'Rotate the leaked Google API keys immediately', 'Redact the credit card numbers...', 'Encrypt the file at rest...')"
        ]
    }}
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
        
        ai_report = json.loads(response_text)
        
        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "observations": ai_report.get("observations", ["No specific compliance issues identified."]),
            "risks": ai_report.get("risks", ["Minimal risk identified under normal usage."]),
            "remediation": ai_report.get("remediation", ["Ensure standard access controls are applied."])
        }
    except Exception as e:
        logger.error(f"Groq compliance generation failed: {e}. Returning fallback report.")
        # Add basic info to fallback and return
        fallback_report["observations"].append("AI compliance generation failed; showing rule-based findings.")
        fallback_report["remediation"].append("Ensure standard data protection procedures are implemented.")
        return fallback_report
