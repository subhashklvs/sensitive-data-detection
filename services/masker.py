import logging
import re

logger = logging.getLogger(__name__)

SECTION_HEADER_PATTERN = re.compile(
    r"^[ \t]*(?:"
    r"education(?:al background)?|academic background|qualifications|"
    r"summary|professional summary|objective|career objective|"
    r"experience|work experience|professional experience|employment history|"
    r"skills|technical skills|projects|certifications|achievements|"
    r"publications|languages|references|personal details|"
    r"positions of responsibility"
    r")[ \t]*:?[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)


def _redact_education_sections(text: str) -> str:
    """Replace education details with level-specific placeholders in resume sections."""
    headers = list(SECTION_HEADER_PATTERN.finditer(text))
    education_headers = [
        header for header in headers
        if re.fullmatch(
            r"[ \t]*(?:education(?:al background)?|academic background|qualifications)[ \t]*:?[ \t]*",
            header.group(),
            re.IGNORECASE,
        )
    ]

    for header in reversed(education_headers):
        next_header = next(
            (candidate for candidate in headers if candidate.start() > header.start()),
            None,
        )
        section_end = next_header.start() if next_header else len(text)
        section_text = text[header.end():section_end]
        categories = (
            ("SCHOOL", r"\b(?:school|ssc|10(?:th)?|secondary|matric(?:ulation)?)\b"),
            ("INTERMEDIATE", r"\b(?:intermediate|12(?:th)?|higher secondary|hsc|puc|pre[- ]university)\b"),
            ("B_TECH", r"\b(?:b\.?\s?tech|bachelor(?:'s)?|b\.?e\.?|undergraduate|engineering)\b"),
        )
        placeholders = [
            f"[REDACTED_{label}_1]"
            for label, pattern in categories
            if re.search(pattern, section_text, re.IGNORECASE)
        ]
        if not placeholders:
            placeholders = ["[REDACTED_EDUCATION_1]"]

        replacement = "\n" + "\n".join(placeholders) + "\n"
        text = text[:header.end()] + replacement + text[section_end:]

    return text


def mask_document_text(text: str, findings: list[dict]) -> str:
    """
    Redacts sensitive details in the text by replacing them with descriptive tags,
    e.g. [REDACTED_EMAIL_1].
    Uses offset-based replacement in descending order to prevent index shift issues,
    with a value-based fallback for findings without exact start/end offsets.
    """
    # Separate findings with valid offsets from those without
    offset_findings = []
    value_only_findings = []
    
    for f in findings:
        start = f.get("start", -1)
        end = f.get("end", -1)
        val = f.get("value", "")
        
        if start != -1 and end != -1 and val:
            offset_findings.append(f)
        elif val:
            value_only_findings.append(f)

    # Sort offset findings by start index in descending order
    # This prevents replacement from corrupting the offsets of earlier findings in the document
    offset_findings.sort(key=lambda x: x["start"], reverse=True)
    
    masked_text = text
    replaced_ranges = [] # Track ranges that have been replaced to avoid double-redaction/overlaps
    
    # Track entity counts for clean numbering (e.g. EMAIL_1, EMAIL_2)
    entity_counts = {}

    for f in offset_findings:
        start = f["start"]
        end = f["end"]
        val = f["value"]
        f_type = f["type"].upper().replace(" ", "_")
        
        # Check if this range overlaps with any already replaced ranges
        overlap = False
        for r_start, r_end in replaced_ranges:
            if not (end <= r_start or start >= r_end):
                overlap = True
                break
                
        if overlap:
            continue
            
        # Increment entity count
        entity_counts[f_type] = entity_counts.get(f_type, 0) + 1
        placeholder = f"[REDACTED_{f_type}_{entity_counts[f_type]}]"
        
        # Double check that the value matches what's actually in the text at those offsets
        # If it doesn't match exactly (e.g. case difference), we still replace it
        masked_text = masked_text[:start] + placeholder + masked_text[end:]
        replaced_ranges.append((start, end))

    # For findings without offsets, do a simple value replacement on the final text
    for f in value_only_findings:
        val = f["value"]
        f_type = f["type"].upper().replace(" ", "_")
        
        if val in masked_text:
            entity_counts[f_type] = entity_counts.get(f_type, 0) + 1
            placeholder = f"[REDACTED_{f_type}_{entity_counts[f_type]}]"
            masked_text = masked_text.replace(val, placeholder)
            
    return _redact_education_sections(masked_text)
