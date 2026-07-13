import os
import logging
import base64
import pandas as pd
import fitz  # PyMuPDF
from groq import Groq

logger = logging.getLogger(__name__)

def parse_txt(file_path: str) -> str:
    """Reads a text file, trying common encodings to avoid crashes."""
    encodings = ["utf-8", "latin-1", "utf-16", "cp1252"]
    for enc in encodings:
        try:
            with open(file_path, "r", encoding=enc) as f:
                content = f.read()
                logger.info(f"Successfully parsed text file with {enc} encoding.")
                return content
        except UnicodeDecodeError:
            continue
    raise ValueError("Unable to parse text file. Unsupported encoding.")

def parse_csv(file_path: str) -> tuple[str, list[dict]]:
    """
    Parses a CSV file.
    Returns:
        - A text representation (Markdown table style) for LLM consumption.
        - A list of dictionaries representing the structured rows for detailed tracking.
    """
    try:
        df = pd.read_csv(file_path)
        # Convert df to dictionary records
        records = df.to_dict(orient="records")
        # Generate markdown string representation for context
        markdown_str = df.to_markdown(index=False)
        return markdown_str, records
    except Exception as e:
        logger.error(f"Error parsing CSV file: {e}")
        # Fallback to simple line parsing if pandas fails
        import csv
        records = []
        lines = []
        with open(file_path, mode="r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                records.append(dict(row))
            f.seek(0)
            lines = f.readlines()
        return "".join(lines), records

def parse_pdf_text_only(file_path: str) -> str:
    """Extracts text from a PDF file using PyMuPDF (fitz)."""
    text = ""
    try:
        with fitz.open(file_path) as doc:
            for page in doc:
                text += page.get_text() + "\n"
    except Exception as e:
        logger.error(f"PyMuPDF extraction failed: {e}")
    return text.strip()

def ocr_pdf_with_groq(file_path: str, api_key: str) -> str:
    """
    Renders pages of a scanned PDF as images and sends them to Groq Llama 3.2 Vision for OCR extraction.
    Used as a fallback for scanned documents without digital text.
    """
    if not api_key or api_key == "YOUR_GROQ_API_KEY_HERE":
        logger.warning("Groq API key not configured. Skipping Groq OCR fallback.")
        return ""

    logger.info("Starting Groq OCR fallback for scanned PDF...")
    try:
        client = Groq(api_key=api_key)
        extracted_text = []

        with fitz.open(file_path) as doc:
            # To avoid hitting rate limits or taking too long, we process up to 10 pages in OCR fallback
            max_pages = min(len(doc), 10)
            if len(doc) > 10:
                logger.warning(f"PDF has {len(doc)} pages. OCR fallback limited to first 10 pages.")

            for i in range(max_pages):
                page = doc.load_page(i)
                # Render page to an image (zoom=2 for better resolution/OCR quality)
                mat = fitz.Matrix(2.0, 2.0)
                pix = page.get_pixmap(matrix=mat)
                img_data = pix.tobytes("png")

                # Encode image to base64 for Groq Multimodal API
                img_base64 = base64.b64encode(img_data).decode("utf-8")

                # Call Groq vision model to transcribe the page
                prompt = (
                    "Transcribe all text from this page image accurately. "
                    "Do not add any explanations, summaries, or introductions. "
                    "Just return the exact transcribed text."
                )
                
                response = client.chat.completions.create(
                    model="llama-3.2-11b-vision-preview",
                    messages=[
                        {
                            "role": "user",
                            "content": [
                                {"type": "text", "text": prompt},
                                {
                                    "type": "image_url",
                                    "image_url": {
                                        "url": f"data:image/png;base64,{img_base64}"
                                    }
                                }
                            ]
                        }
                    ]
                )
                
                text = response.choices[0].message.content
                if text:
                    extracted_text.append(text)
                
            return "\n\n--- PAGE BREAK ---\n\n".join(extracted_text)
    except Exception as e:
        logger.error(f"Groq OCR fallback failed: {e}")
        return ""

def parse_pdf(file_path: str, groq_api_key: str = None) -> str:
    """
    Main entry point for PDF parsing.
    First tries digital text extraction; falls back to Groq OCR if the document
    appears to be scanned (i.e. very little text extracted).
    """
    text = parse_pdf_text_only(file_path)
    
    # If we extracted very little text, check if it's a scanned PDF
    if len(text.strip()) < 50 and groq_api_key:
        logger.info("Extracted text is very short. Falling back to Groq OCR...")
        ocr_text = ocr_pdf_with_groq(file_path, groq_api_key)
        if ocr_text:
            text = ocr_text

    return text
