# ShieldAudit AI - Sensitive Data Detection & Compliance Assistant

ShieldAudit AI is an enterprise-grade, privacy-centric application designed to scan, detect, and redact sensitive personal identifiable information (PII), national identifiers, financial data, and confidential business intelligence from documents. 

Equipped with a hybrid regex-LLM detection architecture and strict mathematical validation layers, ShieldAudit AI generates automated compliance logs, provides security risk analysis, and offers interactive Q&A capabilities over uploaded PDF, TXT, and CSV documents—wrapped in a modern, glassmorphic Single Page Application (SPA).

---

## 🚀 Key Features

*   **Multi-Format Document Parser**: Extraction support for digital PDFs (via `PyMuPDF`), plain text files (with automatic encoding fallback), and tabular CSVs (via `Pandas`).
*   **Groq-Powered OCR Fallback**: Scanned image-only PDFs are automatically rendered to images page-by-page and processed using Groq's Llama 3.2 Vision model for OCR extraction.
*   **Hybrid Sensitive Data Detection**:
    *   *Rule-Based Engines*: Deterministic patterns for Aadhaar, PAN, Emails, Phone Numbers, Credit Cards, Bank details, and API Keys.
    *   *Mathematical Checksums*: Embedded **Verhoeff algorithm** (Aadhaar validation) and **Luhn algorithm** (Credit Card validation) to eliminate false positives.
    *   *AI Semantic Engine (Groq Llama 3)*: Performs high-level semantic search for confidential corporate text, trade secrets, passwords, and verifies rule-based findings.
*   **Data Masker / Redactor**: Descending-offset text replacement that swaps sensitive strings with safe placeholder tokens (e.g. `[REDACTED_AADHAAR_1]`), generating a downloadable cleaned document.
*   **Compliance Risk Classification**: Weighted scoring system (0-100) assigning risk categories (Low, Medium, High) alongside compliance observations (GDPR, PCI-DSS, India DPDP Act), threats, and remediation steps.
*   **Interactive Q&A Chat**: An in-browser chatbot that lets you ask questions directly about the uploaded document, grounded strictly in the parsed content to prevent hallucinations.
*   **Security Audit Logs**: Encoded, metadata-only activity log persisted in a local SQLite database, showing processing events without storing raw PII data.

---

## 📁 Repository Structure

```
├── main.py                 # FastAPI Application Server (CORS, REST API, SPA Static router)
├── requirements.txt        # Python dependency list
├── .env.example            # Environment configuration template
├── audit.db                # Auto-generated SQLite audit log database (created on run)
├── services/               # Core business logic packages
│   ├── parser.py           # Text extractor (PDF, TXT, CSV, Groq OCR fallback)
│   ├── detector.py         # Hybrid detection (Regex, Luhn/Verhoeff checksums, Groq validation)
│   ├── compliance.py       # Risk scoring and compliance analysis service
│   ├── rag.py              # Grounded Q&A service over document contents
│   ├── masker.py           # Offset-based text redaction engine
│   └── audit.py            # SQLite audit logger
└── static/                 # Glassmorphic SPA Frontend Assets
    ├── index.html          # Web dashboard layout
    ├── css/style.css       # Premium custom stylesheets and animations
    └── js/app.js           # Client-side routing, upload, chart, and chat logic
```

---

## 🛠️ Setup & Installation Instructions

### Prerequisites
*   Python 3.10 or higher installed.
*   A Groq API Key (obtain from the [Groq Console](https://console.groq.com/)).

### Step 1: Clone and Navigate
Clone the repository and enter the directory:
```bash
git clone <your-repository-link>
cd sensitive-data-detection
```

### Step 2: Install Dependencies
Install all required libraries using pip:
```bash
pip install -r requirements.txt
```

### Step 3: Configure Environment
Copy the example environment configuration and edit it to include your Groq API key:
```bash
cp .env.example .env
```
Open `.env` and configure:
```env
GROQ_API_KEY=your_actual_groq_api_key_here
PORT=8000
```
> **Note**: You can also insert/override the Groq API key directly in the browser UI via the **Settings** panel on the sidebar.

### Step 4: Run the Application
Start the FastAPI server:
```bash
python -m uvicorn main:app --port 8000 --host 127.0.0.1
```
Open your browser and navigate to **`http://127.0.0.1:8000`** to interact with the web dashboard.

---

## 🏗️ Architecture & AI/ML Approach

```
                  +----------------------------------------------+
                  |            Browser Frontend (SPA)            |
                  +----------------------+-----------------------+
                                         |
                                         | REST API (JSON / Multipart)
                                         v
                  +----------------------+-----------------------+
                  |            FastAPI Backend Engine            |
                  +-----+----------------+-----------------+-----+
                        |                |                 |
      1. Parse          v                | 2. Detect       v 3. Log
+-----------------------+--------+       |           +-----+-----------------+
| services/parser.py             |       |           | services/audit.py     |
| - PyMuPDF (PDF)                |       |           | - SQLite DB           |
| - Pandas (CSV)                 |       |           | - Metadata-only       |
| - Groq OCR Fallback (Vision)   |       |           +-----------------------+
+--------------------------------+       |
                                         v
                       +-----------------+-----------------+
                       | services/detector.py              |
                       | - Rule Engine (Regex patterns)    |
                       | - Checksums (Luhn & Verhoeff)     |
                       | - Semantic Analysis (Groq Llama 3)|
                       +-----------------+-----------------+
                                         |
                                         | 4. Compliance Report & Redact
                                         v
                       +-----------------+-----------------+
                       | services/compliance.py            |
                       | services/masker.py                |
                       | services/rag.py                   |
                       +-----------------------------------+
```

### AI/ML Approach & Algorithms
1.  **Strict Hybrid Filter**: Rule-based regex handles high-throughput matching for structured data. Mathematical validators (Luhn algorithm for credit cards, Verhoeff algorithm for Aadhaar) verify structural math, screening out invalid numbers and false hits.
2.  **Semantic Contextual Validation**: The filtered regex findings are forwarded to Groq (Llama 3) along with the text. The model determines if findings are valid in context (e.g. distinguishing a serial number from a tax ID) and captures unstructured risk profiles (confidential business projects, mergers, IP) that rules cannot detect.
3.  **Grounded Retrieval-Augmented Generation (RAG)**: For document Q&A, the system mounts the parsed text directly in the Groq (Llama 3) context window. A system prompt grounds the AI, commanding it to reject out-of-document facts, eliminating hallucination risks common in standard RAG pipelines.

---

## ⚠️ Challenges Faced & Solutions

*   **Hyphen Range Compilation Errors in Python Regex**: 
    *   *Challenge*: Certain character classes (e.g., `[-\s]` and `[\s-.]`) failed to compile, throwing "bad character range" exceptions because Python interpreted the hyphen as an active character range operator.
    *   *Solution*: Reordered all bracket groupings so that the hyphen is located at the very end of the character class (e.g., `[\s-]` and `[\s.-]`), forcing the regex engine to treat it as a literal hyphen.
*   **Index Shifting During Text Redaction**:
    *   *Challenge*: Substituting sensitive strings with redaction tags (e.g., replacing `a@b.com` with `[REDACTED_EMAIL_ADDRESS_1]`) alters the overall text length, invalidating the start and end offsets of subsequent findings and corrupting the final document.
    *   *Solution*: Sorted all valid findings by their character start index in *descending order* (from the end of the document to the beginning). Replacing text from back-to-front guarantees that prior character coordinates remain completely unaffected.
*   **Multimodal OCR without Local Binary Dependencies**:
    *   *Challenge*: Digital PDF parsers yield empty strings when processing scanned PDFs. Integrating Tesseract OCR requires local OS-level binaries, which are difficult to manage across different platforms.
    *   *Solution*: Added a fallback that uses `PyMuPDF` to render pages as images and uploads them page-by-page directly to Groq's Llama 3.2 Vision model, executing high-accuracy OCR without any local binary dependencies.

---

## 🔮 Future Improvements

1.  **Incremental RAG Indexing**: Integrate vector DBs (e.g., FAISS or ChromaDB) to support searching across huge multi-document folders.
2.  **PDF/CSV Layout Reconstruction**: Re-render the masked text back into its original PDF layout, returning a redacted visual PDF rather than raw text.
3.  **Local LLM execution**: Introduce support for running lightweight local models (e.g., Llama 3 or Phi 3 via Ollama) to support offline deployments.

---

## 🔗 Deployment & Links

*   **GitHub Repository**: [GitHub Link Placeholder - Please update]
*   **Working Prototype**: [Prototype Link Placeholder - Please update]
*   **Demo Video**: [Demo Video Link Placeholder - Please update]
