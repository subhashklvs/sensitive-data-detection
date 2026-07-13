import logging
from groq import Groq

logger = logging.getLogger(__name__)

def chunk_text(text: str, chunk_size: int = 1500, overlap: int = 200) -> list[str]:
    """Splits a long text into overlapping chunks for keyword retrieval if needed."""
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append(text[start:end])
        start += chunk_size - overlap
    return chunks

def retrieve_relevant_context(text: str, query: str, max_chars: int = 100000) -> str:
    """
    If the document is extremely large, performs simple keyword/overlap retrieval
    to fit the context into the model's preferred input budget.
    For standard documents, returns the entire text.
    """
    if len(text) <= max_chars:
        return text
        
    logger.info("Document is extremely large. Running context chunk retrieval...")
    chunks = chunk_text(text)
    query_words = set(query.lower().split())
    
    scored_chunks = []
    for chunk in chunks:
        # Simple term overlap scoring
        chunk_words = set(chunk.lower().split())
        score = len(query_words.intersection(chunk_words))
        scored_chunks.append((score, chunk))
        
    # Sort by score descending and take the top chunks that fit in the max_chars limit
    scored_chunks.sort(key=lambda x: x[0], reverse=True)
    
    selected_chunks = []
    current_length = 0
    for score, chunk in scored_chunks:
        if current_length + len(chunk) > max_chars:
            break
        selected_chunks.append(chunk)
        current_length += len(chunk)
        
    return "\n\n... [SECTION BREAK] ...\n\n".join(selected_chunks)

def answer_document_query(
    document_text: str,
    query: str,
    chat_history: list[dict] = None,
    api_key: str = None
) -> str:
    """
    Answers a query about the document using Groq API.
    Supports multi-turn chat history.
    """
    if not api_key or api_key == "YOUR_GROQ_API_KEY_HERE":
        return (
            "🔒 **Groq API Key Required**: Please configure your Groq API Key in the "
            "**Settings** panel in the sidebar to enable interactive AI Q&A over this document."
        )

    if not document_text or not document_text.strip():
        return "The document appears to be empty. Please upload a valid document first."

    # Retrieve context based on the query (handles oversized files dynamically)
    context = retrieve_relevant_context(document_text, query)
    
    # Constructing a system message that strictly grounds the model
    system_instruction = (
        "You are an AI Compliance & Security Assistant. "
        "Your sole task is to answer the user's questions about the uploaded document. "
        "Use ONLY the information in the provided document to answer. "
        "Do not make up facts or extrapolate beyond what is stated in the document. "
        "If the answer cannot be found in the document, say: "
        "'I could not find the answer to this question in the document content.' "
        "Always maintain a helpful, objective, and security-conscious tone."
    )
    
    # Build prompt with history
    formatted_history = []
    if chat_history:
        for msg in chat_history:
            role = "user" if msg.get("role") == "user" else "assistant"
            content = msg.get("content", "")
            formatted_history.append(f"{role.capitalize()}: {content}")
            
    history_str = "\n".join(formatted_history)
    
    prompt = f"""
    {system_instruction}
    
    DOCUMENT CONTENT:
    ---
    {context}
    ---
    
    CHAT HISTORY:
    {history_str}
    
    User's New Question: {query}
    
    Assistant:
    """
    
    try:
        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logger.error(f"Error during Q&A generation: {e}")
        return f"Sorry, I encountered an error while processing your request: {str(e)}"
