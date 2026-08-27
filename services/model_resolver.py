import os
import logging
from groq import Groq

logger = logging.getLogger(__name__)

# Cached model selection to avoid querying the API on every request
_RESOLVED_MODEL = None

def get_groq_model(api_key: str) -> str:
    """
    Dynamically resolves the best available Groq model.
    Checks the GROQ_MODEL environment variable first.
    If not set, queries the Groq API and matches against a preference list.
    """
    global _RESOLVED_MODEL
    
    # 1. Check if a model is explicitly configured in environment
    env_model = os.getenv("GROQ_MODEL")
    if env_model:
        return env_model
        
    # 2. Return cached model if already resolved
    if _RESOLVED_MODEL:
        return _RESOLVED_MODEL

    default_model = "llama-3.3-70b-versatile"
    
    if not api_key or api_key == "YOUR_GROQ_API_KEY_HERE":
        return default_model

    try:
        client = Groq(api_key=api_key)
        models = client.models.list()
        available_ids = [m.id for m in models.data]
        
        # Priority list of preferred models
        preferred_models = [
            "llama-3.3-70b-versatile",
            "openai/gpt-oss-120b",
            "groq/compound",
            "qwen/qwen3.8-27b",
            "openai/gpt-oss-20b",
            "groq/compound-mini",
            "llama-3.1-70b-versatile",
            "llama3-70b-8192"
        ]
        
        for model_id in preferred_models:
            if model_id in available_ids:
                logger.info(f"Dynamically resolved Groq model to: {model_id}")
                _RESOLVED_MODEL = model_id
                return model_id
                
        # Fallback to the first non-whisper, non-guard model
        if available_ids:
            chat_models = [mid for mid in available_ids if "whisper" not in mid.lower() and "guard" not in mid.lower()]
            resolved = chat_models[0] if chat_models else available_ids[0]
            logger.info(f"No preferred models found. Dynamically fell back to: {resolved}")
            _RESOLVED_MODEL = resolved
            return resolved
            
    except Exception as e:
        logger.error(f"Failed to query Groq models list: {e}. Falling back to default: {default_model}")
        
    return default_model
