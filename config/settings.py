"""
SecureAgent Configuration
Loads environment variables and exposes typed config constants.
All LLM providers used here are on free tiers.
"""

import os
import json
import time
import logging
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ── LLM Keys (Free Providers) ─────────────────────────────────────────────────
GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.1-70b-versatile")

GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CORPUS_PATH: str = os.getenv("CORPUS_PATH", os.path.join(BASE_DIR, "corpus"))
FRAMEWORK_PATH: str = os.getenv("FRAMEWORK_PATH", os.path.join(BASE_DIR, "data", "frameworks"))
CHROMA_DB_PATH: str = os.getenv("CHROMA_DB_PATH", os.path.join(BASE_DIR, "data", "indices", "chroma_db"))
OUTPUT_PATH: str = os.getenv("OUTPUT_PATH", os.path.join(BASE_DIR, "output"))

NIST_CSF_PATH: str = os.path.join(FRAMEWORK_PATH, "nist_csf_2_0.json")
MITRE_ATTACK_PATH: str = os.path.join(FRAMEWORK_PATH, "mitre_attack_enterprise.json")
REPORT_TEMPLATE_PATH: str = os.path.join(BASE_DIR, "templates", "report_template.docx")

# ── Retry config for free-tier rate limits ────────────────────────────────────
MAX_RETRIES: int = int(os.getenv("LLM_MAX_RETRIES", "3"))
RETRY_BASE_DELAY: float = float(os.getenv("LLM_RETRY_DELAY", "15"))


class _RetryLLMWrapper:
    """Wraps a LangChain LLM and retries on rate-limit (429) errors with exponential backoff."""

    def __init__(self, llm, max_retries: int = MAX_RETRIES, base_delay: float = RETRY_BASE_DELAY):
        self._llm = llm
        self._max_retries = max_retries
        self._base_delay = base_delay

    def __getattr__(self, name):
        attr = getattr(self._llm, name)
        if name == "invoke":
            return self._wrap_invoke(attr)
        return attr

    def _wrap_invoke(self, original_invoke):
        def invoke_with_retry(*args, **kwargs):
            last_err = None
            for attempt in range(self._max_retries + 1):
                try:
                    return original_invoke(*args, **kwargs)
                except Exception as e:
                    err_str = str(e).lower()
                    is_rate_limit = "429" in err_str or "resource_exhausted" in err_str or "rate" in err_str
                    if is_rate_limit and attempt < self._max_retries:
                        delay = self._base_delay * (2 ** attempt)
                        logger.warning(
                            f"Rate limited (attempt {attempt + 1}/{self._max_retries + 1}). "
                            f"Waiting {delay:.0f}s before retry..."
                        )
                        time.sleep(delay)
                        last_err = e
                    else:
                        raise
            raise last_err
        return invoke_with_retry


def get_llm(with_retry: bool = True):
    """
    Returns a LangChain LLM client using free providers.
    Priority: Groq → Gemini (both free tier, no credit card required)

    Groq signup:   https://console.groq.com  (free: 14,400 req/day)
    Gemini signup: https://aistudio.google.com (free: 15 req/min)

    Args:
        with_retry: Wrap LLM with auto-retry on 429 rate limits (default True)
    """
    # Read keys at call time (not import time) so Streamlit secrets
    # injected into os.environ after module load are picked up.
    groq_key = os.getenv("GROQ_API_KEY", "")
    gemini_key = os.getenv("GEMINI_API_KEY", "")

    llm = None
    if groq_key:
        from langchain_groq import ChatGroq
        logger.info("Using Groq LLM (llama-3.1-70b-versatile)")
        llm = ChatGroq(
            model=GROQ_MODEL,
            api_key=groq_key,
            temperature=0.1,
        )
    elif gemini_key:
        from langchain_google_genai import ChatGoogleGenerativeAI
        logger.info("Using Gemini LLM (gemini-2.0-flash)")
        llm = ChatGoogleGenerativeAI(
            model=GEMINI_MODEL,
            google_api_key=gemini_key,
            temperature=0.1,
        )
    else:
        raise EnvironmentError(
            "No LLM API key found. Set GROQ_API_KEY or GEMINI_API_KEY in your .env file.\n"
            "Both are FREE:\n"
            "  Groq:   https://console.groq.com\n"
            "  Gemini: https://aistudio.google.com"
        )

    if with_retry:
        return _RetryLLMWrapper(llm)
    return llm


def get_org_profile() -> dict:
    """
    Load organization profile from config/org_profile.json.
    This decouples agent prompts from hardcoded MedBridge references.
    To assess a different organization, modify org_profile.json.
    """
    profile_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "org_profile.json")
    try:
        with open(profile_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"org_name": "Unknown Organization", "industry": "Unknown"}


# Convenience accessors
ORG_PROFILE = get_org_profile()
ORG_NAME: str = ORG_PROFILE.get("org_name", "Unknown Organization")
ORG_INDUSTRY: str = ORG_PROFILE.get("industry", "Unknown")


def get_embed_model():
    """
    Returns a free local embedding model via sentence-transformers.
    No API calls, no cost — runs on CPU.
    """
    from llama_index.embeddings.huggingface import HuggingFaceEmbedding
    return HuggingFaceEmbedding(model_name="sentence-transformers/all-MiniLM-L6-v2")
