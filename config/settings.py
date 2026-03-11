"""
SecureAgent Configuration
Loads environment variables and exposes typed config constants.
All LLM providers used here are on free tiers.
"""

import os
import json
from dotenv import load_dotenv

load_dotenv()

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


def get_llm():
    """
    Returns a LangChain LLM client using free providers.
    Priority: Groq → Gemini (both free tier, no credit card required)

    Groq signup:   https://console.groq.com  (free: 14,400 req/day)
    Gemini signup: https://aistudio.google.com (free: 15 req/min)
    """
    if GROQ_API_KEY:
        from langchain_groq import ChatGroq
        return ChatGroq(
            model=GROQ_MODEL,
            api_key=GROQ_API_KEY,
            temperature=0.1,
        )
    elif GEMINI_API_KEY:
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(
            model=GEMINI_MODEL,
            google_api_key=GEMINI_API_KEY,
            temperature=0.1,
        )
    else:
        raise EnvironmentError(
            "No LLM API key found. Set GROQ_API_KEY or GEMINI_API_KEY in your .env file.\n"
            "Both are FREE:\n"
            "  Groq:   https://console.groq.com\n"
            "  Gemini: https://aistudio.google.com"
        )


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
