# SecureAgent
### AI-Powered Autonomous Security Posture Assessment Agent
**CIS 8397 Cybersecurity Capstone | Georgia State University | Spring 2026**

---

SecureAgent is an agentic AI pipeline built on LangGraph that conducts document-based cybersecurity posture assessments. It ingests organizational documents (policies, architecture diagrams, incident histories, vendor contracts) and produces a board-ready consulting report with NIST CSF 2.0 scoring, STRIDE threat analysis, MITRE ATT&CK mapping, risk register, FAIR risk quantification, and an 18-month remediation roadmap.

**Simulated Engagement:** MedBridge Health Systems (1,200-employee healthcare org, hybrid Azure + on-prem, Epic EHR, HIPAA-regulated)

**Comparable Tools:** GRC platforms such as Archer, ServiceNow GRC, CyberSaint — SecureAgent automates the initial document-analysis phase of a security assessment, similar in scope to what a consulting team would produce during a desktop review.

---

## Quick Start (All Free)

### 1. Get a Free API Key
- **Gemini** (primary): [aistudio.google.com](https://aistudio.google.com) — free tier: 15 req/min, no credit card
- **Groq** (alternative): [console.groq.com](https://console.groq.com) — free tier: 14,400 req/day

### 2. Setup Environment
```bash
git clone <repo-url>
cd secureagent
pip install -r requirements.txt
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY (or GROQ_API_KEY)
```

> **Security Note:** Never commit API keys. The `.env` file is in `.gitignore`. Copy `.env.example` to `.env` and add your keys there.

### 3. Download Framework Data
```bash
python scripts/download_frameworks.py
```

### 4. Run the Demo
```bash
streamlit run app/streamlit_app.py
```
Use the pre-loaded MedBridge corpus and watch the 5-agent pipeline run end-to-end.

### 5. Run Tests
```bash
pytest tests/ -v
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                 LangGraph State Machine              │
│                                                      │
│  [1] Ingestion → [2] Threat Modeling → [3] Assessment│
│       → [4] Gap Analysis → [5] Report Generation    │
└─────────────────────────────────────────────────────┘
```

| Agent | Purpose |
|---|---|
| **Ingestion Agent** | Parse documents; extract asset inventory, policies, vendor refs |
| **Threat Modeling Agent** | STRIDE analysis + MITRE ATT&CK technique mapping + kill chain |
| **Assessment Agent** | NIST CSF 2.0 maturity scoring (1–5) for all 6 functions |
| **Gap & Risk Agent** | Control gap identification; 15+ risk findings; FAIR Monte Carlo ALE |
| **Report Generation Agent** | Synthesize all outputs into professional consulting DOCX report |

### Data Provenance
Each agent tracks whether its output was LLM-generated or fell back to static templates. The generated report includes a **Data Provenance** appendix that discloses which sections used live AI analysis versus pre-defined data.

---

## Free Tech Stack

| Layer | Tool | Cost |
|---|---|---|
| LLM | Google Gemini 2.0 Flash (or Groq Llama 3.1) | Free |
| Embeddings | sentence-transformers `all-MiniLM-L6-v2` (local) | Free |
| Vector Store | ChromaDB (local) | Free |
| Agent Framework | LangGraph | Open source |
| Risk Quantification | FAIR Monte Carlo (numpy) | Open source |
| Report | python-docx | Open source |
| Frontend | Streamlit | Open source |

---

## Key Features

- **NIST CSF 2.0 Scoring:** All 6 functions scored with evidence-based justifications
- **STRIDE + MITRE ATT&CK:** 20+ threat scenarios mapped to healthcare-specific techniques
- **FAIR Monte Carlo:** 10,000-iteration simulation with P10/P90 confidence intervals (not just point estimates)
- **Vendor-Grounded Budget:** Roadmap with market-referenced cost estimates (CrowdStrike, Azure Sentinel, KnowBe4, etc.)
- **Human-in-the-Loop:** Risk register review step before report generation
- **Data Provenance:** Transparent tracking of LLM-generated vs. fallback-static content

---

## Limitations

- **Document-based only:** No live infrastructure scanning, vulnerability testing, or interviews. Findings are limited to what is documented in the provided corpus.
- **Simulated organization:** The MedBridge corpus is a synthetic dataset. Real-world assessments would require real organizational documents.
- **AI-assisted, not AI-autonomous:** The LLM generates analysis based on corpus content and prompts. Findings should be reviewed by qualified security professionals.
- **FAIR estimates are indicative:** Monte Carlo simulation provides probability ranges, but inputs are based on industry benchmarks, not actuarial data specific to the client organization.
- **Configurable but MedBridge-optimized:** While `config/org_profile.json` allows organization parameters to be changed, prompts and fallback data are currently tuned for a healthcare scenario.

---

## Future Work

- **Live infrastructure integration:** Connect to vulnerability scanners (Tenable, Qualys), cloud APIs (Azure, AWS), and identity providers for real-time evidence collection.
- **Multi-organization support:** Fully parameterized pipeline that adapts prompts and benchmarks to different industries and org sizes.
- **CI/CD integration:** Run assessments on a schedule as part of a continuous compliance pipeline.
- **Enhanced FAIR calibration:** Subject-matter-expert input tools for calibrating Monte Carlo distribution parameters.
- **Interactive remediation tracking:** Dashboard for tracking remediation progress against the roadmap.

---

## Sprint Roadmap

| Sprint | Weeks | Focus | Points |
|---|---|---|---|
| Sprint 1 | 1–2 | Foundation + Project Charter | 10 |
| Sprint 2 | 3–4 | Threat Modeling + Gap Analysis | 20 |
| Sprint 3 | 5–6 | Architecture + Working Demo | 22 |
| Sprint 4 | 7–8 | Final Report + Oral Defense | 43 |

---

## Project Structure

```
secureagent/
├── agents/             # 5 LangGraph agent nodes + state + validators
├── app/                # Streamlit demo UI
├── config/             # Settings, org_profile.json
├── corpus/             # 6 simulated MedBridge documents
├── report/             # python-docx report generator
├── tools/              # FAIR calculator, document parser
├── tests/              # Unit tests (pytest)
├── scripts/            # Framework data download
├── .env.example        # API key template (never commit .env)
└── requirements.txt    # All dependencies
```
