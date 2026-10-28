# 🛡️ Shadow AI Interception & Automated Redaction Proxy

> **Hackathon Prototype**: Enterprise Data Loss Prevention (DLP) Proxy Gateway for Generative AI & Public LLMs.

---

## 🎯 Overview

When corporate employees query public LLMs (like ChatGPT, Claude, or Gemini), they often inadvertently paste proprietary code, customer PII, AWS credentials, and financial metrics—creating catastrophic **"Shadow AI"** data leakage.

This prototype simulates a **Secure In-Line Corporate Proxy Gateway** that sits between employees and public LLMs:
1. **Intercepts** outgoing prompts in real time.
2. **Detects** sensitive data using Microsoft Presidio NER and custom cybersecurity recognizers.
3. **Redacts & Replaces** sensitive data with referentially consistent surrogate tokens (`[PERSON_1]`, `[SSN_1]`, `[CREDIT_CARD_1]`, `[API_KEY_1]`).
4. **Dispatches** the sanitized prompt to the external LLM.
5. **Re-hydrates** the response locally inside the corporate perimeter before displaying the completed answer to the employee.

---

## 🚀 Quick Start Instructions

### 1. Install Dependencies
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### 2. Run the Application
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## 🏗️ Architecture & Extensibility

```
[ Employee Terminal ]
        │
        ▼ (Raw Prompt with Sensitive PII/Secrets)
┌────────────────────────────────────────────────────────┐
│  Shadow AI In-Line Proxy Gateway                       │
│  ├─ 1. Interception Engine (Presidio + Custom Regex)   │
│  ├─ 2. Conflict Resolver & Policy Gate (PCI/HIPAA)     │
│  ├─ 3. Redaction Engine (Surrogate Tokens + Vault)     │
└────────────────────────────────────────────────────────┘
        │
        ▼ (Sanitized Prompt e.g. [PERSON_1], [SSN_1])
┌────────────────────────────────────────────────────────┐
│  Public LLM / Cloud Endpoint (ChatGPT, Ollama, etc.)   │
│  - Never sees actual SSN, Card numbers, or API keys!   │
└────────────────────────────────────────────────────────┘
        │
        ▼ (Sanitized Response)
┌────────────────────────────────────────────────────────┐
│  Local Re-hydration Vault (Corporate Perimeter)       │
│  - Restores [PERSON_1] -> John Doe for internal user  │
└────────────────────────────────────────────────────────┘
        │
        ▼
[ Safe, Context-Complete Answer Delivered to Employee ]
```

### Swapping in a Local Open-Source LLM (e.g. Ollama / vLLM)
In [`app.py`](app.py), we implemented an abstract `BaseLLMClient` interface:
```python
class BaseLLMClient(ABC):
    @abstractmethod
    def generate(self, sanitized_prompt: str) -> str:
        pass
```
- `MockLLMClient` is selected by default for zero-setup demonstrations.
- To connect to a local open-source LLM, start Ollama (`ollama run llama3.2`) and choose **Local Ollama** in the Streamlit sidebar!
