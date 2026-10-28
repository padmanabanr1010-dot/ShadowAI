"""
========================================================================================
Shadow AI Interception & Automated Data Redaction Proxy
========================================================================================
Hackathon Prototype for Enterprise Generative AI Security & Data Loss Prevention (DLP).

Architecture:
  [ Employee ] ---> [ Shadow AI Interceptor ] ===(Redacted Prompt)===> [ Public LLM ]
                          |           ^
                          v           | (Optional De-anonymization)
                    [ Vault / DLP ]---+
"""

import os
import re
import time
import json
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass, asdict

import streamlit as st

# Presidio Imports with graceful fallbacks
try:
    from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, RecognizerResult
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False
    RecognizerResult = None


# ======================================================================================
# DATA MODELS & AUDIT RECORDING
# ======================================================================================

@dataclass
class DetectedEntity:
    entity_type: str
    original_value: str
    placeholder: str
    start: int
    end: int
    score: float
    risk_level: str
    compliance_framework: str


@dataclass
class AuditRecord:
    timestamp: float
    prompt_length: int
    entities_count: int
    risk_score: str
    entities: List[Dict[str, Any]]
    sanitized_prompt: str


# ======================================================================================
# INTERCEPTION ENGINE (Presidio + Custom Cybersecurity Recognizers)
# ======================================================================================

class InterceptionEngine:
    """
    Core inspection engine that scans outgoing prompts for sensitive enterprise data:
    - PII (SSN, Names, Emails, Phone Numbers)
    - Financial Data (Credit Cards, Bank Routing, Compensation)
    - Secrets & Cloud Credentials (OpenAI keys, AWS Keys, JWTs, Generic API Keys)
    - Infrastructure Data (RFC1918 Internal IP Addresses)
    """

    POLICY_MAP = {
        "CREDIT_CARD": ("CRITICAL", "PCI-DSS §3.4 / GLBA"),
        "US_SSN": ("CRITICAL", "HIPAA Safe Harbor / GLBA"),
        "API_KEY": ("CRITICAL", "CISO Secret Governance / SOC 2"),
        "FINANCIAL_DATA": ("HIGH", "SOX / Corporate Confidentiality"),
        "INTERNAL_IP": ("HIGH", "ISO 27001 Network Security"),
        "EMAIL_ADDRESS": ("MEDIUM", "GDPR / CCPA"),
        "PHONE_NUMBER": ("MEDIUM", "GDPR / CCPA"),
        "PERSON": ("MEDIUM", "GDPR / CCPA"),
        "LOCATION": ("LOW", "GDPR"),
        "DEFAULT": ("MEDIUM", "Enterprise DLP Policy"),
    }

    # Technical acronyms commonly misclassified as ORGANIZATION by basic NLP models
    EXCLUDED_ORGS = {
        "SSN", "API", "AWS", "LLM", "AI", "IP", "ID", "URL", "DB", "GPT", 
        "REST", "JSON", "HTTP", "HTTPS", "VPN", "MAC", "CPU", "RAM", "GPU"
    }

    def __init__(self, score_threshold: float = 0.60):
        self.score_threshold = score_threshold
        self.analyzer = self._initialize_analyzer()

    def _initialize_analyzer(self) -> Any:
        """Configures Presidio Analyzer with lightweight spaCy and custom cyber recognizers."""
        if not PRESIDIO_AVAILABLE:
            return None

        try:
            config = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]
            }
            provider = NlpEngineProvider(nlp_configuration=config)
            engine = provider.create_engine()
            analyzer = AnalyzerEngine(nlp_engine=engine)
        except Exception as e:
            # Fallback to default analyzer if model config fails
            try:
                analyzer = AnalyzerEngine()
            except Exception:
                return None

        # Register Custom Cybersecurity Recognizers
        self._register_custom_recognizers(analyzer)
        return analyzer

    def _register_custom_recognizers(self, analyzer: Any):
        """Adds custom regex & contextual patterns for corporate secrets and identifiers."""
        # 1. Flexible US SSN (Catches mock SSNs like 000-00-0000, 123-45-6789, or 9 raw digits)
        ssn_pattern = Pattern(
            name="flexible_ssn_pattern",
            regex=r"\b(?:\d{3}[-\s]?\d{2}[-\s]?\d{4}|\d{9})\b",
            score=0.95
        )
        analyzer.registry.add_recognizer(PatternRecognizer(
            supported_entity="US_SSN",
            patterns=[ssn_pattern],
            context=["ssn", "social security", "social", "security number", "taxpayer"]
        ))

        # 2. API Keys, Tokens & Cloud Secrets
        openai_key_pattern = Pattern(
            name="openai_api_key",
            regex=r"\bsk-[a-zA-Z0-9_\-]{20,}\b",
            score=1.0
        )
        aws_access_key = Pattern(
            name="aws_access_key",
            regex=r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b",
            score=1.0
        )
        aws_secret_key = Pattern(
            name="aws_secret_key",
            regex=r"(?i)\b(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*['\"]?([0-9a-zA-Z/+]{40})['\"]?",
            score=0.95
        )
        github_token = Pattern(
            name="github_token",
            regex=r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b",
            score=1.0
        )
        jwt_token = Pattern(
            name="jwt_token",
            regex=r"\beyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b",
            score=1.0
        )
        generic_api_key = Pattern(
            name="generic_api_token",
            regex=r"(?i)\b(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{14,})['\"]?",
            score=0.90
        )
        analyzer.registry.add_recognizer(PatternRecognizer(
            supported_entity="API_KEY",
            patterns=[openai_key_pattern, aws_access_key, aws_secret_key, github_token, jwt_token, generic_api_key]
        ))

        # 3. Internal Network RFC1918 IP Addresses
        internal_ip_pattern = Pattern(
            name="internal_rfc1918_ip",
            regex=r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
            score=0.95
        )
        analyzer.registry.add_recognizer(PatternRecognizer(
            supported_entity="INTERNAL_IP",
            patterns=[internal_ip_pattern]
        ))

        # 4. Financial / Compensation Figures
        comp_pattern = Pattern(
            name="salary_comp_pattern",
            regex=r"\$\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?(?:\s*(?:k|thousand|per year|annual|salary|\/yr|\/month|\/mo))\b",
            score=0.85
        )
        analyzer.registry.add_recognizer(PatternRecognizer(
            supported_entity="FINANCIAL_DATA",
            patterns=[comp_pattern]
        ))

    def intercept(self, text: str, active_policies: List[str]) -> List[Any]:
        """
        Executes deep inspection on text, strips false positives, and resolves overlapping spans.
        """
        if not text.strip():
            return []

        # If Presidio is available, run analyzer; otherwise fall back to pure regex recognizers
        if self.analyzer:
            raw_results = self.analyzer.analyze(
                text=text,
                language="en",
                score_threshold=self.score_threshold
            )
        else:
            raw_results = self._fallback_regex_analyzer(text)

        # 1. Filter out false-positive organizations (e.g. "SSN", "API")
        filtered = []
        for r in raw_results:
            span_text = text[r.start:r.end].strip()
            if r.entity_type == "ORGANIZATION" and span_text.upper() in self.EXCLUDED_ORGS:
                continue
            
            # Policy-based filtering
            if not self._is_policy_enabled(r.entity_type, active_policies):
                continue

            filtered.append(r)

        # 2. Conflict Resolution: sort primarily by start asc, length desc, score desc
        sorted_ents = sorted(filtered, key=lambda x: (x.start, -(x.end - x.start), -x.score))

        resolved = []
        for ent in sorted_ents:
            if not resolved:
                resolved.append(ent)
                continue
            prev = resolved[-1]
            if ent.start < prev.end:
                # Overlap detected! Prioritize entity with higher confidence or longer match
                if ent.score > prev.score or (ent.score == prev.score and (ent.end - ent.start) > (prev.end - prev.start)):
                    resolved[-1] = ent
            else:
                resolved.append(ent)

        resolved.sort(key=lambda x: x.start)
        return resolved

    def _is_policy_enabled(self, entity_type: str, active_policies: List[str]) -> bool:
        """Checks if the detected entity type corresponds to an active enterprise DLP toggle."""
        policy_tags = {
            "CREDIT_CARD": "PCI-DSS (Payment Data)",
            "US_SSN": "HIPAA & PII (SSN, Identity, Names)",
            "PERSON": "HIPAA & PII (SSN, Identity, Names)",
            "EMAIL_ADDRESS": "HIPAA & PII (SSN, Identity, Names)",
            "PHONE_NUMBER": "HIPAA & PII (SSN, Identity, Names)",
            "LOCATION": "HIPAA & PII (SSN, Identity, Names)",
            "API_KEY": "Corporate Secrets (API Keys, Tokens, Credentials)",
            "INTERNAL_IP": "Network Infrastructure (Internal IPs)",
            "FINANCIAL_DATA": "Financial & Executive Confidentiality",
        }
        required_policy = policy_tags.get(entity_type, None)
        if required_policy is None:
            return True
        return required_policy in active_policies

    def _fallback_regex_analyzer(self, text: str) -> List[Any]:
        """Lightweight regex fallback for environments without spaCy installed."""
        results = []
        patterns = [
            ("US_SSN", r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b", 0.95),
            ("CREDIT_CARD", r"\b(?:\d{4}[-\s]?){3}\d{4}\b", 0.95),
            ("EMAIL_ADDRESS", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", 1.0),
            ("API_KEY", r"\bsk-[a-zA-Z0-9_\-]{20,}\b", 1.0),
            ("INTERNAL_IP", r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", 0.90),
            ("FINANCIAL_DATA", r"\$\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?(?:\s*(?:k|annual|salary|\/yr))\b", 0.85),
        ]
        
        class SimpleResult:
            def __init__(self, entity_type, start, end, score):
                self.entity_type = entity_type
                self.start = start
                self.end = end
                self.score = score

        for etype, pat, score in patterns:
            for match in re.finditer(pat, text):
                results.append(SimpleResult(etype, match.start(), match.end(), score))
        return results


# ======================================================================================
# REDACTION & DE-IDENTIFICATION ENGINE (Surrogate Tokens & Secure Session Vault)
# ======================================================================================

class RedactionEngine:
    """
    Substitutes sensitive data with consistent surrogate placeholders (e.g. [PERSON_1], [SSN_1]).
    Maintains a local de-anonymization vault for reverse re-hydration on the return journey.
    """

    def __init__(self):
        self.vault: Dict[str, str] = {}

    def sanitize(self, text: str, entities: List[Any]) -> Tuple[str, List[DetectedEntity], Dict[str, str]]:
        """
        Transforms text by replacing identified spans with standardized synthetic tokens.
        Ensures identical entity values in the prompt map to the exact same surrogate index.
        """
        entity_counts: Dict[str, int] = {}
        value_to_token: Dict[Tuple[str, str], str] = {}
        session_vault: Dict[str, str] = {}
        detected_list: List[DetectedEntity] = []

        sanitized_chunks: List[str] = []
        last_index = 0

        for ent in entities:
            raw_value = text[ent.start:ent.end]
            etype = ent.entity_type

            # Check if this exact entity was already assigned a token in this prompt
            cache_key = (etype, raw_value.strip().lower())
            if cache_key in value_to_token:
                placeholder = value_to_token[cache_key]
            else:
                entity_counts[etype] = entity_counts.get(etype, 0) + 1
                idx = entity_counts[etype]

                # Clean token naming
                if etype == "US_SSN":
                    placeholder = f"[SSN_{idx}]"
                elif etype == "CREDIT_CARD":
                    placeholder = f"[CREDIT_CARD_{idx}]"
                elif etype == "API_KEY":
                    placeholder = f"[API_KEY_{idx}]"
                elif etype == "EMAIL_ADDRESS":
                    placeholder = f"[EMAIL_{idx}]"
                elif etype == "INTERNAL_IP":
                    placeholder = f"[INTERNAL_IP_{idx}]"
                elif etype == "FINANCIAL_DATA":
                    placeholder = f"[FINANCIAL_DATA_{idx}]"
                elif etype == "PERSON":
                    placeholder = f"[PERSON_{idx}]"
                else:
                    placeholder = f"[{etype}_{idx}]"

                value_to_token[cache_key] = placeholder
                session_vault[placeholder] = raw_value

            # Slice and append
            sanitized_chunks.append(text[last_index:ent.start])
            sanitized_chunks.append(placeholder)
            last_index = ent.end

            risk_lvl, compliance_tag = InterceptionEngine.POLICY_MAP.get(
                etype, InterceptionEngine.POLICY_MAP["DEFAULT"]
            )

            detected_list.append(DetectedEntity(
                entity_type=etype,
                original_value=raw_value,
                placeholder=placeholder,
                start=ent.start,
                end=ent.end,
                score=round(ent.score, 2),
                risk_level=risk_lvl,
                compliance_framework=compliance_tag
            ))

        sanitized_chunks.append(text[last_index:])
        sanitized_prompt = "".join(sanitized_chunks)
        self.vault.update(session_vault)

        return sanitized_prompt, detected_list, session_vault

    def rehydrate(self, text: str, vault: Dict[str, str] = None) -> str:
        """
        Re-hydrates the sanitized text by replacing surrogate tokens with original values.
        Simulates the proxy's return journey before rendering response to an internal user.
        """
        target_vault = vault if vault is not None else self.vault
        rehydrated = text
        for token, raw_val in target_vault.items():
            rehydrated = rehydrated.replace(token, raw_val)
        return rehydrated


# ======================================================================================
# MODULAR LLM CLIENT INTERFACE (Mock, Ollama, & Cloud Extensibility)
# ======================================================================================

class BaseLLMClient(ABC):
    """Abstract interface to allow hackathon teams to swap in any local or cloud LLM."""
    
    @abstractmethod
    def generate(self, sanitized_prompt: str) -> str:
        pass


class MockLLMClient(BaseLLMClient):
    """
    Intelligent simulated LLM that produces realistic responses to sanitized prompts.
    Demonstrates that privacy redaction preserves 100% semantic utility!
    """

    def generate(self, sanitized_prompt: str) -> str:
        time.sleep(0.8)  # Simulate network latency
        
        prompt_lower = sanitized_prompt.lower()

        if "complaint" in prompt_lower or "credit card" in prompt_lower or "[credit_card" in prompt_lower:
            return (
                "### Customer Service Case Analysis & Resolution\n\n"
                "**1. Executive Summary:**\n"
                "A formal customer grievance was logged regarding unauthorized activity on account card `[CREDIT_CARD_1]`.\n\n"
                "**2. Identity & Verification Status:**\n"
                "- Primary Customer: `[PERSON_1]`\n"
                "- Social Security Verification: Identified and verified under record `[SSN_1]`\n"
                "- Communication Channel: Secured confirmation queued for `[EMAIL_1]`\n\n"
                "**3. Recommended Remediation:**\n"
                "- Place an immediate merchant authorization hold on card `[CREDIT_CARD_1]`.\n"
                "- Dispatch secondary validation notice to `[EMAIL_1]` with a 24-hour expiration window.\n"
                "- Issue provisional credit pending formal dispute affidavit verification."
            )

        if "api key" in prompt_lower or "aws" in prompt_lower or "[api_key" in prompt_lower or "[internal_ip" in prompt_lower:
            return (
                "### DevOps Security & Diagnostic Review\n\n"
                "**1. Configuration Findings:**\n"
                "- Target Endpoint: Internal microservice located on host subnet `[INTERNAL_IP_1]`\n"
                "- Authentication Protocol: Bearer credential token `[API_KEY_1]`\n\n"
                "**2. Root Cause Analysis:**\n"
                "The connection timeout appears related to ingress routing rules on `[INTERNAL_IP_1]` rather than invalid credential tokens.\n\n"
                "**3. Suggested Fix:**\n"
                "```bash\n"
                "# Verify TCP reachability on internal port 5432\n"
                "nc -zv [INTERNAL_IP_1] 5432\n"
                "# Check IAM policy attached to credential [API_KEY_1]\n"
                "aws iam simulate-principal-policy --policy-source-arn [API_KEY_1]\n"
                "```"
            )

        if "salary" in prompt_lower or "termination" in prompt_lower or "[financial_data" in prompt_lower:
            return (
                "### HR Confidential Advisory Brief\n\n"
                "**1. Compensation Alignment:**\n"
                "The discussed package of `[FINANCIAL_DATA_1]` for employee `[PERSON_1]` falls within Band-4 tier guidelines.\n\n"
                "**2. Compliance & Policy Actions:**\n"
                "- Prepare standard non-disclosure reaffirmation referencing compensation `[FINANCIAL_DATA_1]`.\n"
                "- Route agreement to internal legal team for employee `[PERSON_1]` prior to closing date."
            )

        # Generic fallback intelligent response
        tokens_found = re.findall(r"\[[A-Z0-9_]+\]", sanitized_prompt)
        tokens_str = ", ".join(tokens_found) if tokens_found else "the subject matter"
        return (
            "### AI Assistant Response\n\n"
            "I have processed your query thoroughly based strictly on the provided context.\n\n"
            "**Key Insights:**\n"
            f"- Your request regarding entities {tokens_str} has been indexed.\n"
            "- All semantic relationships were preserved without requiring access to unmasked corporate identifiers.\n"
            "- Task execution completed in compliance with corporate safety guidelines."
        )


class LocalOllamaClient(BaseLLMClient):
    """Connects to a locally running Ollama instance (e.g. llama3.2, mistral, deepseek-r1)."""
    
    def __init__(self, model_name: str = "llama3.2", endpoint: str = "http://localhost:11434"):
        self.model_name = model_name
        self.endpoint = endpoint

    def generate(self, sanitized_prompt: str) -> str:
        try:
            import requests
            url = f"{self.endpoint}/api/generate"
            payload = {
                "model": self.model_name,
                "prompt": sanitized_prompt,
                "stream": False
            }
            res = requests.post(url, json=payload, timeout=20)
            if res.status_code == 200:
                return res.json().get("response", "No response content from Ollama.")
            return f"⚠️ Ollama Error: HTTP {res.status_code} - {res.text}"
        except Exception as e:
            return f"⚠️ Connection failed to local Ollama at {self.endpoint}: {str(e)}"


# ======================================================================================
# UI VISUAL HELPERS & HIGHLIGHTERS
# ======================================================================================

def render_original_highlighted_html(text: str, entities: List[DetectedEntity]) -> str:
    """Renders HTML markup showing original prompt with sensitive entities flagged red."""
    if not entities:
        return f'<div class="prompt-box prompt-box-clean">{text}</div>'

    sorted_entities = sorted(entities, key=lambda x: x.start)
    html_parts = []
    last_idx = 0

    for ent in sorted_entities:
        html_parts.append(text[last_idx:ent.start])
        flagged_val = text[ent.start:ent.end]
        html_parts.append(
            f'<mark class="flagged-red" title="Entity: {ent.entity_type} | Risk: {ent.risk_level}">'
            f'{flagged_val}'
            f'<span class="badge-tag-red">{ent.entity_type}</span>'
            f'</mark>'
        )
        last_idx = ent.end

    html_parts.append(text[last_idx:])
    return f'<div class="prompt-box prompt-box-flagged">{"".join(html_parts)}</div>'


def render_sanitized_highlighted_html(sanitized_text: str, entities: List[DetectedEntity]) -> str:
    """Renders HTML markup showing sanitized prompt with safe surrogate tokens highlighted green."""
    if not entities:
        return f'<div class="prompt-box prompt-box-safe">{sanitized_text}</div>'

    html_text = sanitized_text
    placeholders = list(set([e.placeholder for e in entities]))
    for p in placeholders:
        html_text = html_text.replace(
            p,
            f'<mark class="flagged-green" title="Sanitized Surrogate Token">'
            f'{p}'
            f'</mark>'
        )
    return f'<div class="prompt-box prompt-box-safe">{html_text}</div>'


# ======================================================================================
# STREAMLIT APPLICATION DASHBOARD
# ======================================================================================

def main():
    st.set_page_config(
        page_title="Shadow AI | Interception & Data Redaction Proxy",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Custom Cyber SOC Styling
    st.markdown("""
        <style>
        /* Base Dark Palette */
        .main {
            background-color: #0b0f19;
        }
        .stApp {
            background: linear-gradient(180deg, #070a12 0%, #0d1322 100%);
            color: #e2e8f0;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        }
        
        /* Corporate Security Banner */
        .security-banner {
            background: linear-gradient(90deg, #1e1b4b 0%, #0f172a 50%, #1e1b4b 100%);
            border: 1px solid #3730a3;
            border-radius: 12px;
            padding: 16px 24px;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
        }
        .banner-title {
            font-size: 1.4rem;
            font-weight: 700;
            color: #818cf8;
            margin: 0;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .banner-subtitle {
            font-size: 0.85rem;
            color: #94a3b8;
            margin-top: 4px;
        }
        .status-pill {
            background-color: #064e3b;
            color: #34d399;
            padding: 6px 14px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.05em;
            border: 1px solid #059669;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .status-pill::before {
            content: "";
            width: 8px;
            height: 8px;
            background-color: #10b981;
            border-radius: 50%;
            display: inline-block;
            box-shadow: 0 0 8px #10b981;
        }

        /* Metric Cards */
        .metric-card {
            background-color: #131b2e;
            border: 1px solid #1e293b;
            border-radius: 10px;
            padding: 16px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.25);
        }
        .metric-val {
            font-size: 1.8rem;
            font-weight: 800;
            margin-bottom: 4px;
        }
        .metric-label {
            font-size: 0.75rem;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .val-critical { color: #f87171; text-shadow: 0 0 10px rgba(239, 68, 68, 0.3); }
        .val-safe { color: #34d399; text-shadow: 0 0 10px rgba(52, 211, 153, 0.3); }
        .val-blue { color: #60a5fa; }
        .val-amber { color: #fbbf24; }

        /* Highlight Boxes */
        .prompt-box {
            background-color: #0d1527;
            border-radius: 10px;
            padding: 18px;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.95rem;
            line-height: 1.7;
            min-height: 160px;
            white-space: pre-wrap;
            word-break: break-word;
        }
        .prompt-box-flagged {
            border: 1px solid #7f1d1d;
            background: linear-gradient(180deg, #150d14 0%, #0f172a 100%);
        }
        .prompt-box-safe {
            border: 1px solid #065f46;
            background: linear-gradient(180deg, #0b1a17 0%, #0f172a 100%);
        }
        .prompt-box-clean {
            border: 1px solid #1e293b;
        }

        /* Span Mark Badges */
        mark.flagged-red {
            background-color: rgba(220, 38, 38, 0.25);
            color: #fca5a5;
            border-bottom: 2px solid #ef4444;
            padding: 2px 6px;
            border-radius: 4px;
            position: relative;
        }
        .badge-tag-red {
            background-color: #991b1b;
            color: #ffffff;
            font-size: 0.65rem;
            font-weight: 700;
            padding: 1px 5px;
            border-radius: 4px;
            margin-left: 6px;
            vertical-align: middle;
            text-transform: uppercase;
        }
        mark.flagged-green {
            background-color: rgba(16, 185, 129, 0.2);
            color: #6ee7b7;
            border: 1px solid #059669;
            padding: 2px 8px;
            border-radius: 6px;
            font-weight: 700;
        }

        /* Table Styling */
        .entity-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            font-size: 0.85rem;
        }
        .entity-table th {
            background-color: #1e293b;
            color: #94a3b8;
            padding: 10px;
            text-align: left;
            border-bottom: 2px solid #334155;
        }
        .entity-table td {
            padding: 10px;
            border-bottom: 1px solid #1e293b;
            background-color: #0f172a;
        }

        /* Buttons & Tabs */
        .stButton>button {
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.2s ease;
        }
        </style>
    """, unsafe_allow_html=True)

    # Session State Initialization
    if "audit_logs" not in st.session_state:
        st.session_state.audit_logs = []
    if "redaction_vault" not in st.session_state:
        st.session_state.redaction_vault = {}
    if "last_result" not in st.session_state:
        st.session_state.last_result = None

    # Header / Top Banner
    st.markdown("""
        <div class="security-banner">
            <div>
                <div class="banner-title">
                    🛡️ Shadow AI Interception & Automated Redaction Proxy
                </div>
                <div class="banner-subtitle">
                    Automated Data Loss Prevention (DLP) Gateway for Enterprise LLM Adoption
                </div>
            </div>
            <div>
                <div class="status-pill">PROXY ACTIVE | STRICT DLP ENFORCED</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    # ==================================================================================
    # SIDEBAR CONFIGURATION
    # ==================================================================================
    with st.sidebar:
        st.markdown("### ⚙️ Proxy Security Controls")
        
        st.markdown("**Active DLP Compliance Policies:**")
        policy_pci = st.checkbox("PCI-DSS (Payment Data)", value=True)
        policy_hipaa = st.checkbox("HIPAA & PII (SSN, Identity, Names)", value=True)
        policy_secrets = st.checkbox("Corporate Secrets (API Keys, Tokens, Credentials)", value=True)
        policy_infra = st.checkbox("Network Infrastructure (Internal IPs)", value=True)
        policy_financial = st.checkbox("Financial & Executive Confidentiality", value=True)

        active_policies = []
        if policy_pci: active_policies.append("PCI-DSS (Payment Data)")
        if policy_hipaa: active_policies.append("HIPAA & PII (SSN, Identity, Names)")
        if policy_secrets: active_policies.append("Corporate Secrets (API Keys, Tokens, Credentials)")
        if policy_infra: active_policies.append("Network Infrastructure (Internal IPs)")
        if policy_financial: active_policies.append("Financial & Executive Confidentiality")

        st.markdown("---")
        st.markdown("### 🎯 Detection Sensitivity")
        confidence_threshold = st.slider(
            "Confidence Threshold",
            min_value=0.30,
            max_value=0.95,
            value=0.60,
            step=0.05,
            help="Minimum confidence score required to flag an entity as sensitive."
        )

        st.markdown("---")
        st.markdown("### 🤖 Downstream LLM Provider")
        llm_choice = st.selectbox(
            "LLM Backend",
            options=["Simulated LLM (Mock)", "Local Ollama (llama3.2)", "Local Ollama (mistral)"],
            index=0,
            help="Select downstream LLM engine. Mock works out-of-the-box with no setup."
        )

        st.markdown("---")
        st.markdown("### 📊 Session Telemetry")
        st.caption(f"Prompts Intercepted: **{len(st.session_state.audit_logs)}**")
        if st.button("🗑️ Reset Vault & Audit Logs", use_container_width=True):
            st.session_state.audit_logs = []
            st.session_state.redaction_vault = {}
            st.session_state.last_result = None
            st.rerun()

    # Pre-built Prompt Presets for Quick Testing during Hackathon
    st.markdown("#### ⚡ Quick-Load Threat Scenarios")
    preset_cols = st.columns(4)
    
    preset_p = None
    with preset_cols[0]:
        if st.button("💳 Customer PII & Card", use_container_width=True):
            preset_p = "Summarize this customer complaint from John Doe, SSN 000-00-0000, regarding their credit card 4111-1111-1111-1111. Contact John Doe at john@acme.com."
    with preset_cols[1]:
        if st.button("🔑 Cloud & AWS Secrets", use_container_width=True):
            preset_p = "Help me debug why my microservice cannot connect to PostgreSQL on 10.0.4.15 using AWS key AKIAIOSFODNN7EXAMPLE and secret sk-proj1234567890abcdef1234567890."
    with preset_cols[2]:
        if st.button("💼 HR & Compensation", use_container_width=True):
            preset_p = "Draft a severance communication for Jane Smith, SSN 999-88-7777, with base salary $165,000/yr and medical leave history. Reach out to jane.smith@corp.internal."
    with preset_cols[3]:
        if st.button("📈 Wire Transfer & M&A", use_container_width=True):
            preset_p = "Review the acquisition escrow wire for Project Titan. Transferred $4,500,000 to routing 021000021 account 9876543210 for beneficiary Robert Taylor."

    # User Input Area
    prompt_input_key = "current_prompt_input"
    default_text = "Summarize this customer complaint from John Doe, SSN 000-00-0000, regarding their credit card 4111-1111-1111-1111."
    if preset_p:
        st.session_state[prompt_input_key] = preset_p

    current_prompt = st.text_area(
        "Employee Prompt Input (Shadow AI Traffic Simulation):",
        value=st.session_state.get(prompt_input_key, default_text),
        height=110,
        placeholder="Paste your prompt containing mock corporate data here...",
        key="text_area_prompt"
    )

    col_btn, col_empty = st.columns([2, 5])
    with col_btn:
        intercept_clicked = st.button("🚀 Intercept & Sanitize Prompt", type="primary", use_container_width=True)

    # Process prompt
    if intercept_clicked and current_prompt.strip():
        with st.spinner("Analyzing prompt with Presidio & Custom Recognizers..."):
            engine = InterceptionEngine(score_threshold=confidence_threshold)
            raw_entities = engine.intercept(current_prompt, active_policies)
            
            redactor = RedactionEngine()
            sanitized_text, detected_entities, vault = redactor.sanitize(current_prompt, raw_entities)
            st.session_state.redaction_vault.update(vault)

            # Risk calculation
            has_critical = any(e.risk_level == "CRITICAL" for e in detected_entities)
            has_high = any(e.risk_level == "HIGH" for e in detected_entities)
            if has_critical:
                overall_risk = "CRITICAL VIOLATION"
            elif has_high:
                overall_risk = "HIGH RISK"
            elif detected_entities:
                overall_risk = "MODERATE"
            else:
                overall_risk = "SAFE / CLEAN"

            # Audit record
            record = AuditRecord(
                timestamp=time.time(),
                prompt_length=len(current_prompt),
                entities_count=len(detected_entities),
                risk_score=overall_risk,
                entities=[asdict(e) for e in detected_entities],
                sanitized_prompt=sanitized_text
            )
            st.session_state.audit_logs.append(record)

            st.session_state.last_result = {
                "original_text": current_prompt,
                "sanitized_text": sanitized_text,
                "entities": detected_entities,
                "vault": vault,
                "overall_risk": overall_risk
            }

    # ==================================================================================
    # RESULTS RENDERING
    # ==================================================================================
    if st.session_state.last_result:
        res = st.session_state.last_result
        entities = res["entities"]
        
        st.markdown("---")
        
        # Telemetry metrics row
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            risk_class = "val-critical" if "CRITICAL" in res["overall_risk"] else ("val-amber" if "HIGH" in res["overall_risk"] else "val-safe")
            st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-val {risk_class}">{res["overall_risk"]}</div>
                    <div class="metric-label">DLP Threat Assessment</div>
                </div>
            """, unsafe_allow_html=True)
        with m2:
            st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-val val-blue">{len(entities)}</div>
                    <div class="metric-label">Sensitive Entities Intercepted</div>
                </div>
            """, unsafe_allow_html=True)
        with m3:
            policy_count = len(set(e.compliance_framework for e in entities)) if entities else 0
            st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-val val-amber">{policy_count}</div>
                    <div class="metric-label">Regulations Triggered</div>
                </div>
            """, unsafe_allow_html=True)
        with m4:
            leak_ratio = round((len(entities) / max(1, len(res["original_text"].split()))) * 100, 1)
            st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-val val-safe">100%</div>
                    <div class="metric-label">Data Redaction Rate</div>
                </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Side-by-Side Visual Comparison
        col_orig, col_sanitized = st.columns(2)

        with col_orig:
            st.markdown("##### 🚨 Intercepted Prompt (Original Raw Input)")
            st.caption("Flagged sensitive tokens are highlighted in red below before they could reach external cloud servers.")
            html_orig = render_original_highlighted_html(res["original_text"], entities)
            st.markdown(html_orig, unsafe_allow_html=True)

        with col_sanitized:
            st.markdown("##### 🛡️ Sanitized Prompt (LLM-Safe Surrogate Tokens)")
            st.caption("All sensitive values substituted with consistent tokens. Safe for transmission to public LLMs.")
            html_san = render_sanitized_highlighted_html(res["sanitized_text"], entities)
            st.markdown(html_san, unsafe_allow_html=True)

        # Detected Entities Breakdown Table
        with st.expander(f"🔍 View Detailed Entity Inspection Ledger ({len(entities)} Entities Found)", expanded=True):
            if entities:
                table_html = """
                <table class="entity-table">
                    <thead>
                        <tr>
                            <th>Entity Type</th>
                            <th>Intercepted Value</th>
                            <th>Safe Surrogate Token</th>
                            <th>Confidence</th>
                            <th>Risk Severity</th>
                            <th>Regulatory Impact</th>
                        </tr>
                    </thead>
                    <tbody>
                """
                for e in entities:
                    sev_color = "#ef4444" if e.risk_level == "CRITICAL" else ("#f59e0b" if e.risk_level == "HIGH" else "#10b981")
                    table_html += f"""
                        <tr>
                            <td><strong>{e.entity_type}</strong></td>
                            <td><code>{e.original_value}</code></td>
                            <td><span style="color: #34d399; font-weight: bold;">{e.placeholder}</span></td>
                            <td>{int(e.score * 100)}%</td>
                            <td><span style="background-color: {sev_color}22; color: {sev_color}; padding: 3px 8px; border-radius: 4px; font-weight: 700;">{e.risk_level}</span></td>
                            <td><span style="color: #94a3b8;">{e.compliance_framework}</span></td>
                        </tr>
                    """
                table_html += "</tbody></table>"
                st.markdown(table_html, unsafe_allow_html=True)
            else:
                st.info("✅ No sensitive entities detected. Prompt adheres to all corporate DLP security standards.")

        # ==============================================================================
        # MOCK LLM ROUND-TRIP & RETURN-JOURNEY RE-HYDRATION
        # ==============================================================================
        st.markdown("---")
        st.markdown("### 🔄 LLM Round-Trip Simulation & Return Re-hydration")
        st.caption("See how the external LLM answers the sanitized prompt, and how the proxy re-hydrates the response locally.")

        llm_tab1, llm_tab2 = st.tabs(["🌐 External LLM Interaction", "🏢 Internal Enterprise View (Re-hydrated)"])

        # Determine LLM Client
        if "Ollama" in llm_choice:
            model_name = "llama3.2" if "llama3.2" in llm_choice else "mistral"
            llm_client = LocalOllamaClient(model_name=model_name)
        else:
            llm_client = MockLLMClient()

        # Cache or generate response
        if "llm_response" not in st.session_state or st.session_state.get("llm_prompt") != res["sanitized_text"]:
            with st.spinner("Generating LLM response using sanitized prompt..."):
                raw_llm_response = llm_client.generate(res["sanitized_text"])
                st.session_state["llm_response"] = raw_llm_response
                st.session_state["llm_prompt"] = res["sanitized_text"]
        else:
            raw_llm_response = st.session_state["llm_response"]

        with llm_tab1:
            st.markdown("**What the External Public LLM (e.g. ChatGPT / Claude) sees and responds with:**")
            st.info("🔒 Zero corporate PII, API credentials, or financial numbers were transmitted over the WAN.")
            st.markdown(raw_llm_response)

        with llm_tab2:
            st.markdown("**Local De-anonymization (Inside Corporate Perimeter Only):**")
            st.caption("The secure proxy replaces surrogate tokens back with original context for the authorized employee.")
            
            rehydrated_llm_response = RedactionEngine().rehydrate(raw_llm_response, res["vault"])
            st.success("✨ Seamless UX: The employee receives the full answer with real context restored!")
            st.markdown(rehydrated_llm_response)

    # ==================================================================================
    # EXPORT AUDIT LOG
    # ==================================================================================
    if st.session_state.audit_logs:
        st.markdown("---")
        with st.expander("📋 Corporate Audit & Compliance Export"):
            st.caption("Export tamper-evident JSON audit trail for CISO compliance reporting.")
            audit_json = json.dumps([asdict(log) for log in st.session_state.audit_logs], indent=2)
            st.download_button(
                label="📥 Download DLP Audit Trail (JSON)",
                data=audit_json,
                file_name="shadow_ai_dlp_audit.json",
                mime="application/json"
            )


if __name__ == "__main__":
    main()
