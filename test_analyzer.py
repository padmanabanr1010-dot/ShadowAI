"""
Test prototype to verify Presidio with custom recognizers and surrogate anonymization.
"""
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider

def get_test_analyzer():
    config = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]
    }
    engine = NlpEngineProvider(nlp_configuration=config).create_engine()
    analyzer = AnalyzerEngine(nlp_engine=engine)

    # 1. Flexible US SSN Recognizer
    ssn_pattern = Pattern(
        name="flexible_ssn",
        regex=r"\b(?:\d{3}[-\s]?\d{2}[-\s]?\d{4}|\d{9})\b",
        score=0.95
    )
    ssn_recognizer = PatternRecognizer(
        supported_entity="US_SSN",
        patterns=[ssn_pattern],
        context=["ssn", "social security", "social", "security number", "taxpayer"]
    )
    analyzer.registry.add_recognizer(ssn_recognizer)

    # 2. API Keys Recognizer
    openai_pattern = Pattern(name="openai_key", regex=r"\bsk-[a-zA-Z0-9_-]{20,}\b", score=1.0)
    aws_pattern = Pattern(name="aws_key", regex=r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b", score=1.0)
    github_pattern = Pattern(name="github_token", regex=r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b", score=1.0)
    jwt_pattern = Pattern(name="jwt_token", regex=r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b", score=1.0)
    generic_key_pattern = Pattern(
        name="generic_api_key",
        regex=r"(?i)\b(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|bearer)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{16,})['\"]?",
        score=0.9
    )
    analyzer.registry.add_recognizer(PatternRecognizer(
        supported_entity="API_KEY",
        patterns=[openai_pattern, aws_pattern, github_pattern, jwt_pattern, generic_key_pattern]
    ))

    # 3. Internal Network IP Recognizer
    ip_pattern = Pattern(
        name="private_ip",
        regex=r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        score=0.95
    )
    analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="INTERNAL_IP", patterns=[ip_pattern]))

    # 4. Financial / Compensation Data
    salary_pattern = Pattern(
        name="salary_comp",
        regex=r"\$\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?(?:\s*(?:k|thousand|per year|annual|salary|\/yr|\/month|\/mo))\b",
        score=0.85
    )
    analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="FINANCIAL_DATA", patterns=[salary_pattern]))

    return analyzer

def redact_and_map(text: str, entities):
    # Filter false positives
    filtered = []
    for r in entities:
        val = text[r.start:r.end].strip()
        if r.entity_type == "ORGANIZATION" and val.upper() in ["SSN", "API", "AWS", "LLM", "AI", "IP", "ID", "URL", "DB"]:
            continue
        filtered.append(r)

    # Sort primarily by start asc, length desc, score desc
    sorted_ents = sorted(filtered, key=lambda x: (x.start, -(x.end - x.start), -x.score))

    # Conflict resolution for overlapping spans
    resolved = []
    for ent in sorted_ents:
        if not resolved:
            resolved.append(ent)
            continue
        prev = resolved[-1]
        # Check overlap
        if ent.start < prev.end:
            # Overlapping! Choose the one with higher score or longer match
            if ent.score > prev.score or (ent.score == prev.score and (ent.end - ent.start) > (prev.end - prev.start)):
                resolved[-1] = ent
        else:
            resolved.append(ent)

    # Generate consistent surrogate placeholders
    # e.g., John Doe -> [PERSON_1], second John Doe -> [PERSON_1], Jane -> [PERSON_2]
    entity_counts = {}
    value_to_token = {}
    vault = {}

    # Sort resolved back in order of appearance
    resolved.sort(key=lambda x: x.start)

    sanitized_parts = []
    last_idx = 0
    tokenized_entities = []

    for ent in resolved:
        raw_val = text[ent.start:ent.end]
        etype = ent.entity_type

        # Check if already assigned
        cache_key = (etype, raw_val.lower().strip())
        if cache_key in value_to_token:
            token = value_to_token[cache_key]
        else:
            entity_counts[etype] = entity_counts.get(etype, 0) + 1
            idx = entity_counts[etype]
            if etype == "US_SSN":
                token = f"[SSN_{idx}]"
            elif etype == "CREDIT_CARD":
                token = f"[CREDIT_CARD_{idx}]"
            elif etype == "API_KEY":
                token = f"[API_KEY_{idx}]"
            elif etype == "EMAIL_ADDRESS":
                token = f"[EMAIL_{idx}]"
            elif etype == "INTERNAL_IP":
                token = f"[INTERNAL_IP_{idx}]"
            elif etype == "FINANCIAL_DATA":
                token = f"[FINANCIAL_DATA_{idx}]"
            elif etype == "PERSON":
                token = f"[PERSON_{idx}]"
            else:
                token = f"[{etype}_{idx}]"

            value_to_token[cache_key] = token
            vault[token] = raw_val

        sanitized_parts.append(text[last_idx:ent.start])
        sanitized_parts.append(token)
        last_idx = ent.end
        tokenized_entities.append({
            "entity_type": etype,
            "original_value": raw_val,
            "placeholder": token,
            "start": ent.start,
            "end": ent.end,
            "score": ent.score
        })

    sanitized_parts.append(text[last_idx:])
    sanitized_text = "".join(sanitized_parts)

    return sanitized_text, tokenized_entities, vault

def rehydrate_text(sanitized_text: str, vault: dict) -> str:
    result = sanitized_text
    for token, original in vault.items():
        result = result.replace(token, original)
    return result

if __name__ == "__main__":
    analyzer = get_test_analyzer()
    prompt = "Summarize this customer complaint from John Doe, SSN 000-00-0000, regarding their credit card 4111-1111-1111-1111. Contact John Doe at john@acme.com or API key sk-proj12345678901234567890 on internal host 10.0.4.12 with salary $150,000/yr."
    raw_results = analyzer.analyze(text=prompt, language="en")
    sanitized, ents, vault = redact_and_map(prompt, raw_results)
    print("SANITIZED PROMPT:")
    print(sanitized)
    print("\nRESOLVED ENTITIES & VAULT:")
    for k, v in vault.items():
        print(f"  {k} -> {v}")
    print("\nREHYDRATED TEST:")
    print(rehydrate_text(sanitized, vault))
