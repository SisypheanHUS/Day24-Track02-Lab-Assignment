# src/pii/detector.py
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider

# Language used by the active NLP engine — set once during build
_analysis_language: str = "vi"


def get_analysis_language() -> str:
    """Trả về ngôn ngữ đang dùng cho NLP engine."""
    return _analysis_language


def build_vietnamese_analyzer() -> AnalyzerEngine:
    global _analysis_language

    # TASK 2.2.1 — CCCD: đúng 12 chữ số, không liền chữ số khác
    cccd_recognizer = PatternRecognizer(
        supported_entity="VN_CCCD",
        patterns=[Pattern(
            name="cccd_pattern",
            regex=r"(?<!\d)\d{12}(?!\d)",
            score=0.9
        )],
        context=["cccd", "căn cước", "chứng minh", "cmnd"]
    )

    # TASK 2.2.2 — SĐT VN: 0[3|5|7|8|9] + 8 chữ số
    phone_recognizer = PatternRecognizer(
        supported_entity="VN_PHONE",
        patterns=[Pattern(
            name="vn_phone",
            regex=r"(?<!\d)0[35789]\d{8}(?!\d)",
            score=0.85
        )],
        context=["điện thoại", "sdt", "phone", "liên hệ"]
    )

    # TASK 2.2.3 — NLP engine: Vietnamese model, fallback to English
    try:
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "vi", "model_name": "vi_core_news_lg"}]
        })
        nlp_engine = provider.create_engine()
        _analysis_language = "vi"
    except Exception:
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]
        })
        nlp_engine = provider.create_engine()
        _analysis_language = "en"

    # TASK 2.2.4 — Khởi tạo AnalyzerEngine và đăng ký recognizers
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
    analyzer.registry.add_recognizer(cccd_recognizer)
    analyzer.registry.add_recognizer(phone_recognizer)

    return analyzer


def detect_pii(text: str, analyzer: AnalyzerEngine) -> list:
    """Detect PII trong text. Entities: PERSON, EMAIL_ADDRESS, VN_CCCD, VN_PHONE."""
    return analyzer.analyze(
        text=text,
        language=_analysis_language,
        entities=["PERSON", "EMAIL_ADDRESS", "VN_CCCD", "VN_PHONE"]
    )
