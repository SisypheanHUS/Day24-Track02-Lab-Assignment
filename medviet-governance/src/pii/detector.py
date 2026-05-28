# src/pii/detector.py
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider


def build_vietnamese_analyzer() -> AnalyzerEngine:
    # TASK 2.2.1 — CCCD: đúng 12 chữ số, không liền chữ số khác
    cccd_pattern = Pattern(
        name="cccd_pattern",
        regex=r"(?<!\d)\d{12}(?!\d)",
        score=0.9
    )
    cccd_recognizer = PatternRecognizer(
        supported_entity="VN_CCCD",
        patterns=[cccd_pattern],
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

    # TASK 2.2.3 — NLP engine dùng spaCy Vietnamese model
    try:
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "vi", "model_name": "vi_core_news_lg"}]
        })
        nlp_engine = provider.create_engine()
        _lang = "vi"
    except Exception:
        # Fallback nếu model tiếng Việt chưa cài
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]
        })
        nlp_engine = provider.create_engine()
        _lang = "en"

    # TASK 2.2.4 — Khởi tạo AnalyzerEngine và đăng ký recognizers
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
    analyzer.registry.add_recognizer(cccd_recognizer)
    analyzer.registry.add_recognizer(phone_recognizer)

    # Lưu ngôn ngữ để detect_pii dùng
    analyzer._vn_lang = _lang

    return analyzer


def detect_pii(text: str, analyzer: AnalyzerEngine) -> list:
    lang = getattr(analyzer, "_vn_lang", "vi")
    results = analyzer.analyze(
        text=text,
        language=lang,
        entities=["PERSON", "EMAIL_ADDRESS", "VN_CCCD", "VN_PHONE"]
    )
    return results
