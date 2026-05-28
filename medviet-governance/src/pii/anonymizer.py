# src/pii/anonymizer.py
import hashlib
import random
import pandas as pd
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from faker import Faker
from .detector import build_vietnamese_analyzer, detect_pii, get_analysis_language

fake = Faker("vi_VN")


class MedVietAnonymizer:

    def __init__(self):
        self.analyzer = build_vietnamese_analyzer()
        self.anonymizer = AnonymizerEngine()
        # Language is determined at build time based on installed spaCy model
        self.language = get_analysis_language()

    # --- helpers ---

    def _anonymize_address(self, text: str) -> str:
        """Anonymize địa chỉ qua anonymize_text(); dùng fake address nếu không detect được."""
        anonymized = self.anonymize_text(text)
        # Nếu không có PII nào được detect, địa chỉ gốc được trả về nguyên — replace trực tiếp
        return anonymized if anonymized != text else fake.address()

    def _fake_cccd(self) -> str:
        return "".join([str(random.randint(0, 9)) for _ in range(12)])

    def _fake_phone(self) -> str:
        return f"0{random.choice([3, 5, 7, 8, 9])}" + \
               "".join([str(random.randint(0, 9)) for _ in range(8)])

    # --- public API ---

    def anonymize_text(self, text: str, strategy: str = "replace") -> str:
        """
        Anonymize text với strategy được chọn:
        - replace : thay bằng fake data
        - mask    : che các ký tự đầu bằng '*'
        - hash    : SHA-256 one-way hash
        """
        results = detect_pii(text, self.analyzer)
        if not results:
            return text

        operators = {}

        if strategy == "replace":
            operators = {
                "PERSON": OperatorConfig("replace", {"new_value": fake.name()}),
                "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": fake.email()}),
                "VN_CCCD": OperatorConfig("replace", {"new_value": self._fake_cccd()}),
                "VN_PHONE": OperatorConfig("replace", {"new_value": self._fake_phone()}),
            }
        elif strategy == "mask":
            operators = {
                "PERSON": OperatorConfig("mask", {
                    "masking_char": "*", "chars_to_mask": 6, "from_end": False
                }),
                "EMAIL_ADDRESS": OperatorConfig("mask", {
                    "masking_char": "*", "chars_to_mask": 6, "from_end": False
                }),
                "VN_CCCD": OperatorConfig("mask", {
                    "masking_char": "*", "chars_to_mask": 8, "from_end": False
                }),
                "VN_PHONE": OperatorConfig("mask", {
                    "masking_char": "*", "chars_to_mask": 6, "from_end": False
                }),
            }
        elif strategy == "hash":
            operators = {
                "PERSON": OperatorConfig("hash", {"hash_type": "sha256"}),
                "EMAIL_ADDRESS": OperatorConfig("hash", {"hash_type": "sha256"}),
                "VN_CCCD": OperatorConfig("hash", {"hash_type": "sha256"}),
                "VN_PHONE": OperatorConfig("hash", {"hash_type": "sha256"}),
            }

        anonymized = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=operators
        )
        return anonymized.text

    def anonymize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Anonymize toàn bộ DataFrame:
        - ho_ten, email : dùng anonymize_text()
        - dia_chi       : replace trực tiếp bằng fake address
        - cccd, so_dien_thoai : replace trực tiếp bằng fake data
        - bac_si_phu_trach    : replace trực tiếp bằng fake name
        - benh, ket_qua_xet_nghiem, patient_id, ngay_sinh, ngay_kham : GIỮ NGUYÊN
        """
        df_anon = df.copy()

        df_anon["ho_ten"] = df["ho_ten"].apply(
            lambda x: self.anonymize_text(str(x))
        )
        df_anon["email"] = df["email"].apply(
            lambda x: self.anonymize_text(str(x))
        )
        # anonymize_text() cho địa chỉ; fallback sang fake address nếu Presidio
        # không detect được PII trong chuỗi địa chỉ thuần (không có email/phone)
        df_anon["dia_chi"] = df["dia_chi"].apply(
            lambda x: self._anonymize_address(str(x))
        )
        df_anon["cccd"] = [self._fake_cccd() for _ in range(len(df))]
        df_anon["so_dien_thoai"] = [self._fake_phone() for _ in range(len(df))]
        df_anon["bac_si_phu_trach"] = [fake.name() for _ in range(len(df))]

        return df_anon

    def calculate_detection_rate(self,
                                  original_df: pd.DataFrame,
                                  pii_columns: list) -> float:
        """
        Tính % ô PII được detect thành công.
        Mục tiêu: > 95%.
        """
        total = 0
        detected = 0

        for col in pii_columns:
            for value in original_df[col].astype(str):
                total += 1
                results = detect_pii(value, self.analyzer)
                if len(results) > 0:
                    detected += 1

        return detected / total if total > 0 else 0.0
