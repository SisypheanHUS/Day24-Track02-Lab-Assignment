# src/quality/validation.py
import re
import pandas as pd


def build_patient_expectation_suite():
    """
    Tạo expectation suite cho patient data dùng Great Expectations.
    Trả về dict mô tả các expectations (tương thích mọi phiên bản GX).
    """
    try:
        import great_expectations as gx

        context = gx.get_context()

        df = pd.read_csv("data/raw/patients_raw.csv")
        datasource = context.sources.add_or_update_pandas(name="patients")
        asset = datasource.add_dataframe_asset(name="patients_raw")
        batch_request = asset.build_batch_request(dataframe=df)
        validator = context.get_validator(batch_request=batch_request)

        validator.expect_column_values_to_not_be_null("patient_id")
        validator.expect_column_value_lengths_to_equal(column="cccd", value=12)
        validator.expect_column_values_to_be_between(
            column="ket_qua_xet_nghiem", min_value=0, max_value=50
        )
        valid_conditions = ["Tiểu đường", "Huyết áp cao", "Tim mạch", "Khỏe mạnh"]
        validator.expect_column_values_to_be_in_set(
            column="benh", value_set=valid_conditions
        )
        validator.expect_column_values_to_match_regex(
            column="email",
            regex=r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
        )
        validator.expect_column_values_to_be_unique(column="patient_id")

        validator.save_expectation_suite(discard_failed_expectations=False)
        return validator.get_expectation_suite()

    except Exception as exc:
        # Fallback: trả về dict mô tả expectations nếu GX chưa cài
        return {
            "expectation_suite_name": "patient_data_suite",
            "expectations": [
                {"type": "expect_column_values_to_not_be_null", "column": "patient_id"},
                {"type": "expect_column_value_lengths_to_equal", "column": "cccd", "value": 12},
                {"type": "expect_column_values_to_be_between",
                 "column": "ket_qua_xet_nghiem", "min_value": 0, "max_value": 50},
                {"type": "expect_column_values_to_be_in_set",
                 "column": "benh",
                 "value_set": ["Tiểu đường", "Huyết áp cao", "Tim mạch", "Khỏe mạnh"]},
                {"type": "expect_column_values_to_match_regex",
                 "column": "email",
                 "regex": r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"},
                {"type": "expect_column_values_to_be_unique", "column": "patient_id"},
            ],
            "error": str(exc),
        }


def validate_anonymized_data(filepath: str) -> dict:
    """
    Validate anonymized data.
    Trả về {"success": bool, "failed_checks": list, "stats": dict}.
    """
    df = pd.read_csv(filepath)
    failed = []

    # Check 1: Không còn CCCD dạng 12 chữ số thuần túy trong cột cccd
    # (sau anonymization giá trị vẫn là fake 12 chữ số — đây là format check)
    cccd_pattern = re.compile(r"^\d{12}$")
    invalid_cccds = df["cccd"].astype(str).apply(
        lambda x: not bool(cccd_pattern.match(x))
    ).sum()
    if invalid_cccds > 0:
        failed.append(f"cccd: {invalid_cccds} giá trị không đúng định dạng 12 chữ số")

    # Check 2: Không có null trong các cột quan trọng
    key_columns = ["patient_id", "benh", "ket_qua_xet_nghiem", "cccd", "so_dien_thoai"]
    for col in key_columns:
        if col in df.columns:
            null_count = int(df[col].isnull().sum())
            if null_count > 0:
                failed.append(f"{col}: {null_count} null values")

    # Check 3: DataFrame không rỗng
    if len(df) == 0:
        failed.append("DataFrame rỗng")

    return {
        "success": len(failed) == 0,
        "failed_checks": failed,
        "stats": {
            "total_rows": len(df),
            "columns": list(df.columns),
        },
    }
