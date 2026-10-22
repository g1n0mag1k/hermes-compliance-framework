"""HealthSherpa CSV export ingestion: loading, validation, PHI column detection."""

import re
from pathlib import Path

import pandas as pd

PHI_COLUMN_PATTERNS: list[str] = [
    "name",
    "first",
    "last",
    "ssn",
    "social",
    "dob",
    "birth",
    "date_of_birth",
    "address",
    "street",
    "city",
    "zip",
    "phone",
    "email",
    "member_id",
    "subscriber_id",
    "policy_id",
    "group_id",
    "npi",
    "tin",
    "ein",
    "gender",
]

# Patterns match whole tokens of the normalized column name, so short patterns
# like "tin" or "ein" do not fire inside unrelated words ("Setting", "Reinstated").
# Trailing digits are allowed so "Address1" / "Phone2" still match.
_PHI_COLUMN_RE = re.compile(
    r"(?<![a-z0-9])(?:"
    + "|".join(re.escape(p) for p in sorted(PHI_COLUMN_PATTERNS, key=len, reverse=True))
    + r")(?![a-z])"
)


def _normalize_column_name(name: str) -> str:
    name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


class HealthSherpaIngester:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self) -> pd.DataFrame:
        if not self.path.exists():
            raise FileNotFoundError(f"CSV not found: {self.path}")
        try:
            df = pd.read_csv(self.path, dtype=str, keep_default_na=False)
        except pd.errors.EmptyDataError:
            raise ValueError("CSV has no rows") from None
        df.columns = df.columns.str.strip()
        if len(df.index) == 0:
            raise ValueError("CSV has no rows")
        return df

    def identify_phi_columns(self, df: pd.DataFrame) -> list[str]:
        return [
            col
            for col in df.columns
            if _PHI_COLUMN_RE.search(_normalize_column_name(str(col)))
        ]

    def validate(self, df: pd.DataFrame) -> None:
        if len(df.index) == 0:
            raise ValueError("DataFrame has no rows")
        if len(df.columns) == 0:
            raise ValueError("DataFrame has no columns")
