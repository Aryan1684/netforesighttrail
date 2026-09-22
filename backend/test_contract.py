from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"backend"))

from constants import FEATURE_NAMES,LABELS

assert len(FEATURE_NAMES)==42
assert len(LABELS)==10
print("42-feature contract: PASS")
print("10-class contract: PASS")
