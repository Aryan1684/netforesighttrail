from pathlib import Path
import sys
import numpy as np

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"backend"))

from model_pipeline import ModelPipeline

p=ModelPipeline(ROOT/"models")
p.load()
assert len(p.feature_names)==42
assert len(p.class_names)==10

rng=np.random.default_rng(42)
window=rng.normal(size=(5,42)).astype("float32")
result=p.predict(window)

assert result.current_label in p.class_names
assert result.next_label in p.class_names
assert abs(sum(result.current_probabilities.values())-1)<1e-4
assert abs(sum(result.next_probabilities.values())-1)<1e-4

print("XGBoost load: PASS")
print("Transformer load: PASS")
print("Inference shape 5x42: PASS")
print("Probability outputs: PASS")
