import joblib
import numpy as np
from skl2onnx import convert_sklearn
from skl2onnx import FloatTensorType

model = joblib.load("/output/model_rf.joblib")
