from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import pandas as pd

app = FastAPI(title="DNS Radar ML Inference Engine")

# 1. Load the model into memory exactly once at startup
print("Loading ML Model into memory...")
try:
    model = joblib.load("model_v1.pkl")
    print("Model loaded successfully.")
except Exception as e:
    print(f"Failed to load model: {e}")
    print("The server cannot function without the model. Exiting.")
    exit(1)  # Exit if model can't be loaded, since the server can't function without it

# 2. Define the expected JSON payload (Matches Go FeatureVector perfectly)


class DNSFeatureVector(BaseModel):
    domain: str
    client_ip: str
    shannon_entropy: float
    max_subdomain_len: int
    avg_subdomain_len: float
    unigram_deviation: float
    bigram_entropy: float
    nxdomain_ratio: float
    unique_subdomains: int
    txt_ratio: float
    burstiness: float


@app.post("/api/v1/score")
async def score_domain(vector: DNSFeatureVector):
    if model is None:
        raise HTTPException(status_code=500, detail="Model not loaded")

    # 3. Format the data for Scikit-Learn
    # We drop domain and client_ip, keeping only the 9 math features the model expects,
    # IN THE EXACT SAME ORDER as the training columns.
    features_dict = {
        "shannon_entropy": [vector.shannon_entropy],
        "max_subdomain_len": [vector.max_subdomain_len],
        "avg_subdomain_len": [vector.avg_subdomain_len],
        "unigram_deviation": [vector.unigram_deviation],
        "bigram_entropy": [vector.bigram_entropy],
        "nxdomain_ratio": [vector.nxdomain_ratio],
        "unique_subdomains": [vector.unique_subdomains],
        "txt_ratio": [vector.txt_ratio],
        "burstiness": [vector.burstiness]
    }

    df = pd.DataFrame(features_dict)

    # 4. Perform Inference
    # predict() returns [0] or [1]
    # predict_proba() returns the confidence array, e.g., [[0.1, 0.9]] (10% safe, 90% tunnel)
    prediction = int(model.predict(df)[0])
    confidence = float(model.predict_proba(df)[0][prediction])

    # 5. Return the threat decision
    return {
        "domain": vector.domain,
        "client_ip": vector.client_ip,
        "is_tunnel": prediction == 1,
        "threat_score": confidence,
        "action": "BLOCK" if prediction == 1 and confidence > 0.85 else "ALLOW"
    }

if __name__ == "__main__":
    import uvicorn
    # Run the server bound to all interfaces
    uvicorn.run(app, host="0.0.0.0", port=8000)
