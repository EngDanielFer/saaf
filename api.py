import subprocess
import sys
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

sys.path.insert(0, "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/scripts/python")
from extract_json import extract_json_from_stdout

app = FastAPI(title="SAAF Pro API", version="6.7.14")


class ScrapeRequest(BaseModel):
    url: str


@app.post("/scrape")
def scrape(req: ScrapeRequest):
    try:
        result = subprocess.run(
            ["node", "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/scripts/node/scraper.js", req.url],
            capture_output=True,
            text=True,
            timeout=60,
        )
        data = extract_json_from_stdout(result.stdout)
        return data
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Scraper timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
def health():
    return {"status": "ok"}
