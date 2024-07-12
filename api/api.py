from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional
import os
import json

app = FastAPI()

REPO_PATH = '../'
RHSA_MAPPING_PATH = 'rhsa-mappings.json'

class CVECounts(BaseModel):
    public_exploit_count: Optional[int] = 0

class CVETimeline(BaseModel):
    nvd_published: Optional[str] = ""

class CVEExploit(BaseModel):
    name: Optional[str] = ""
    url: Optional[str] = ""
    source: Optional[str] = ""
    date_added: Optional[str] = ""

class CVE(BaseModel):
    id: str
    reported_exploited: Optional[str] = ""
    exploit_maturity: Optional[str] = ""
    counts: CVECounts = Field(default_factory=CVECounts)
    timeline: CVETimeline = Field(default_factory=CVETimeline)
    exploits: List[CVEExploit] = Field(default_factory=list)

@app.get("/v1/vuln", response_model=List[CVE])
async def get_cve(vulnIds: str):
    vuln_ids = vulnIds.split(',')
    cve_ids = []
    
    # Load RHSA mappings if they exist
    if os.path.exists(RHSA_MAPPING_PATH):
        with open(RHSA_MAPPING_PATH, 'r') as file:
            rhsa_mappings = json.load(file)
    else:
        rhsa_mappings = {}

    # Check each ID and convert RHSA to CVE if necessary
    for vuln_id in vuln_ids:
        if vuln_id.startswith('RHSA-'):
            if vuln_id in rhsa_mappings:
                cve_ids.extend(rhsa_mappings[vuln_id])
            else:
                raise HTTPException(status_code=404, detail=f"RHSA {vuln_id} not found or has no associated CVEs")
        else:
            cve_ids.append(vuln_id)

    cve_data = []

    for cve_id in cve_ids:
        year_match = cve_id.split('-')[1]
        file_path = os.path.join(REPO_PATH, year_match, f"{cve_id}.json")

        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                cve_json = json.load(file)
                # Ensure all required fields are present with default values if missing
                cve_json.setdefault('reported_exploited', "")
                cve_json.setdefault('exploit_maturity', "")
                cve_json.setdefault('counts', {}).setdefault('public_exploit_count', 0)
                cve_json.setdefault('timeline', {}).setdefault('nvd_published', "")
                cve_json.setdefault('exploits', [])
                cve_data.append(cve_json)
        else:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

    return cve_data

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
