from fastapi import FastAPI, HTTPException, File, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from typing import List, Optional
import os
import json
import logging

app = FastAPI()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

REPO_PATH = '../'  # Adjust this path as needed
RHSA_MAPPING_PATH = 'rhsa-mappings.json'  # Ensure this path is correct

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
    vuln_ids = [vuln_id.strip() for vuln_id in vulnIds.split(',')]
    cve_ids = []

    # Load RHSA mappings if they exist
    if os.path.exists(RHSA_MAPPING_PATH):
        with open(RHSA_MAPPING_PATH, 'r') as file:
            rhsa_mappings = json.load(file)
        logger.info("RHSA mappings loaded successfully.")
    else:
        rhsa_mappings = {}
        logger.warning("RHSA mappings file not found.")

    # Check each ID and convert RHSA to CVE if necessary
    for vuln_id in vuln_ids:
        if vuln_id.startswith('RHSA-'):
            if vuln_id in rhsa_mappings:
                logger.info(f"Mapping RHSA ID to CVEs: {vuln_id} -> {rhsa_mappings[vuln_id]}")
                cve_ids.extend(rhsa_mappings[vuln_id])
            else:
                logger.error(f"RHSA ID not found or has no associated CVEs: {vuln_id}")
                raise HTTPException(status_code=404, detail=f"RHSA {vuln_id} not found or has no associated CVEs")
        else:
            cve_ids.append(vuln_id)

    if not cve_ids:
        logger.warning("No CVE IDs found after processing.")
        raise HTTPException(status_code=400, detail="No valid CVE IDs found.")

    cve_data = []

    for cve_id in cve_ids:
        parts = cve_id.split('-')
        if len(parts) < 3:
            logger.error(f"Invalid CVE ID format: {cve_id}")
            raise HTTPException(status_code=400, detail=f"Invalid CVE ID format: {cve_id}")
        year_match = parts[1]
        file_path = os.path.join(REPO_PATH, year_match, f"{cve_id}.json")

        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                try:
                    cve_json = json.load(file)
                except json.JSONDecodeError:
                    logger.error(f"Invalid JSON format in file: {file_path}")
                    raise HTTPException(status_code=500, detail=f"Invalid JSON format in CVE file: {cve_id}")

                # Ensure all required fields are present with default values if missing
                cve_json.setdefault('reported_exploited', "")
                cve_json['reported_exploited'] = str(cve_json['reported_exploited']).lower()  # Ensure string type and lowercase
                cve_json.setdefault('exploit_maturity', "").lower()
                cve_json.setdefault('counts', {}).setdefault('public_exploit_count', 0)
                cve_json.setdefault('timeline', {}).setdefault('nvd_published', "")
                cve_json.setdefault('exploits', [])
                cve_data.append(cve_json)
                logger.info(f"CVE data loaded: {cve_id}")
        else:
            logger.error(f"CVE file not found: {cve_id} at {file_path}")
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

    return cve_data

@app.post("/v1/report")
async def upload_csv(file: UploadFile = File(...)):
    # Acceptable content types for CSV files
    acceptable_types = [
        'text/csv',
        'application/csv',
        'application/vnd.ms-excel',
        'text/plain',
        'text/tsv',
        'application/octet-stream'  # Sometimes used when the content type is unknown
    ]

    # Check if the uploaded file is a CSV
    if file.content_type not in acceptable_types:
        logger.error(f"Invalid file type: {file.content_type}")
        raise HTTPException(status_code=400, detail="Only CSV files are accepted")

    # Read the uploaded file
    content = await file.read()
    # Convert bytes to string
    try:
        csv_content = content.decode('utf-8')
    except UnicodeDecodeError:
        logger.error("Failed to decode uploaded file as UTF-8.")
        raise HTTPException(status_code=400, detail="Unable to decode the uploaded file. Ensure it's a UTF-8 encoded CSV.")

    # Now we can read the CSV content using pandas
    import pandas as pd
    from io import StringIO

    try:
        df = pd.read_csv(StringIO(csv_content))
        logger.info("CSV file read successfully.")
    except Exception as e:
        logger.error(f"Error reading CSV file: {e}")
        raise HTTPException(status_code=400, detail=f"Error reading CSV file: {str(e)}")

    # Now, search for mentions of 'CVE-' and 'RHSA-' in each column
    import re
    cve_pattern = re.compile(r'\bCVE-\d{4}-\d+\b')
    rhsa_pattern = re.compile(r'\bRHSA-\d{4}:\d+\b')  # RHSA IDs with colons

    max_count = 0
    target_column = None
    for column in df.columns:
        # Convert column to string
        col_data = df[column].astype(str)
        # Count matches
        matches = col_data.str.contains(cve_pattern) | col_data.str.contains(rhsa_pattern)
        count = matches.sum()
        logger.info(f"Column '{column}' has {count} CVE/RHSA matches.")
        if count > max_count:
            max_count = count
            target_column = column
            logger.info(f"New target column selected: '{column}' with {count} matches.")

    if target_column is None:
        logger.warning("No CVE or RHSA IDs found in the CSV.")
        raise HTTPException(status_code=400, detail="No CVE or RHSA IDs found in the CSV")

    # Extract the IDs from the target column
    col_data = df[target_column].astype(str)
    ids = []
    entry_id_mapping = []  # List of lists, mapping each entry to its CVE IDs

    # Load RHSA mappings once
    if os.path.exists(RHSA_MAPPING_PATH):
        with open(RHSA_MAPPING_PATH, 'r') as file:
            rhsa_mappings = json.load(file)
        logger.info("RHSA mappings loaded successfully for CSV processing.")
    else:
        rhsa_mappings = {}
        logger.warning("RHSA mappings file not found during CSV upload.")

    for entry in col_data:
        cve_ids = cve_pattern.findall(entry)
        rhsa_ids = rhsa_pattern.findall(entry)
        all_cve_ids = cve_ids.copy()
        for rhsa_id in rhsa_ids:
            # Lookup RHSA ID as-is
            if rhsa_id in rhsa_mappings:
                logger.info(f"Mapping RHSA ID to CVEs: {rhsa_id} -> {rhsa_mappings[rhsa_id]}")
                cve_ids_from_rhsa = rhsa_mappings[rhsa_id]
                all_cve_ids.extend(cve_ids_from_rhsa)
            else:
                logger.error(f"RHSA ID not found during CSV processing: {rhsa_id}")
                # Optionally, you can choose to skip or handle missing RHSA IDs differently
        # Keep track of all CVE IDs for this entry
        entry_id_mapping.append(all_cve_ids)
        # Add to the global list of CVE IDs
        ids.extend(all_cve_ids)

    # Remove duplicates from CVE IDs
    ids = list(set(ids))
    logger.info(f"Total unique CVE IDs extracted from CSV: {len(ids)}")

    if not ids:
        logger.warning("No valid CVE IDs found after mapping in CSV.")
        raise HTTPException(status_code=400, detail="No valid CVE IDs found after mapping.")

    # Now query the existing API with these CVE IDs
    try:
        cve_data = await get_cve(','.join(ids))
        logger.info(f"Retrieved {len(cve_data)} CVE records from API.")
    except HTTPException as e:
        logger.error(f"Error querying CVE data: {e.detail}")
        raise e

    # Create mapping from CVE ID to 'reported_exploited' and 'exploit_maturity'
    cve_id_to_reported_exploited = {item['id']: item.get('reported_exploited', '').lower() for item in cve_data}
    cve_id_to_exploit_maturity = {item['id']: item.get('exploit_maturity', '').lower() for item in cve_data}

    # Define the ordering for exploit_maturity and reported_exploited
    exploit_maturity_order = {'exploited': 4, 'weaponized': 3, 'poc': 2, 'none': 1, '': 0}
    reported_exploited_order = {'true': 2, 'false': 1, '': 0}

    # Now, we can append the new columns to the dataframe
    reported_exploited_list = []
    exploit_maturity_list = []
    for cve_ids_entry in entry_id_mapping:
        highest_reported_exploited = ''
        highest_reported_exploited_value = 0
        highest_exploit_maturity = ''
        highest_exploit_maturity_value = 0

        for cve_id in cve_ids_entry:
            reported_exploited = cve_id_to_reported_exploited.get(cve_id, '').lower()
            exploit_maturity = cve_id_to_exploit_maturity.get(cve_id, '').lower()

            # Get ordering value
            reported_exploited_value = reported_exploited_order.get(reported_exploited, 0)
            exploit_maturity_value = exploit_maturity_order.get(exploit_maturity, 0)

            # Update if higher for reported_exploited
            if reported_exploited_value > highest_reported_exploited_value:
                highest_reported_exploited = reported_exploited
                highest_reported_exploited_value = reported_exploited_value

            # Update if higher for exploit_maturity
            if exploit_maturity_value > highest_exploit_maturity_value:
                highest_exploit_maturity = exploit_maturity
                highest_exploit_maturity_value = exploit_maturity_value

        # Capitalize for consistency
        reported_exploited_list.append(highest_reported_exploited.capitalize())
        exploit_maturity_list.append(highest_exploit_maturity.capitalize())

    # Append the new columns
    df['reported_exploited'] = reported_exploited_list
    df['exploit_maturity'] = exploit_maturity_list

    # Convert dataframe back to CSV
    output = StringIO()
    df.to_csv(output, index=False)
    modified_csv = output.getvalue()

    logger.info("CSV processing completed successfully.")

    # Return the modified CSV
    return Response(content=modified_csv, media_type='text/csv')

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
