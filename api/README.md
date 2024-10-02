# CVE API Server

This project is a FastAPI server that serves CVE data from a cloned GitHub repository. The server reads CVE JSON files from the local disk and returns the data via an API.

## Prerequisites

- Python 3.7+
- Git

## Installation

1. **Clone the Repository**

   Clone the CVE data repository to your local machine:

   ```bash
   git clone https://github.com/ralvares/ssvc.me.git
   cd ssvc.me/api
   ```

2. **Install Dependencies**

   Install the required Python packages using `pip`:

   ```bash
   pip install -r requirements.txt
   ```

## Running the Server

1. **Start the FastAPI server**

   Run the server using `uvicorn`:

   ```bash
   uvicorn api:app --reload --port 8080
   ```

2. **Access the API**

   You can access the API at `http://localhost:8080`. For example, to get data for specific CVEs, you can use:

   ```
   http://localhost:8080/v1/vuln?vulnIds=CVE-2023-1234,CVE-2023-5678,RHSA-2024:4389
   ```

## Project Structure

```
ssvc.me/api/
├── api.py              # FastAPI application
├── requirements.txt     # Python dependencies
├── README.md            # Project documentation
```

## API Endpoints

### GET /v1/vuln

Fetches CVE data for the specified IDs.

**Parameters:**

- `vulnIds`: Comma-separated list of CVE IDs or RHSA (e.g., `CVE-2023-1234,CVE-2023-5678,RHSA-2024:4389`)

**Response:**

Returns a list of CVE data in JSON format.

**Example:**

Request:
```
GET /v1/vuln?vulnIds=CVE-2023-1234,CVE-2023-5678,RHSA-2024:4389
```

Response:
```json
[
    {
        "id": "CVE-2023-1234",
        "reported_exploited": "yes",
        "exploit_maturity": "high",
        "counts": {
            "public_exploit_count": 3
        },
        "timeline": {
            "nvd_published": "2023-04-12"
        },
        "exploits": [
            {
                "name": "Exploit 1",
                "url": "https://example.com/exploit1",
                "source": "exploit-db",
                "date_added": "2023-05-01"
            }
        ]
    },
    {
        "id": "CVE-2023-5678",
        "reported_exploited": "no",
        "exploit_maturity": "low",
        "counts": {
            "public_exploit_count": 1
        },
        "timeline": {
            "nvd_published": "2023-06-15"
        },
        "exploits": []
    }
]
```

# RHACS Report Enhancements

## Overview

The **RHACS (Red Hat Advanced Cluster Security) Report Enhancement API** allows users to upload their ACS (Advanced Cluster Security) report CSV files and receive an enriched CSV output detailing the exploitability of each CVE or RHSA listed in their reports.

## Features

- **Upload ACS Report CSV:** Seamlessly upload your vulnerability reports in CSV format.
- **Exploitability Analysis:** Obtain detailed information about the exploitability of each CVE or RHSA, including whether it's reported as exploited and its exploit maturity level.
- **Automated Processing:** Utilize simple `curl` commands to interact with the API and automate report enhancements.

## Usage

### Uploading an ACS Report

To enhance your ACS report with exploitability information, use the following `curl` command to upload your CSV file and receive the processed report:

```bash
curl -X POST "http://localhost:8080/v1/report" \    
     -H "accept: text/csv" \
     -H "Content-Type: multipart/form-data" \
     -F "file=@RHACS_Vulnerability_Report_demo-report_15_August_2024.csv;type=text/csv" > report.csv
```

### Example

Assuming you have a vulnerability report named `RHACS_Vulnerability_Report_demo-report_15_August_2024.csv`, you can enhance it by running:

```bash
curl -X POST "http://localhost:8080/v1/report" \    
     -H "accept: text/csv" \
     -H "Content-Type: multipart/form-data" \
     -F "file=@RHACS_Vulnerability_Report_demo-report_15_August_2024.csv;type=text/csv" > report.csv
```

After execution, the `report.csv` file will contain additional columns:

- **reported_exploited:** Indicates whether the vulnerability has been reported as exploited (`True` or `False`).
- **exploit_maturity:** Shows the exploit maturity level, such as `Exploited`, `Weaponized`, `POC`, or `None`.

### Explanation

With the RHACS Report Enhancements:

- **CVE Analysis:** For each CVE listed in your ACS report, the API provides details on whether it's been exploited and its maturity level.
- **RHSA Analysis:** Similarly, for each RHSA, the API maps it to associated CVEs and provides exploitability information for each.
- **Comprehensive Insights:** The enriched report helps in prioritizing vulnerabilities based on their exploitability, aiding in more effective security management.

## API Endpoints

### POST `/v1/report`

- **Description:** Upload an ACS report CSV file and receive an enhanced CSV with exploitability information.
- **Request:**
  - **Content-Type:** `multipart/form-data`
  - **Form Data:**
    - `file`: The ACS report CSV file to upload.
- **Response:**
  - **Content-Type:** `text/csv`
  - **Body:** The enhanced CSV file with additional columns for exploitability.


