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
   uvicorn main:app --port 8080 --reload
   ```

2. **Access the API**

   You can access the API at `http://localhost:8000`. For example, to get data for specific CVEs, you can use:

   ```
   http://localhost:8000/v1/vuln?vulnIds=CVE-2023-1234,CVE-2023-5678
   ```

## Project Structure

```
project-directory/
├── main.py              # FastAPI application
├── requirements.txt     # Python dependencies
├── README.md            # Project documentation
└── ssvc.me/         # Cloned repository with CVE data
```

## API Endpoints

### GET /cve

Fetches CVE data for the specified IDs.

**Parameters:**

- `ids`: Comma-separated list of CVE IDs (e.g., `CVE-2023-1234,CVE-2023-5678`)

**Response:**

Returns a list of CVE data in JSON format.

**Example:**

Request:
```
GET /v1/vuln?vulnIds=CVE-2023-1234,CVE-2023-5678
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
