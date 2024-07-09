# Exploit Intelligence Repository

## Introduction

Welcome to the Exploit & Vulnerability Intelligence repository! This open-source project aims to provide the community with the latest exploit information and streamline the process of vulnerability management. By integrating various sources of exploit data, this repository helps security enthusiasts and professionals stay up-to-date with emerging threats.

### Exploit Intelligence and Prioritization

- **Git Repository Monitoring**: Automatically track and update the latest Proof of Concepts (PoCs) for exploits available on GitHub.
- **Exploits Websites Monitoring**: Monitor leading exploit databases for newly published exploits to stay ahead of threats.
- ...

### Comprehensive Data Integration

- **National Vulnerability Database (NVD)**: Keep up-to-date with the latest vulnerability data from the NVD.
- **CISA KEV**: Keep up-to-date with the latest Known Exploited Vulnerabilities Catalog.
- **EPSS**: Keep up-to-date with the latest EPSS Score.
- **GitHub Security Advisory**: Access the most recent security advisories directly from GitHub.
- **OSV - OpenSource Vulnerability Database**: Integrate and stay current with vulnerability data from the OSV.
- **Packet Storm Security Monitoring**: Fetch and stay updated with the latest exploit information from Packet Storm Security.
- **0day.today Exploit Monitoring**: Integrate the latest exploits from 0day.today to maintain an updated security posture.
- **Metasploit**: Stay informed about the latest exploits and payloads available in the Metasploit framework.
- **ExploitDB**: Access and integrate exploit information from the Exploit Database (ExploitDB).
- **Nuclei**: Keep up-to-date with the latest templates for vulnerability scanning using Nuclei.

## Roadmap

This project is continuously evolving with the help of the community. Here’s what’s on the horizon:

- **In-the-Wild Exploitation Tracking**: Develop comprehensive timelines to monitor the progression of exploitation, offering insights into the lifecycle of exploitation for more proactive decision-making.

## USING THE API

# Vulnerability Feed Intelligence API Documentation

## Overview

The Vulnerability Feed Intelligence API provides comprehensive information about software vulnerabilities, helping organizations prioritize vulnerability management. The API leverages the Stakeholder-Specific Vulnerability Categorization (SSVC) framework to provide decisions based on exploitation, automation, exposure, and human impact.

## Base URL

```
https://api.ssvc.me
```

## Endpoint

### Get Vulnerability Information

**Endpoint:** `/v1/vuln`

**Method:** `GET`

**Description:** Retrieves detailed vulnerability information based on provided CVE IDs. Supports querying multiple CVE IDs at once, with a limit of 200.

### Query Parameters

- `vulnIds` (required): Comma-separated list of vulnerability IDs (e.g., `CVE-2021-44228,CVE-2021-45046`). Limit: 200.
- `exposure` (optional): Exposure level (`open`, `small`, `controlled`). Default: `open`.
- `impact` (optional): Impact level (`low`, `medium`, `high`, `critical`). Default: `high`.

### Example Request

**Request:**

```
GET /v1/vuln?vulnIds=CVE-2021-44228,CVE-2021-45046&exposure=small&impact=medium
```

### Curl Example

```sh
curl -X GET "https://api.ssvc.me/v1/vuln?vulnIds=CVE-2021-44228,CVE-2021-45046&exposure=open&impact=medium"
```

### Python Example

```python
import requests

url = "https://api.ssvc.me/v1/vuln"
params = {
    "vulnIds": "CVE-2021-44228,CVE-2021-45046",
    "exposure": "small",
    "impact": "medium"
}

response = requests.get(url, params=params)
print(response.json())
```

### Go Example

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "net/url"
)

func main() {
    baseURL := "https://api.ssvc.me/v1/vuln"
    params := url.Values{}
    params.Add("vulnIds", "CVE-2021-44228,CVE-2021-45046")
    params.Add("exposure", "small")
    params.Add("impact", "medium")
    params.Add("stix", "true")

    queryURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())
    resp, err := http.Get(queryURL)
    if err != nil {
        log.Fatalf("Failed to make request: %v", err)
    }
    defer resp.Body.Close()

    var result map[string]interface{}
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        log.Fatalf("Failed to parse response: %v", err)
    }

    resultJSON, err := json.MarshalIndent(result, "", "  ")
    if err != nil {
        log.Fatalf("Failed to marshal response: %v", err)
    }

    fmt.Println(string(resultJSON))
}
```

## Response Structure

The response from the API includes metadata about the request and an array of vulnerability data.

### Response Example

```json
{
  "metadata": {
    "timestamp": "2024-06-14T12:02:22.341011+00:00"
  },
  "data": [
    {
      "id": "CVE-2021-44228",
      "severity": "critical",
      "automatable": "yes",
      "cisaKEV": true,
      "reported_exploited": true,
      "exploit_maturity": "active",
      "counts": {
        "public_exploit_count": 410
      },
      "timeline": {
        "nvd_published": "2021-12-10",
        "cisaKEV_published": "2021-12-10"
      },
      "epss": {
        "epss_score": "0.97547",
        "epss_percentile": "0.99996"
      },
      "ssvc": {
        "automatable": "yes",
        "exposure": "open",
        "impact": "high",
        "decision": "immediate"
      },
      "exploits": [
        {
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
          "name": "Apache Log4j2 Remote Code Execution Vulnerability",
          "source": "cisa_kev",
          "date_added": "2021-12-10",
          "exploit_maturity": "in_wild"
        },
        {
          "url": "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/java/remote/51183.txt",
          "name": "AD Manager Plus 7122 - Remote Code Execution (RCE)",
          "source": "exploitdb",
          "date_added": "2023-04-01",
          "exploit_maturity": "poc"
        },
        {
          "url": "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/java/remote/50592.py",
          "name": "Apache Log4j 2 - Remote Code Execution (RCE)",
          "source": "exploitdb",
          "date_added": "2021-12-14",
          "exploit_maturity": "poc"
        },
        ...
        ...
        ...
      ]
    }
  ]
}
```

## Rate Limiting

The API enforces a rate limit to ensure fair usage for all clients.

- **Rate Limit**: 30 requests per minute

If the rate limit is exceeded, the API will return a `429 Too Many Requests` status code. Clients are advised to implement retry logic with exponential backoff to handle rate limiting gracefully.

## SSVC Framework

The SSVC (Stakeholder-Specific Vulnerability Categorization) framework helps in making informed decisions by considering multiple factors:

- **Exploitation**: Whether the vulnerability is actively being exploited.
- **Automation**: Whether the exploitation of the vulnerability can be automated.
- **Exposure**: The level of exposure of the system to the vulnerability.
- **Human Impact**: The potential impact on human life or safety.

### Decision Example

```json
{
  "ssvc": {
    "automatable": true,
    "exposure": "small",
    "impact": "medium",
    "decision": "immediate"
  }
}
```

## Product Overview

The Vulnerability Feed Intelligence API provides exploit and vulnerability intelligence directly into the tools, processes, programs, and systems that need it to outpace adversaries. By integrating this API, organizations can prioritize vulnerabilities that matter based on the threat landscape and defer those that don't, using the SSVC framework.

### Key Benefits

- **Vulnerability Prioritization**: Focus on vulnerabilities that pose the highest risk based on current threats and defer those with lower impact.
- **Automation and Integration**: Seamlessly integrate with existing tools and processes to streamline vulnerability management.
- **Comprehensive Insights**: Gain detailed information about vulnerabilities, including exploit availability and impact assessments.

## Conclusion

The Vulnerability Feed Intelligence API provides crucial information for prioritizing vulnerability management within organizations. By incorporating the SSVC framework, it offers a structured approach to making decisions based on exploitation, automation, exposure, and human impact. 

This repository aims to empower the open-source community by providing easy access to the latest exploits and vulnerability information.
Together, we can create a more secure digital environment.

---
