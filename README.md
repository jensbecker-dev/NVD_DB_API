# NVD CVE Database API

## Overview
This project provides a Flask-based web application for accessing and interacting with the National Vulnerability Database (NVD) CVE data. It simplifies security assessments by providing precise information about vulnerabilities, affected systems, and exploit proof of concepts through both a web interface and API endpoints.

![Dashboard Screenshot](screenshots/dashboard.png)

## Purpose
Security professionals often need quick and reliable access to vulnerability data. This tool streamlines the process of:
- Retrieving detailed CVE information
- Identifying vulnerable systems
- Accessing exploit proof of concepts
- Supporting security engagements and penetration tests
- Facilitating surface-level security scanning

## Features
- User-friendly web interface for searching CVE data
- REST API for programmatic access to vulnerability information
- Local SQLite database for offline access to CVE information
- Background database updates from official NVD feeds
- Detailed vulnerability information with severity ratings
- Identification of affected systems and versions through CPE data
- References to available exploit POCs and related resources
- Filtering capabilities by severity, exploitability, and keywords
- Dashboard with vulnerability statistics and trends

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/nvd-db-api.git
cd nvd-db-api

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Web Interface
Start the Flask application and access the web interface:

```bash
python app.py
```

Then open a browser and navigate to `http://localhost:8080`

### API Access
The application provides RESTful API endpoints:

```
GET /api/cve/<cve_id> - Get details for a specific CVE
GET /db_status - Check database status
```

### Python Module
You can also use the NVDApi module directly in your Python code:

```python
from modules.nvdapi import NVDApi

# Initialize the API client
nvd = NVDApi()

# Search for a specific CVE
cve_details = nvd.get_cve("CVE-2021-44228")

# Search for vulnerabilities affecting a specific product
apache_vulns = nvd.search_cpe("apache", "log4j")
```

## Required Dependencies
- Flask 2.3.3+
- SQLAlchemy 2.0.23+
- Requests 2.31.0+
- Python 3.8+

For a complete list, see the `requirements.txt` file.

## Project Structure
```
app.py                # Main Flask application
cve_database.db       # SQLite database for CVE storage
requirements.txt      # Python dependencies
modules/              # Python modules
├── nvdapi.py         # NVD API client
static/               # Static web assets
├── css/              # Stylesheets
templates/            # HTML templates
screenshots/          # Application screenshots
```

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements
- [National Vulnerability Database](https://nvd.nist.gov/)

## Disclaimer
This tool is intended for legitimate security research and penetration testing with proper authorization. The authors are not responsible for any misuse or damage caused by this program.