import requests
import gzip
import io
import json
import logging
from datetime import datetime, timedelta
import os
import time

def fetch_nvd_data_feed(year=None):
    """
    Fetch the NVD data feed for a specific year or the most recent one if no year is specified.
    """
    try:
        if year:
            url = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
        else:
            url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"

        logging.info(f"Fetching CVE data from {url}")
        response = requests.get(url)
        response.raise_for_status()

        # Process the gzipped response content
        with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as gzip_file:
            cve_data = json.loads(gzip_file.read().decode('utf-8'))

        logging.info(f"Successfully fetched {len(cve_data.get('CVE_Items', []))} CVE items")
        return cve_data.get('CVE_Items', [])

    except Exception as e:
        logging.error(f"Error fetching NVD data: {e}")
        return None

def fetch_all_nvd_data():
    """
    Fetch all available CVE data from the beginning to current year.
    
    Returns:
        List of all CVE items
    """
    all_cves = []
    current_year = datetime.now().year
    start_year = 2002  # NVD CVE data starts from 2002
    
    try:
        # First get the most recent CVEs
        recent_cves = fetch_nvd_data_feed()
        if recent_cves:
            all_cves.extend(recent_cves)
            logging.info(f"Added {len(recent_cves)} recent CVEs")
        
        # Then get historical data year by year
        for year in range(start_year, current_year + 1):  # Only fetch up to current year
            logging.info(f"Fetching CVEs for year {year}")
            
            # Add a delay between requests to avoid rate limiting
            time.sleep(6)  # Be respectful of the NVD API rate limits
            
            year_cves = fetch_nvd_data_feed(year)
            if year_cves:
                all_cves.extend(year_cves)
                logging.info(f"Added {len(year_cves)} CVEs from {year}")
        
        return all_cves
    
    except Exception as e:
        logging.error(f"Error fetching all NVD data: {e}")
        return all_cves  # Return what we have so far

def determine_severity(cvss_score):
    """
    Determine severity level based on CVSS score.
    
    Args:
        cvss_score: Float CVSS score
        
    Returns:
        String severity level
    """
    if cvss_score is None:
        return "UNKNOWN"
    
    # CVSS v3 severity ratings
    if cvss_score >= 9.0:
        return "CRITICAL"
    elif cvss_score >= 7.0:
        return "HIGH"
    elif cvss_score >= 4.0:
        return "MEDIUM"
    elif cvss_score >= 0.1:
        return "LOW"
    else:
        return "NONE"

def fetch_cve_list(start_date=None):
    """
    Fetch a list of CVEs from the NVD API.
    
    Args:
        start_date (str): The date to start fetching CVEs from, in format 'YYYY-MM-DD HH:MM'
        
    Returns:
        List of CVE objects
    """
    try:
        # Use the data feed instead of API for more reliable results
        return fetch_nvd_data_feed()
    except Exception as e:
        logging.error(f"Error fetching CVE list from {start_date}: {e}")
        return []

class NVDApi:
    """
    Class for interacting with the NVD API.
    """
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
    def get_cve(self, cve_id):
        """
        Get details for a specific CVE by ID.
        
        Args:
            cve_id (str): The CVE ID (e.g., CVE-2021-44228)
            
        Returns:
            dict: CVE details or None if not found
        """
        try:
            # Ensure CVE ID is properly formatted
            cve_id = cve_id.upper()
            if not cve_id.startswith("CVE-"):
                cve_id = f"CVE-{cve_id}"
                
            url = f"{self.base_url}?cveId={cve_id}"
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
            
            vulns = data.get('vulnerabilities', [])
            if vulns:
                cve_data = vulns[0].get('cve', {})
                
                # Get CVSS scores
                metrics = cve_data.get('metrics', {})
                cvss_v3 = None
                cvss_v2 = None
                
                # Extract CVSS v3 score
                if 'cvssMetricV31' in metrics:
                    cvss_v3 = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                elif 'cvssMetricV30' in metrics:
                    cvss_v3 = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                
                # Extract CVSS v2 score
                if 'cvssMetricV2' in metrics:
                    cvss_v2 = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                
                # Calculate severity based on CVSS v3 or v2 score
                severity = None
                if cvss_v3 is not None:
                    severity = determine_severity(cvss_v3)
                elif cvss_v2 is not None:
                    severity = determine_severity(cvss_v2)
                else:
                    severity = "UNKNOWN"
                
                # Add the severity to the CVE data
                cve_data['severity'] = severity
                cve_data['cvss_v3_score'] = cvss_v3
                cve_data['cvss_v2_score'] = cvss_v2
                
                return cve_data
                
            return None
        except Exception as e:
            logging.error(f"Error fetching CVE {cve_id}: {e}")
            return None
    
    def search_by_product(self, vendor, product):
        """
        Search for vulnerabilities affecting a specific product.
        
        Args:
            vendor (str): The vendor name
            product (str): The product name
            
        Returns:
            list: List of CVE objects
        """
        try:
            url = f"{self.base_url}?cpeName=cpe:2.3:*:{vendor}:{product}:*"
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
            
            result = []
            for vuln in data.get('vulnerabilities', []):
                if 'cve' in vuln:
                    result.append(vuln['cve'])
            return result
        except Exception as e:
            logging.error(f"Error searching for {vendor} {product}: {e}")
            return []
    
    def get_exploitable(self):
        """
        Get a list of CVEs with known exploits.
        
        Returns:
            list: List of exploitable CVE objects
        """
        try:
            url = f"{self.base_url}?hasKev=true"
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
            
            result = []
            for vuln in data.get('vulnerabilities', []):
                if 'cve' in vuln:
                    result.append(vuln['cve'])
            return result
        except Exception as e:
            logging.error(f"Error fetching exploitable CVEs: {e}")
            return []
