"""
Module for handling additional CVE data sources beyond the standard NVD database.
This module provides integration with:
1. MITRE CVE List (for historical data from 1992-2002)
2. CIRCL CVE Search API
3. NIST Data.gov CVE API
4. Exploit-DB (for exploit/PoC information)

Each source has its own adapter to normalize data to our database schema.
"""

import requests
import json
import logging
import time
from datetime import datetime
import os
import re
import csv
from io import StringIO
import xml.etree.ElementTree as ET
import zipfile
import io
import sqlite3
import tempfile

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants for MITRE CVE data
MITRE_CVE_HISTORICAL_URL = "https://cve.mitre.org/data/downloads/allitems.csv"
MITRE_CVE_XML_URL = "https://cve.mitre.org/data/downloads/allitems.xml"

# Constants for CIRCL API
CIRCL_API_BASE_URL = "https://cve.circl.lu/api"

# Constants for NIST Data.gov API
NIST_DATA_GOV_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Constants for Exploit-DB
EXPLOIT_DB_CSV_URL = "https://github.com/offensive-security/exploitdb/raw/master/files_exploits.csv"
EXPLOIT_DB_ARCHIVE_URL = "https://github.com/offensive-security/exploitdb/archive/master.zip"
EXPLOIT_DB_CSV_FIELDS = ["id", "file", "description", "date", "author", "platform", "type", "port", "cve"]

class ExploitDBAdapter:
    """
    Adapter for fetching and processing exploit data from Exploit-DB.
    This provides actual exploit code and proof-of-concept references for CVEs.
    """
    
    @staticmethod
    def fetch_exploits_csv():
        """
        Fetch the Exploit-DB CSV file containing exploit metadata.
        
        Returns:
            list: List of exploit entries
        """
        try:
            logger.info(f"Fetching Exploit-DB CSV data from {EXPLOIT_DB_CSV_URL}")
            response = requests.get(EXPLOIT_DB_CSV_URL)
            response.raise_for_status()
            
            # Parse CSV data
            csv_data = response.text
            reader = csv.DictReader(StringIO(csv_data))
            
            # Process and return the data
            exploit_entries = []
            for row in reader:
                # Only include entries with CVE IDs
                cve_field = row.get('cve', '')
                if not cve_field or cve_field == '0':
                    continue
                
                # Sometimes multiple CVEs are included in one entry
                cve_ids = []
                # Handle both "CVE-YYYY-XXXXX" format and "YYYY-XXXXX" format
                for cve_match in re.finditer(r'(?:CVE-)?(\d{4}-\d+)', cve_field):
                    cve_id = cve_match.group(0)
                    if not cve_id.startswith('CVE-'):
                        cve_id = f"CVE-{cve_id}"
                    cve_ids.append(cve_id)
                
                if not cve_ids:
                    continue
                
                for cve_id in cve_ids:
                    exploit_entry = {
                        'exploit_id': row.get('id', ''),
                        'file_path': row.get('file', ''),
                        'description': row.get('description', ''),
                        'date': row.get('date', ''),
                        'author': row.get('author', ''),
                        'platform': row.get('platform', ''),
                        'type': row.get('type', ''),
                        'port': row.get('port', ''),
                        'cve_id': cve_id
                    }
                    exploit_entries.append(exploit_entry)
            
            logger.info(f"Fetched {len(exploit_entries)} exploit entries from Exploit-DB CSV")
            return exploit_entries
            
        except Exception as e:
            logger.error(f"Error fetching Exploit-DB CSV data: {e}")
            return []
    
    @staticmethod
    def download_and_extract_exploits():
        """
        Download and extract the Exploit-DB repository to get full exploit code.
        This is a heavy operation and should be used sparingly.
        
        Returns:
            dict: Mapping of exploit IDs to their code content
        """
        try:
            logger.info(f"Downloading Exploit-DB archive from {EXPLOIT_DB_ARCHIVE_URL}")
            response = requests.get(EXPLOIT_DB_ARCHIVE_URL, stream=True)
            response.raise_for_status()
            
            # Create a temporary directory to extract the files
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract the archive
                logger.info("Extracting Exploit-DB archive...")
                zip_file = zipfile.ZipFile(io.BytesIO(response.content))
                zip_file.extractall(temp_dir)
                
                # Base directory after extraction (usually "exploitdb-master")
                base_dir = os.path.join(temp_dir, "exploitdb-master")
                
                # Get CSV data to map exploit IDs to file paths
                csv_path = os.path.join(base_dir, "files_exploits.csv")
                if not os.path.exists(csv_path):
                    logger.error("Could not find exploits CSV in the extracted archive")
                    return {}
                
                exploit_code_map = {}
                with open(csv_path, 'r', encoding='utf-8', errors='ignore') as csv_file:
                    reader = csv.DictReader(csv_file)
                    for row in reader:
                        exploit_id = row.get('id', '')
                        file_path = row.get('file', '')
                        
                        if not exploit_id or not file_path:
                            continue
                        
                        full_path = os.path.join(base_dir, file_path)
                        if os.path.exists(full_path):
                            try:
                                with open(full_path, 'r', encoding='utf-8', errors='ignore') as code_file:
                                    exploit_code = code_file.read()
                                    exploit_code_map[exploit_id] = exploit_code
                            except Exception as e:
                                logger.warning(f"Error reading exploit file {full_path}: {e}")
                
                logger.info(f"Loaded {len(exploit_code_map)} exploit code files from the repository")
                return exploit_code_map
                
        except Exception as e:
            logger.error(f"Error downloading or extracting Exploit-DB repository: {e}")
            return {}
    
    @staticmethod
    def create_standardized_cve_items(exploit_entries):
        """
        Convert Exploit-DB entries to our standardized CVE item format.
        
        Args:
            exploit_entries: List of exploit entries from Exploit-DB
            
        Returns:
            list: List of CVE items in our standard format, enriched with exploit information
        """
        try:
            # Group exploits by CVE ID
            cve_to_exploits = {}
            for entry in exploit_entries:
                cve_id = entry.get('cve_id')
                if not cve_id:
                    continue
                
                if cve_id not in cve_to_exploits:
                    cve_to_exploits[cve_id] = []
                
                cve_to_exploits[cve_id].append(entry)
            
            # Create standardized CVE items
            cve_items = []
            for cve_id, exploits in cve_to_exploits.items():
                # Get the most recent exploit for the main description
                most_recent_exploit = max(exploits, key=lambda x: x.get('date', ''))
                
                # Create a standardized CVE item
                cve_item = {
                    "cve": {
                        "CVE_data_meta": {
                            "ID": cve_id
                        },
                        "description": {
                            "description_data": [
                                {
                                    "lang": "en",
                                    "value": most_recent_exploit.get('description', '')
                                }
                            ]
                        },
                        "references": {
                            "reference_data": []
                        },
                        "exploit_data": [] # Add exploit data as a new field
                    },
                    "publishedDate": most_recent_exploit.get('date'),
                    "lastModifiedDate": most_recent_exploit.get('date'),
                    "impact": {},
                    "has_exploit": True
                }
                
                # Add all exploits for this CVE
                for exploit in exploits:
                    exploit_data = {
                        "exploit_id": exploit.get('exploit_id'),
                        "file_path": exploit.get('file_path'),
                        "description": exploit.get('description'),
                        "date": exploit.get('date'),
                        "author": exploit.get('author'),
                        "platform": exploit.get('platform'),
                        "type": exploit.get('type'),
                        "source": "Exploit-DB"
                    }
                    cve_item["cve"]["exploit_data"].append(exploit_data)
                    
                    # Add a reference to Exploit-DB
                    exploit_id = exploit.get('exploit_id')
                    if exploit_id:
                        cve_item["cve"]["references"]["reference_data"].append({
                            "url": f"https://www.exploit-db.com/exploits/{exploit_id}",
                            "name": f"Exploit-DB-{exploit_id}",
                            "source": "Exploit-DB",
                            "tags": ["Exploit", "PoC"]
                        })
                
                cve_items.append(cve_item)
            
            logger.info(f"Created {len(cve_items)} standardized CVE items from Exploit-DB data")
            return cve_items
            
        except Exception as e:
            logger.error(f"Error creating standardized CVE items from Exploit-DB data: {e}")
            return []
    
    @staticmethod
    def fetch_cve_exploits():
        """
        Fetch exploit information for CVEs from Exploit-DB.
        
        Returns:
            list: List of CVE items with exploit information
        """
        # Fetch exploit metadata from CSV
        exploit_entries = ExploitDBAdapter.fetch_exploits_csv()
        if not exploit_entries:
            return []
        
        # Convert to our standardized format
        return ExploitDBAdapter.create_standardized_cve_items(exploit_entries)
    
    @staticmethod
    def enrich_cve_item_with_exploits(cve_item):
        """
        Enrich a CVE item with exploit information from Exploit-DB.
        
        Args:
            cve_item: CVE item in standardized format
            
        Returns:
            dict: Enriched CVE item
        """
        try:
            cve_id = cve_item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
            if not cve_id:
                return cve_item
            
            # Fetch all exploit entries
            exploit_entries = ExploitDBAdapter.fetch_exploits_csv()
            if not exploit_entries:
                return cve_item
            
            # Find matching exploits for this CVE
            matching_exploits = [e for e in exploit_entries if e.get('cve_id') == cve_id]
            if not matching_exploits:
                return cve_item
            
            # Add exploit data to the CVE item
            if 'cve' not in cve_item:
                cve_item['cve'] = {}
            
            if 'exploit_data' not in cve_item['cve']:
                cve_item['cve']['exploit_data'] = []
            
            for exploit in matching_exploits:
                exploit_data = {
                    "exploit_id": exploit.get('exploit_id'),
                    "file_path": exploit.get('file_path'),
                    "description": exploit.get('description'),
                    "date": exploit.get('date'),
                    "author": exploit.get('author'),
                    "platform": exploit.get('platform'),
                    "type": exploit.get('type'),
                    "source": "Exploit-DB"
                }
                cve_item['cve']['exploit_data'].append(exploit_data)
            
            # Add a flag indicating that this CVE has exploits
            cve_item['has_exploit'] = True
            
            # Add references to Exploit-DB
            if 'references' not in cve_item['cve']:
                cve_item['cve']['references'] = {'reference_data': []}
            
            for exploit in matching_exploits:
                exploit_id = exploit.get('exploit_id')
                if exploit_id:
                    # Check if reference already exists to avoid duplicates
                    reference_exists = any(
                        ref.get('url') == f"https://www.exploit-db.com/exploits/{exploit_id}"
                        for ref in cve_item['cve']['references']['reference_data']
                    )
                    
                    if not reference_exists:
                        cve_item['cve']['references']['reference_data'].append({
                            "url": f"https://www.exploit-db.com/exploits/{exploit_id}",
                            "name": f"Exploit-DB-{exploit_id}",
                            "source": "Exploit-DB",
                            "tags": ["Exploit", "PoC"]
                        })
            
            return cve_item
            
        except Exception as e:
            logger.error(f"Error enriching CVE item with exploit data: {e}")
            return cve_item

class MitreAdapter:
    """
    Adapter for fetching and processing historical CVE data from MITRE.
    """

    @staticmethod
    def fetch_historical_data_csv():
        """
        Fetch historical CVE data from MITRE's CSV file.

        Returns:
            list: List of CVE items from the CSV source.
        """
        logger.info(f"Fetching historical CVE data from MITRE CSV: {MITRE_CVE_HISTORICAL_URL}")
        cve_items = []
        try:
            response = requests.get(MITRE_CVE_HISTORICAL_URL)
            response.raise_for_status()
            # MITRE CSV uses Latin-1 encoding
            response.encoding = 'latin-1'
            csv_data = response.text
            # Skip header lines before the actual CSV header
            lines = csv_data.splitlines()
            start_line = 0
            for i, line in enumerate(lines):
                if line.startswith('"Name"'):
                    start_line = i
                    break
            
            if start_line == 0 and not lines[0].startswith('"Name"'):
                 logger.error("Could not find CSV header in MITRE data.")
                 return []

            csv_content = "\n".join(lines[start_line:])
            reader = csv.DictReader(StringIO(csv_content))

            for row in reader:
                cve_id = row.get('Name')
                if not cve_id or not cve_id.startswith('CVE-'):
                    continue

                # Basic conversion to standardized format
                cve_item = {
                    "cve": {
                        "CVE_data_meta": {"ID": cve_id},
                        "description": {
                            "description_data": [{"lang": "en", "value": row.get('Description', '')}]
                        },
                        "references": {
                            "reference_data": [] # CSV format doesn't typically contain structured references
                        }
                    },
                    "publishedDate": None, # Not directly available in this CSV format
                    "lastModifiedDate": None, # Not directly available
                    "impact": {}, # Not available in this CSV format
                    "source": "MITRE_CSV"
                }
                # References might be embedded in description or other fields, requires complex parsing

                cve_items.append(cve_item)

            logger.info(f"Fetched {len(cve_items)} items from MITRE CSV")
            return cve_items

        except requests.exceptions.RequestException as e:
            logger.error(f"HTTP Error fetching MITRE CSV data: {e}")
            return []
        except csv.Error as e:
            logger.error(f"CSV Error parsing MITRE data: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error fetching or parsing MITRE CSV data: {e}")
            return []

    @staticmethod
    def fetch_historical_data_xml():
        """
        Fetch historical CVE data from MITRE's XML file.
        Note: MITRE's 'allitems.xml' is often deprecated or unavailable.
              This method provides a basic structure but might need adjustments
              if a suitable XML source is identified.

        Returns:
            list: List of CVE items from the XML source.
        """
        logger.warning(f"Attempting to fetch historical CVE data from MITRE XML: {MITRE_CVE_XML_URL}. This source may be deprecated.")
        cve_items = []
        try:
            # Add a timeout to avoid hanging indefinitely
            response = requests.get(MITRE_CVE_XML_URL, timeout=60)
            response.raise_for_status()
            xml_content = response.content

            # Parse XML (MITRE's XML structure can vary, this is a guess)
            # It's common for large XML files to require iterative parsing
            # For simplicity, we attempt direct parsing here.
            root = ET.fromstring(xml_content)
            # Namespace handling might be necessary, e.g., ns = {'cve': 'http://some.namespace/url'}
            # Findall calls would then use ns, e.g., root.findall('.//cve:item', ns)

            # Adjust XPath based on the actual structure of the XML file
            for item_elem in root.findall('.//item'): # Example XPath
                cve_id = item_elem.get('name') # Example attribute
                if not cve_id or not cve_id.startswith('CVE-'):
                    continue

                desc_elem = item_elem.find('.//description') # Example XPath
                description = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else 'No description available.'

                refs_data = []
                refs_container = item_elem.find('.//references') # Example XPath
                if refs_container is not None:
                    for ref_elem in refs_container.findall('.//reference'): # Example XPath
                        url = ref_elem.get('url') # Example attribute
                        source = ref_elem.get('source') # Example attribute
                        if url:
                            refs_data.append({
                                "url": url,
                                "name": url, # Or use source if available
                                "source": source or "MITRE",
                                "tags": []
                            })

                # Basic conversion to standardized format
                cve_item = {
                    "cve": {
                        "CVE_data_meta": {"ID": cve_id},
                        "description": {
                            "description_data": [{"lang": "en", "value": description}]
                        },
                        "references": {
                            "reference_data": refs_data
                        }
                    },
                    "publishedDate": item_elem.get('published'), # Example attribute
                    "lastModifiedDate": item_elem.get('modified'), # Example attribute
                    "impact": {}, # Extract CVSS if available in XML
                    "source": "MITRE_XML"
                }
                cve_items.append(cve_item)

            logger.info(f"Fetched {len(cve_items)} items from MITRE XML")
            return cve_items

        except requests.exceptions.Timeout:
            logger.error(f"Timeout occurred while fetching MITRE XML data from {MITRE_CVE_XML_URL}")
            return []
        except requests.exceptions.RequestException as e:
            logger.error(f"HTTP Error fetching MITRE XML data: {e}")
            # MITRE XML might return 404 or other errors if deprecated
            return []
        except ET.ParseError as e:
            logger.error(f"Error parsing MITRE XML data: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error fetching or processing MITRE XML data: {e}")
            return []

def fetch_historical_cve_data():
    """
    Fetch historical CVE data from MITRE for years 1992-2002.
    
    Returns:
        list: List of CVE items from historical sources
    """
    logger.info("Fetching historical CVE data (1992-2002)...")
    
    # Try to fetch data using both methods (CSV and XML)
    items_from_csv = MitreAdapter.fetch_historical_data_csv()
    items_from_xml = MitreAdapter.fetch_historical_data_xml()
    
    # Merge the data, preferring XML when both have the same CVE ID
    cve_items = {}
    
    # Add CSV items first
    for item in items_from_csv:
        cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
        if cve_id:
            cve_items[cve_id] = item
    
    # Add XML items, overwriting CSV items if they exist
    for item in items_from_xml:
        cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
        if cve_id:
            cve_items[cve_id] = item
    
    # Convert dict back to list
    historical_items = list(cve_items.values())
    
    logger.info(f"Fetched {len(historical_items)} historical CVE items")
    return historical_items

def enrich_cve_data(cve_item):
    """
    Enrich a CVE item with additional data from alternative sources.
    
    Args:
        cve_item: CVE item in standardized format
        
    Returns:
        dict: Enriched CVE item
    """
    try:
        cve_id = cve_item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
        if not cve_id:
            return cve_item
        
        # Try to get additional data from CIRCL
        circl_item = CirclAdapter.fetch_cve_by_id(cve_id)
        if circl_item:
            # 1. If no CVSS scores, add from CIRCL
            if 'impact' not in cve_item or not cve_item['impact']:
                cve_item['impact'] = circl_item.get('impact', {})
            
            # 2. If no references, add from CIRCL
            if ('cve' in cve_item and 'references' not in cve_item['cve']) or \
               ('cve' in cve_item and 'references' in cve_item['cve'] and not cve_item['cve']['references'].get('reference_data')):
                cve_item['cve']['references'] = circl_item.get('cve', {}).get('references', {'reference_data': []})
            
            # 3. Supplement or update description if needed
            circl_desc = circl_item.get('cve', {}).get('description', {}).get('description_data', [])
            if circl_desc and ('cve' not in cve_item or 
                              'description' not in cve_item['cve'] or 
                              not cve_item['cve']['description'].get('description_data')):
                cve_item['cve']['description'] = {'description_data': circl_desc}
        
        # Try to enrich with exploit data from Exploit-DB
        cve_item = ExploitDBAdapter.enrich_cve_item_with_exploits(cve_item)
        
        return cve_item
        
    except Exception as e:
        logger.error(f"Error enriching CVE data: {e}")
        return cve_item

def fetch_all_additional_sources():
    """
    Fetch CVE data from all additional sources beyond the standard NVD feed.
    
    Returns:
        list: List of CVE items from additional sources
    """
    all_additional_items = []
    
    # 1. Fetch historical data (1992-2002)
    historical_items = fetch_historical_cve_data()
    all_additional_items.extend(historical_items)
    
    # 2. Fetch latest data from CIRCL
    circl_items = CirclAdapter.fetch_latest_cves(1000)
    
    # Create a mapping of existing CVE IDs to avoid duplicates
    existing_cve_ids = {item.get('cve', {}).get('CVE_data_meta', {}).get('ID'): True 
                       for item in all_additional_items}
    
    # Only add items that don't already exist
    new_circl_items = [item for item in circl_items 
                      if item.get('cve', {}).get('CVE_data_meta', {}).get('ID') not in existing_cve_ids]
    
    all_additional_items.extend(new_circl_items)
    
    # Update our set of existing CVE IDs after adding CIRCL items
    for item in new_circl_items:
        cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
        if cve_id:
            existing_cve_ids[cve_id] = True
    
    # 3. Fetch exploit data from Exploit-DB
    logger.info("Fetching exploit data from Exploit-DB...")
    exploit_items = ExploitDBAdapter.fetch_cve_exploits()
    
    # Only add items that don't already exist
    new_exploit_items = [item for item in exploit_items 
                        if item.get('cve', {}).get('CVE_data_meta', {}).get('ID') not in existing_cve_ids]
    
    # For existing items, try to enrich them with exploit data
    for item in all_additional_items:
        cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
        if not cve_id:
            continue
        
        # Find matching exploit item
        matching_exploit = next((e for e in exploit_items 
                               if e.get('cve', {}).get('CVE_data_meta', {}).get('ID') == cve_id), None)
        
        if matching_exploit:
            # Add exploit data to the existing item
            if 'exploit_data' in matching_exploit.get('cve', {}):
                if 'exploit_data' not in item.get('cve', {}):
                    item['cve']['exploit_data'] = []
                item['cve']['exploit_data'].extend(matching_exploit['cve']['exploit_data'])
            
            # Mark as having an exploit
            item['has_exploit'] = True
            
            # Add Exploit-DB references
            if 'references' in matching_exploit.get('cve', {}):
                if 'references' not in item.get('cve', {}):
                    item['cve']['references'] = {'reference_data': []}
                
                for ref in matching_exploit['cve']['references'].get('reference_data', []):
                    if ref.get('source') == 'Exploit-DB':
                        # Check if reference already exists
                        if not any(r.get('url') == ref.get('url') for r in item['cve']['references']['reference_data']):
                            item['cve']['references']['reference_data'].append(ref)
    
    all_additional_items.extend(new_exploit_items)
    
    logger.info(f"Fetched a total of {len(all_additional_items)} CVE items from additional sources")
    return all_additional_items