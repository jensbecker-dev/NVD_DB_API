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
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import threading

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
EXPLOIT_DB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
EXPLOIT_DB_ARCHIVE_URL = "https://gitlab.com/exploit-database/exploitdb/-/archive/main/exploitdb-main.zip"
EXPLOIT_DB_CSV_FIELDS = ["id", "file", "description", "date", "author", "platform", "type", "port", "cve"]
EXPLOIT_DB_BASE_URL = "https://www.exploit-db.com/exploits/"
EXPLOIT_DB_RAW_URL = "https://www.exploit-db.com/raw/"

# Default paths for storing exploit data
DEFAULT_EXPLOIT_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'exploit_cache.db')
DEFAULT_EXPLOIT_FILES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'exploits')

# Create exploits directory if it doesn't exist
os.makedirs(DEFAULT_EXPLOIT_FILES_DIR, exist_ok=True)

class CirclAdapter:
    """
    Adapter for fetching and processing CVE data from CIRCL CVE Search API.
    CIRCL provides a comprehensive API with good search capabilities.
    """
    
    @staticmethod
    def fetch_latest_cves(limit=100):
        """
        Fetch the latest CVEs from the CIRCL API.
        
        Args:
            limit: Maximum number of CVEs to fetch
            
        Returns:
            list: List of standardized CVE items
        """
        try:
            logger.info(f"Fetching latest {limit} CVEs from CIRCL API")
            url = f"{CIRCL_API_BASE_URL}/last/{limit}"
            response = requests.get(url)
            response.raise_for_status()
            
            cve_items = []
            circl_items = response.json()
            
            for circl_item in circl_items:
                # Convert CIRCL format to our standardized format
                cve_id = circl_item.get('id')
                
                # Skip items without proper CVE ID
                if not cve_id or not cve_id.startswith('CVE-'):
                    continue
                
                # Format description
                description = circl_item.get('summary', '')
                
                # Extract CVSS information
                cvss = circl_item.get('cvss', None)
                impact = {}
                if cvss:
                    impact = {
                        "baseMetricV2": {
                            "cvssV2": {
                                "baseScore": cvss
                            }
                        }
                    }
                
                # Format references
                references = []
                for ref in circl_item.get('references', []):
                    references.append({
                        "url": ref,
                        "name": ref,
                        "source": "CIRCL"
                    })
                
                # Format dates
                published = circl_item.get('Published', '')
                modified = circl_item.get('Modified', '')
                
                # Create standardized CVE item
                cve_item = {
                    "cve": {
                        "CVE_data_meta": {
                            "ID": cve_id
                        },
                        "description": {
                            "description_data": [
                                {
                                    "lang": "en",
                                    "value": description
                                }
                            ]
                        },
                        "references": {
                            "reference_data": references
                        }
                    },
                    "publishedDate": published,
                    "lastModifiedDate": modified,
                    "impact": impact
                }
                
                cve_items.append(cve_item)
            
            logger.info(f"Fetched {len(cve_items)} CVE items from CIRCL API")
            return cve_items
            
        except Exception as e:
            logger.error(f"Error fetching latest CVEs from CIRCL API: {e}")
            return []
    
    @staticmethod
    def fetch_cve_by_id(cve_id):
        """
        Fetch a specific CVE by ID from the CIRCL API.
        
        Args:
            cve_id: The CVE ID to fetch
            
        Returns:
            dict: Standardized CVE item or None if not found
        """
        try:
            logger.info(f"Fetching CVE {cve_id} from CIRCL API")
            url = f"{CIRCL_API_BASE_URL}/cve/{cve_id}"
            response = requests.get(url)
            
            # If not found, return None
            if response.status_code == 404:
                logger.warning(f"CVE {cve_id} not found in CIRCL API")
                return None
            
            response.raise_for_status()
            circl_item = response.json()
            
            # Convert CIRCL format to our standardized format
            # Format description
            description = circl_item.get('summary', '')
            
            # Extract CVSS information
            cvss = circl_item.get('cvss', None)
            impact = {}
            if cvss:
                impact = {
                    "baseMetricV2": {
                        "cvssV2": {
                            "baseScore": cvss
                        }
                    }
                }
            
            # Format references
            references = []
            for ref in circl_item.get('references', []):
                references.append({
                    "url": ref,
                    "name": ref,
                    "source": "CIRCL"
                })
            
            # Format dates
            published = circl_item.get('Published', '')
            modified = circl_item.get('Modified', '')
            
            # Create standardized CVE item
            cve_item = {
                "cve": {
                    "CVE_data_meta": {
                        "ID": cve_id
                    },
                    "description": {
                        "description_data": [
                            {
                                "lang": "en",
                                "value": description
                            }
                        ]
                    },
                    "references": {
                        "reference_data": references
                    }
                },
                "publishedDate": published,
                "lastModifiedDate": modified,
                "impact": impact
            }
            
            return cve_item
            
        except Exception as e:
            logger.error(f"Error fetching CVE {cve_id} from CIRCL API: {e}")
            return None

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
                
                # Base directory after extraction (usually "exploitdb-main")
                base_dir = os.path.join(temp_dir, "exploitdb-main")
                
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
    def download_and_store_exploit(exploit_id):
        """
        Download and store the exploit code for a given exploit ID locally.
        
        Args:
            exploit_id: The Exploit-DB ID
            
        Returns:
            str: Path to the stored exploit file or None if failed
        """
        try:
            # Check if already exists in filesystem
            exploit_file_path = os.path.join(DEFAULT_EXPLOIT_FILES_DIR, f"{exploit_id}.txt")
            if os.path.exists(exploit_file_path):
                logger.info(f"Exploit code for ID {exploit_id} already exists at {exploit_file_path}")
                return exploit_file_path
                
            url = f"{EXPLOIT_DB_RAW_URL}{exploit_id}"
            logger.info(f"Downloading exploit code from {url}")
            response = requests.get(url)
            response.raise_for_status()
            
            # Save the exploit code to a file
            with open(exploit_file_path, 'w', encoding='utf-8', errors='ignore') as exploit_file:
                exploit_file.write(response.text)
            
            # Also update the SQLite database
            ExploitDBAdapter.update_exploit_db(exploit_id, response.text)
            
            logger.info(f"Stored exploit code for ID {exploit_id} at {exploit_file_path}")
            return exploit_file_path
            
        except Exception as e:
            logger.error(f"Error downloading or storing exploit code for ID {exploit_id}: {e}")
            return None
    
    @staticmethod
    def download_and_store_exploits_bulk(exploit_ids, max_workers=10):
        """
        Download and store multiple exploits in bulk using threading.
        
        Args:
            exploit_ids: List of Exploit-DB IDs
            max_workers: Maximum number of concurrent downloads
            
        Returns:
            dict: Mapping of exploit IDs to their stored file paths
        """
        exploit_file_map = {}
        exploit_ids_to_download = []
        
        # First check which exploits are already downloaded
        for exploit_id in exploit_ids:
            exploit_file_path = os.path.join(DEFAULT_EXPLOIT_FILES_DIR, f"{exploit_id}.txt")
            if os.path.exists(exploit_file_path):
                exploit_file_map[exploit_id] = exploit_file_path
            else:
                exploit_ids_to_download.append(exploit_id)
        
        logger.info(f"Found {len(exploit_file_map)} exploits already downloaded, will download {len(exploit_ids_to_download)} more")
        
        # Download exploits in parallel
        if exploit_ids_to_download:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_exploit_id = {executor.submit(ExploitDBAdapter.download_and_store_exploit, exploit_id): exploit_id 
                                      for exploit_id in exploit_ids_to_download}
                
                for future in as_completed(future_to_exploit_id):
                    exploit_id = future_to_exploit_id[future]
                    try:
                        exploit_file_path = future.result()
                        if exploit_file_path:
                            exploit_file_map[exploit_id] = exploit_file_path
                    except Exception as e:
                        logger.error(f"Error processing exploit ID {exploit_id}: {e}")
        
        logger.info(f"Downloaded and stored {len(exploit_file_map)} exploits in bulk")
        return exploit_file_map

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
                    "source": "Exploit-DB",
                    "local_file_exists": False
                }
                
                # Check if we have a local copy of this exploit
                exploit_id = exploit.get('exploit_id')
                if exploit_id:
                    local_file_path = os.path.join(DEFAULT_EXPLOIT_FILES_DIR, f"{exploit_id}.txt")
                    if os.path.exists(local_file_path):
                        exploit_data["local_file_exists"] = True
                        exploit_data["local_file_path"] = local_file_path
                    
                    # If not already downloaded, try to download in the background
                    if not exploit_data["local_file_exists"]:
                        threading.Thread(target=ExploitDBAdapter.download_and_store_exploit, args=(exploit_id,), daemon=True).start()
                
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
                        ref.get('url') == f"{EXPLOIT_DB_BASE_URL}{exploit_id}"
                        for ref in cve_item['cve']['references']['reference_data']
                    )
                    
                    if not reference_exists:
                        cve_item['cve']['references']['reference_data'].append({
                            "url": f"{EXPLOIT_DB_BASE_URL}{exploit_id}",
                            "name": f"Exploit-DB-{exploit_id}",
                            "source": "Exploit-DB",
                            "tags": ["Exploit", "PoC"]
                        })
            
            return cve_item
            
        except Exception as e:
            logger.error(f"Error enriching CVE item with exploit data: {e}")
            return cve_item

    @staticmethod
    def init_exploit_db():
        """
        Initialize the database for storing exploit code and metadata.
        """
        try:
            db_path = DEFAULT_EXPLOIT_DB_PATH
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Create tables if they don't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS exploit_code (
                    id TEXT PRIMARY KEY,
                    code TEXT,
                    fetch_date TEXT,
                    file_path TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS exploit_metadata (
                    id TEXT PRIMARY KEY,
                    cve_id TEXT,
                    description TEXT,
                    date TEXT,
                    author TEXT,
                    platform TEXT,
                    type TEXT,
                    file_path TEXT,
                    download_status INTEGER DEFAULT 0,
                    FOREIGN KEY (id) REFERENCES exploit_code(id)
                )
            ''')
            
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_exploit_metadata_cve_id ON exploit_metadata(cve_id)')
            
            conn.commit()
            conn.close()
            
            logger.info(f"Initialized exploit database at {db_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing exploit database: {e}")
            return False
    
    @staticmethod
    def update_exploit_db(exploit_id, code, metadata=None):
        """
        Update the exploit database with code and metadata.
        
        Args:
            exploit_id: The Exploit-DB ID
            code: The exploit code
            metadata: Additional metadata about the exploit
            
        Returns:
            bool: Success indicator
        """
        try:
            db_path = DEFAULT_EXPLOIT_DB_PATH
            file_path = os.path.join(DEFAULT_EXPLOIT_FILES_DIR, f"{exploit_id}.txt")
            
            # Initialize DB if needed
            if not os.path.exists(db_path):
                ExploitDBAdapter.init_exploit_db()
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Insert or update exploit code
            cursor.execute(
                "INSERT OR REPLACE INTO exploit_code (id, code, fetch_date, file_path) VALUES (?, ?, ?, ?)",
                (exploit_id, code, datetime.now().isoformat(), file_path)
            )
            
            # Insert or update metadata if provided
            if metadata:
                cursor.execute(
                    """INSERT OR REPLACE INTO exploit_metadata 
                       (id, cve_id, description, date, author, platform, type, file_path, download_status) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                    (
                        exploit_id,
                        metadata.get('cve_id', ''),
                        metadata.get('description', ''),
                        metadata.get('date', ''),
                        metadata.get('author', ''),
                        metadata.get('platform', ''),
                        metadata.get('type', ''),
                        metadata.get('file_path', file_path)
                    )
                )
            else:
                # Just mark as downloaded if no metadata
                cursor.execute(
                    """INSERT OR REPLACE INTO exploit_metadata 
                       (id, file_path, download_status) 
                       VALUES (?, ?, 1)
                       ON CONFLICT(id) DO UPDATE SET download_status = 1, file_path = ?""",
                    (exploit_id, file_path, file_path)
                )
            
            conn.commit()
            conn.close()
            
            logger.info(f"Updated exploit database with exploit ID {exploit_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating exploit database: {e}")
            return False
    
    @staticmethod
    def import_all_exploit_metadata():
        """
        Import all exploit metadata from Exploit-DB CSV into our database.
        
        Returns:
            int: Count of imported metadata records
        """
        try:
            # Make sure the database is initialized
            ExploitDBAdapter.init_exploit_db()
            
            # Fetch all exploit metadata from CSV
            logger.info("Importing all exploit metadata from Exploit-DB CSV")
            response = requests.get(EXPLOIT_DB_CSV_URL)
            response.raise_for_status()
            
            csv_data = response.text
            reader = csv.DictReader(StringIO(csv_data))
            
            # Connect to the database
            db_path = DEFAULT_EXPLOIT_DB_PATH
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Process and import each exploit record
            count = 0
            for row in reader:
                exploit_id = row.get('id', '')
                if not exploit_id:
                    continue
                
                # Process CVE field
                cve_field = row.get('cve', '')
                cve_id = None
                if cve_field and cve_field != '0':
                    # Handle both "CVE-YYYY-XXXXX" format and "YYYY-XXXXX" format
                    match = re.search(r'(?:CVE-)?(\d{4}-\d+)', cve_field)
                    if match:
                        cve_id = match.group(0)
                        if not cve_id.startswith('CVE-'):
                            cve_id = f"CVE-{cve_id}"
                
                file_path = os.path.join(DEFAULT_EXPLOIT_FILES_DIR, f"{exploit_id}.txt")
                download_status = 1 if os.path.exists(file_path) else 0
                
                # Insert metadata into database
                cursor.execute(
                    """INSERT OR REPLACE INTO exploit_metadata 
                       (id, cve_id, description, date, author, platform, type, file_path, download_status) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        exploit_id,
                        cve_id or '',
                        row.get('description', ''),
                        row.get('date', ''),
                        row.get('author', ''),
                        row.get('platform', ''),
                        row.get('type', ''),
                        row.get('file', ''),
                        download_status
                    )
                )
                
                count += 1
                
                # Commit periodically to avoid memory issues
                if count % 1000 == 0:
                    conn.commit()
                    logger.info(f"Imported {count} exploit metadata records so far")
            
            conn.commit()
            conn.close()
            
            logger.info(f"Imported {count} exploit metadata records in total")
            return count
            
        except Exception as e:
            logger.error(f"Error importing exploit metadata: {e}")
            return 0
    
    @staticmethod
    def download_all_exploits(limit=None, filter_cve_only=True):
        """
        Download all exploit code from Exploit-DB.
        
        Args:
            limit: Optional limit on number of exploits to download
            filter_cve_only: Whether to only download exploits with CVE IDs
            
        Returns:
            int: Number of exploits downloaded
        """
        try:
            # Make sure the database is initialized
            ExploitDBAdapter.init_exploit_db()
            
            # Import metadata if it's not already in the database
            db_path = DEFAULT_EXPLOIT_DB_PATH
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM exploit_metadata")
            metadata_count = cursor.fetchone()[0]
            
            if metadata_count == 0:
                logger.info("No exploit metadata found in database. Importing...")
                ExploitDBAdapter.import_all_exploit_metadata()
            
            # Query for exploit IDs to download
            query = "SELECT id FROM exploit_metadata WHERE download_status = 0"
            params = []
            
            if filter_cve_only:
                query += " AND cve_id != ''"
            
            if limit:
                query += " LIMIT ?"
                params.append(limit)
            
            cursor.execute(query, params)
            exploit_ids = [row[0] for row in cursor.fetchall()]
            conn.close()
            
            if not exploit_ids:
                logger.info("No new exploits to download")
                return 0
            
            logger.info(f"Downloading {len(exploit_ids)} exploits from Exploit-DB")
            
            # Download exploits in bulk
            exploit_file_map = ExploitDBAdapter.download_and_store_exploits_bulk(exploit_ids)
            
            logger.info(f"Successfully downloaded {len(exploit_file_map)} exploits")
            return len(exploit_file_map)
            
        except Exception as e:
            logger.error(f"Error downloading all exploits: {e}")
            return 0
    
    @staticmethod
    def get_locally_available_exploits():
        """
        Get a list of exploit IDs that are available locally.
        
        Returns:
            list: List of exploit IDs that have been downloaded
        """
        try:
            # Check for exploits in filesystem
            file_exploit_ids = []
            if os.path.exists(DEFAULT_EXPLOIT_FILES_DIR):
                file_exploit_ids = [f.stem for f in Path(DEFAULT_EXPLOIT_FILES_DIR).glob('*.txt')]
            
            # Check for exploits in database
            db_exploit_ids = []
            db_path = DEFAULT_EXPLOIT_DB_PATH
            if os.path.exists(db_path):
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM exploit_code")
                db_exploit_ids = [row[0] for row in cursor.fetchall()]
                conn.close()
            
            # Combine and de-duplicate
            all_exploit_ids = list(set(file_exploit_ids + db_exploit_ids))
            logger.info(f"Found {len(all_exploit_ids)} locally available exploits")
            return all_exploit_ids
            
        except Exception as e:
            logger.error(f"Error getting locally available exploits: {e}")
            return []
    
    @staticmethod
    def get_exploits_for_cve(cve_id):
        """
        Get all exploits associated with a specific CVE ID.
        
        Args:
            cve_id: The CVE ID
            
        Returns:
            list: List of exploit metadata and file paths
        """
        if not cve_id:
            return []
        
        try:
            # Convert to standard format if needed
            if not cve_id.startswith('CVE-'):
                cve_id = f"CVE-{cve_id}"
            
            # Query the database for exploits
            db_path = DEFAULT_EXPLOIT_DB_PATH
            if not os.path.exists(db_path):
                ExploitDBAdapter.init_exploit_db()
                ExploitDBAdapter.import_all_exploit_metadata()
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT m.id, m.description, m.date, m.author, m.platform, m.type, m.file_path, m.download_status, c.file_path
                FROM exploit_metadata m
                LEFT JOIN exploit_code c ON m.id = c.id
                WHERE m.cve_id LIKE ?
            """, (f"%{cve_id}%",))
            
            results = cursor.fetchall()
            conn.close()
            
            exploits = []
            for row in results:
                exploit_id = row[0]
                local_file_path = row[8] if row[8] else None
                download_status = row[7]
                
                if not local_file_path and download_status == 1:
                    # If marked as downloaded but no file path in exploit_code,
                    # check if file exists in filesystem
                    file_path = os.path.join(DEFAULT_EXPLOIT_FILES_DIR, f"{exploit_id}.txt")
                    if os.path.exists(file_path):
                        local_file_path = file_path
                
                exploits.append({
                    'exploit_id': exploit_id,
                    'description': row[1],
                    'date': row[2],
                    'author': row[3],
                    'platform': row[4],
                    'type': row[5],
                    'original_file_path': row[6],
                    'downloaded': download_status == 1,
                    'local_file_path': local_file_path,
                    'url': f"{EXPLOIT_DB_BASE_URL}{exploit_id}"
                })
            
            logger.info(f"Found {len(exploits)} exploits for CVE {cve_id}")
            return exploits
            
        except Exception as e:
            logger.error(f"Error getting exploits for CVE {cve_id}: {e}")
            return []
            
    @staticmethod
    def create_standardized_cve_items(exploit_entries):
        """
        Convert exploit entries to standardized CVE items.
        
        Args:
            exploit_entries: List of exploit entries from Exploit-DB CSV
            
        Returns:
            list: List of standardized CVE items with exploit data
        """
        cve_items = []
        for exploit in exploit_entries:
            cve_id = exploit.get('cve_id')
            if not cve_id:
                continue
            
            cve_item = {
                "cve": {
                    "CVE_data_meta": {
                        "ID": cve_id
                    },
                    "description": {
                        "description_data": [
                            {
                                "lang": "en",
                                "value": exploit.get('description', '')
                            }
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "url": f"{EXPLOIT_DB_BASE_URL}{exploit.get('exploit_id')}",
                                "name": f"Exploit-DB-{exploit.get('exploit_id')}",
                                "source": "Exploit-DB",
                                "tags": ["Exploit", "PoC"]
                            }
                        ]
                    }
                },
                "publishedDate": exploit.get('date', ''),
                "lastModifiedDate": exploit.get('date', ''),
                "impact": {},
                "has_exploit": True
            }
            
            cve_items.append(cve_item)
        
        return cve_items

class MitreAdapter:
    """
    Adapter for fetching and processing CVE data from MITRE.
    Focuses on historical CVE data from 1992-2002.
    """
    
    @staticmethod
    def fetch_historical_data_csv():
        """
        Fetch and parse historical CVE data from MITRE's CSV format.
        
        Returns:
            list: List of standardized CVE items
        """
        try:
            logger.info(f"Fetching historical CVE data from {MITRE_CVE_HISTORICAL_URL}")
            response = requests.get(MITRE_CVE_HISTORICAL_URL)
            response.raise_for_status()
            
            csv_data = response.text
            reader = csv.reader(StringIO(csv_data))
            
            # Skip header row
            next(reader, None)
            
            cve_items = []
            for row in reader:
                if len(row) < 4:
                    continue
                
                cve_id = row[0].strip()
                status = row[1].strip() if len(row) > 1 else ""
                description = row[2].strip() if len(row) > 2 else ""
                
                # Skip entries that aren't proper CVE IDs
                if not cve_id.startswith("CVE-"):
                    continue
                
                # Convert to standardized format
                cve_item = {
                    "cve": {
                        "CVE_data_meta": {
                            "ID": cve_id
                        },
                        "description": {
                            "description_data": [
                                {
                                    "lang": "en",
                                    "value": description
                                }
                            ]
                        },
                        "references": {
                            "reference_data": []
                        }
                    },
                    "publishedDate": None,  # Historical data often lacks precise dates
                    "lastModifiedDate": None,
                    "impact": {}
                }
                
                cve_items.append(cve_item)
            
            logger.info(f"Fetched {len(cve_items)} CVE items from MITRE CSV")
            return cve_items
            
        except Exception as e:
            logger.error(f"Error fetching historical data from MITRE CSV: {e}")
            return []
    
    @staticmethod
    def fetch_historical_data_xml():
        """
        Fetch and parse historical CVE data from MITRE's XML format.
        Generally more complete than CSV format.
        
        Returns:
            list: List of standardized CVE items
        """
        try:
            logger.info(f"Fetching historical CVE data from {MITRE_CVE_XML_URL}")
            response = requests.get(MITRE_CVE_XML_URL)
            response.raise_for_status()
            
            # Parse XML
            root = ET.fromstring(response.content)
            
            cve_items = []
            for item in root.findall(".//item"):
                cve_id = item.get("name", "")
                
                # Skip entries that aren't proper CVE IDs
                if not cve_id.startswith("CVE-"):
                    continue
                
                # Extract description and other data
                description = ""
                desc_elem = item.find("desc")
                if desc_elem is not None and desc_elem.text:
                    description = desc_elem.text.strip()
                
                # Extract published date if available
                published_date = None
                date_elem = item.find("date")
                if date_elem is not None and date_elem.text:
                    try:
                        date_str = date_elem.text.strip()
                        # Convert to ISO format
                        published_date = datetime.strptime(date_str, "%Y-%m-%d").isoformat() + "Z"
                    except Exception:
                        pass
                
                # Extract references
                references = []
                refs_elem = item.find("refs")
                if refs_elem is not None:
                    for ref in refs_elem.findall("ref"):
                        ref_url = ref.get("url", "")
                        ref_source = ref.get("source", "")
                        if ref_url:
                            references.append({
                                "url": ref_url,
                                "name": ref_source,
                                "source": "MITRE"
                            })
                
                # Convert to standardized format
                cve_item = {
                    "cve": {
                        "CVE_data_meta": {
                            "ID": cve_id
                        },
                        "description": {
                            "description_data": [
                                {
                                    "lang": "en",
                                    "value": description
                                }
                            ]
                        },
                        "references": {
                            "reference_data": references
                        }
                    },
                    "publishedDate": published_date,
                    "lastModifiedDate": published_date,
                    "impact": {}
                }
                
                cve_items.append(cve_item)
            
            logger.info(f"Fetched {len(cve_items)} CVE items from MITRE XML")
            return cve_items
            
        except Exception as e:
            logger.error(f"Error fetching historical data from MITRE XML: {e}")
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