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
import hashlib

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
EXPLOIT_DB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv?ref_type=heads&inline=false"
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
    def init_exploit_db():
        """
        Initialize the SQLite database for storing exploit metadata and code.
        Creates the database and tables if they don't exist.
        
        Returns:
            bool: Success indicator
        """
        try:
            db_path = DEFAULT_EXPLOIT_DB_PATH
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Create exploit_metadata table if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS exploit_metadata (
                    id TEXT PRIMARY KEY,
                    cve_id TEXT,
                    description TEXT,
                    date TEXT,
                    author TEXT,
                    platform TEXT,
                    type TEXT,
                    file_path TEXT,
                    download_status INTEGER DEFAULT 0
                )
            """)
            
            # Create exploit_code table if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS exploit_code (
                    id TEXT PRIMARY KEY,
                    code TEXT,
                    fetch_date TEXT,
                    file_path TEXT,
                    checksum TEXT
                )
            """)
            
            # Create indexes for performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_id ON exploit_metadata (cve_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_download_status ON exploit_metadata (download_status)")
            
            conn.commit()
            conn.close()
            
            logger.info(f"Initialized exploit database at {db_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing exploit database: {e}")
            return False

    @staticmethod
    def import_all_exploit_metadata():
        """
        Import all exploit metadata from Exploit-DB CSV into the local database.
        
        Returns:
            int: Number of imported entries
        """
        try:
            # Ensure database is initialized
            ExploitDBAdapter.init_exploit_db()
            
            # Fetch exploit metadata
            exploit_entries = ExploitDBAdapter.fetch_exploits_csv()
            if not exploit_entries:
                logger.warning("No exploit entries fetched from Exploit-DB CSV")
                return 0
                
            # Connect to database
            db_path = DEFAULT_EXPLOIT_DB_PATH
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Insert entries into database
            count = 0
            for entry in exploit_entries:
                try:
                    cursor.execute(
                        """INSERT OR REPLACE INTO exploit_metadata 
                           (id, cve_id, description, date, author, platform, type, file_path, download_status) 
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 
                                   (SELECT download_status FROM exploit_metadata WHERE id = ? LIMIT 1))""",
                        (
                            entry['exploit_id'],
                            entry['cve_id'],
                            entry['description'],
                            entry['date'],
                            entry['author'],
                            entry['platform'],
                            entry['type'],
                            entry['file_path'],
                            entry['exploit_id']
                        )
                    )
                    count += 1
                    
                    # Commit in batches to prevent memory issues
                    if count % 1000 == 0:
                        conn.commit()
                        logger.info(f"Committed {count} exploit metadata entries")
                except Exception as e:
                    logger.error(f"Error inserting exploit entry {entry.get('exploit_id')}: {e}")
            
            conn.commit()
            conn.close()
            
            logger.info(f"Imported {count} exploit metadata entries into database")
            return count
            
        except Exception as e:
            logger.error(f"Error importing all exploit metadata: {e}")
            return 0
            
    @staticmethod
    def get_locally_available_exploits():
        """
        Get a list of all exploit IDs that are locally available.
        
        Returns:
            list: List of exploit IDs
        """
        try:
            # Check if database exists
            db_path = DEFAULT_EXPLOIT_DB_PATH
            if not os.path.exists(db_path):
                return []
                
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Query for exploit IDs with download_status = 1
            cursor.execute("SELECT id FROM exploit_metadata WHERE download_status = 1")
            exploit_ids = [row[0] for row in cursor.fetchall()]
            
            conn.close()
            
            return exploit_ids
            
        except Exception as e:
            logger.error(f"Error getting locally available exploits: {e}")
            return []
            
    @staticmethod
    def get_exploits_for_cve(cve_id):
        """
        Get all exploits associated with a specific CVE ID.
        
        Args:
            cve_id: The CVE ID to lookup
            
        Returns:
            list: List of exploit metadata dictionaries
        """
        try:
            # Check if database exists
            db_path = DEFAULT_EXPLOIT_DB_PATH
            if not os.path.exists(db_path):
                ExploitDBAdapter.init_exploit_db()
                return []
                
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Query for exploits matching the CVE ID
            cursor.execute(
                """SELECT id, description, date, author, platform, type, file_path, download_status 
                   FROM exploit_metadata 
                   WHERE cve_id LIKE ? 
                   ORDER BY date DESC""",
                (f"%{cve_id}%",)
            )
            
            exploits = []
            for row in cursor.fetchall():
                exploit_id, description, date, author, platform, exploit_type, file_path, download_status = row
                
                # Check if the exploit code is downloaded
                has_code = download_status == 1
                
                exploits.append({
                    'exploit_id': exploit_id,
                    'description': description,
                    'date': date,
                    'author': author,
                    'platform': platform,
                    'type': exploit_type,
                    'has_code': has_code,
                    'url': f"{EXPLOIT_DB_BASE_URL}{exploit_id}",
                    'raw_url': f"{EXPLOIT_DB_RAW_URL}{exploit_id}"
                })
            
            conn.close()
            
            return exploits
            
        except Exception as e:
            logger.error(f"Error getting exploits for CVE {cve_id}: {e}")
            return []
            
    @staticmethod
    def get_exploit_code_content(exploit_id):
        """
        Get the code content of a specific exploit.
        
        Args:
            exploit_id: The Exploit-DB ID
            
        Returns:
            str: The exploit code or None if not available
        """
        try:
            # Try to get from file first
            file_path = os.path.join(DEFAULT_EXPLOIT_FILES_DIR, f"{exploit_id}.txt")
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
            
            # If not in file, try database
            db_path = DEFAULT_EXPLOIT_DB_PATH
            if os.path.exists(db_path):
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                
                cursor.execute("SELECT code FROM exploit_code WHERE id = ?", (exploit_id,))
                result = cursor.fetchone()
                conn.close()
                
                if result and result[0]:
                    return result[0]
            
            # If not found, try downloading
            logger.info(f"Exploit {exploit_id} not found locally, attempting to download")
            result = ExploitDBAdapter.download_and_store_exploit(exploit_id)
            
            if result:
                with open(result, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting exploit code content for ID {exploit_id}: {e}")
            return None
``` 