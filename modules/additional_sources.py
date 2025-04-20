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
                # Verify the existing file for integrity
                is_valid, message = ExploitDBAdapter.verify_exploit_integrity(exploit_id)
                if is_valid:
                    logger.info(f"Exploit code for ID {exploit_id} already exists and is valid at {exploit_file_path}")
                    return exploit_file_path
                else:
                    logger.warning(f"Existing exploit file for ID {exploit_id} is invalid: {message}. Re-downloading...")
                    os.remove(exploit_file_path)
                
            url = f"{EXPLOIT_DB_RAW_URL}{exploit_id}"
            logger.info(f"Downloading exploit code from {url}")
            
            # Add headers to mimic a browser request
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Cache-Control': 'max-age=0'
            }
            
            # Use session to handle redirects and cookies properly
            session = requests.Session()
            response = session.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            # Verify the content before saving
            is_valid, message = ExploitDBAdapter.verify_exploit_integrity(exploit_id, response.text)
            if not is_valid:
                logger.error(f"Downloaded exploit content for ID {exploit_id} failed verification: {message}")
                return None
            
            # Save the exploit code to a file
            with open(exploit_file_path, 'w', encoding='utf-8', errors='ignore') as exploit_file:
                exploit_file.write(response.text)
            
            # Calculate and store checksum
            checksum = ExploitDBAdapter.calculate_exploit_checksum(response.text)
            
            # Also update the SQLite database
            ExploitDBAdapter.update_exploit_db(exploit_id, response.text, checksum=checksum)
            
            logger.info(f"Stored and verified exploit code for ID {exploit_id} at {exploit_file_path}")
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
            dict: Mapping of exploit IDs to their stored file paths with status information
        """
        exploit_file_map = {}
        exploit_ids_to_download = []
        download_results = {
            "total": len(exploit_ids),
            "already_downloaded": 0,
            "successful_downloads": 0,
            "failed_downloads": 0,
            "verified": 0,
            "invalid": 0
        }
        
        # First check which exploits are already downloaded and valid
        for exploit_id in exploit_ids:
            exploit_file_path = os.path.join(DEFAULT_EXPLOIT_FILES_DIR, f"{exploit_id}.txt")
            if os.path.exists(exploit_file_path):
                # Verify integrity first
                is_valid, message = ExploitDBAdapter.verify_exploit_integrity(exploit_id)
                if is_valid:
                    exploit_file_map[exploit_id] = {
                        "path": exploit_file_path, 
                        "status": "already_valid",
                        "message": "Already downloaded and verified"
                    }
                    download_results["already_downloaded"] += 1
                    download_results["verified"] += 1
                else:
                    # Invalid exploit, add to download list
                    logger.warning(f"Existing exploit {exploit_id} failed verification: {message}")
                    # Remove invalid file
                    try:
                        os.remove(exploit_file_path)
                    except:
                        pass
                    exploit_ids_to_download.append(exploit_id)
            else:
                exploit_ids_to_download.append(exploit_id)
        
        logger.info(f"Found {download_results['already_downloaded']} exploits already downloaded and valid, will download {len(exploit_ids_to_download)} more")
        
        # Download exploits in parallel
        if exploit_ids_to_download:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Define a worker function that returns status information
                def download_worker(exploit_id):
                    try:
                        result = ExploitDBAdapter.download_and_store_exploit(exploit_id)
                        if result:
                            # Verify again to be sure
                            is_valid, message = ExploitDBAdapter.verify_exploit_integrity(exploit_id)
                            if is_valid:
                                return exploit_id, {
                                    "path": result,
                                    "status": "downloaded_valid",
                                    "message": "Successfully downloaded and verified"
                                }
                            else:
                                # Invalid after download, rare but possible
                                logger.warning(f"Downloaded exploit {exploit_id} failed verification: {message}")
                                try:
                                    os.remove(result)
                                except:
                                    pass
                                return exploit_id, {
                                    "path": None,
                                    "status": "downloaded_invalid",
                                    "message": f"Download failed verification: {message}"
                                }
                        else:
                            return exploit_id, {
                                "path": None,
                                "status": "download_failed",
                                "message": "Failed to download"
                            }
                    except Exception as e:
                        logger.error(f"Error in download worker for exploit {exploit_id}: {e}")
                        return exploit_id, {
                            "path": None,
                            "status": "error",
                            "message": str(e)
                        }
                
                # Submit all download tasks
                future_to_exploit_id = {executor.submit(download_worker, exploit_id): exploit_id 
                                      for exploit_id in exploit_ids_to_download}
                
                # Process the results
                for future in as_completed(future_to_exploit_id):
                    try:
                        exploit_id, result = future.result()
                        exploit_file_map[exploit_id] = result
                        
                        if result["status"] == "downloaded_valid":
                            download_results["successful_downloads"] += 1
                            download_results["verified"] += 1
                        elif result["status"] == "downloaded_invalid":
                            download_results["failed_downloads"] += 1
                            download_results["invalid"] += 1
                        else:
                            download_results["failed_downloads"] += 1
                    except Exception as e:
                        exploit_id = future_to_exploit_id[future]
                        logger.error(f"Error processing result for exploit {exploit_id}: {e}")
                        exploit_file_map[exploit_id] = {
                            "path": None,
                            "status": "error",
                            "message": str(e)
                        }
                        download_results["failed_downloads"] += 1
        
        logger.info(f"Bulk download completed: {download_results['already_downloaded']} already downloaded, " +
                  f"{download_results['successful_downloads']} successfully downloaded, " +
                  f"{download_results['failed_downloads']} failed, " +
                  f"{download_results['verified']}/{download_results['total']} exploits verified")
        
        # Add download results to the return value
        exploit_file_map["_summary"] = download_results
        
        return exploit_file_map

    @staticmethod
    def download_all_exploits(limit=None, filter_cve_only=True):
        """
        Download all exploit code from Exploit-DB.
        
        Args:
            limit: Optional limit on number of exploits to download
            filter_cve_only: Whether to only download exploits with CVE IDs
            
        Returns:
            dict: Stats of the download process including verification results
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
                return {
                    "total_metadata": metadata_count,
                    "downloaded": 0,
                    "already_downloaded": 0,
                    "failed": 0,
                    "verified": 0,
                    "invalid": 0
                }
            
            logger.info(f"Downloading {len(exploit_ids)} exploits from Exploit-DB")
            
            # Download exploits in bulk with verification
            results = ExploitDBAdapter.download_and_store_exploits_bulk(exploit_ids)
            summary = results.get("_summary", {})
            
            # Run verification on all downloads
            logger.info("Running verification on all downloaded exploits...")
            verification_stats = ExploitDBAdapter.verify_all_exploits(repair=True)
            
            # Combine statistics
            stats = {
                "total_metadata": metadata_count,
                "total_to_download": len(exploit_ids),
                "downloaded": summary.get("successful_downloads", 0),
                "already_downloaded": summary.get("already_downloaded", 0),
                "failed": summary.get("failed_downloads", 0),
                "verified": verification_stats.get("valid", 0),
                "invalid": verification_stats.get("invalid", 0),
                "repaired": verification_stats.get("repaired", 0),
                "removed": verification_stats.get("removed", 0)
            }
            
            logger.info(f"Exploit download complete: {stats['downloaded']} new, {stats['already_downloaded']} existing, {stats['failed']} failed, {stats['verified']} verified")
            return stats
            
        except Exception as e:
            logger.error(f"Error downloading all exploits: {e}")
            return {
                "total_metadata": 0,
                "downloaded": 0,
                "already_downloaded": 0,
                "failed": 0,
                "verified": 0,
                "invalid": 0,
                "error": str(e)
            }

    @staticmethod
    def update_exploit_db(exploit_id, code, metadata=None, checksum=None):
        """
        Update the exploit database with code and metadata.
        
        Args:
            exploit_id: The Exploit-DB ID
            code: The exploit code
            metadata: Additional metadata about the exploit
            checksum: SHA-256 checksum of the code
            
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
            
            # Check if the checksum column exists
            cursor.execute("PRAGMA table_info(exploit_code)")
            columns = [column[1] for column in cursor.fetchall()]
            if "checksum" not in columns:
                cursor.execute("ALTER TABLE exploit_code ADD COLUMN checksum TEXT")
            
            # Calculate checksum if not provided
            if not checksum and code:
                checksum = ExploitDBAdapter.calculate_exploit_checksum(code)
                
            # Insert or update exploit code
            cursor.execute(
                "INSERT OR REPLACE INTO exploit_code (id, code, fetch_date, file_path, checksum) VALUES (?, ?, ?, ?, ?)",
                (exploit_id, code, datetime.now().isoformat(), file_path, checksum)
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
    def calculate_exploit_checksum(exploit_content):
        """
        Calculate a SHA-256 checksum for exploit content.
        
        Args:
            exploit_content: The exploit code content as string
            
        Returns:
            str: SHA-256 checksum as hexadecimal string
        """
        if not exploit_content:
            return None
        
        return hashlib.sha256(exploit_content.encode('utf-8', errors='ignore')).hexdigest()
    
    @staticmethod
    def verify_exploit_integrity(exploit_id, exploit_content=None):
        """
        Verify the integrity of a downloaded exploit by checking its content.
        
        Args:
            exploit_id: The Exploit-DB ID
            exploit_content: Optional exploit content (if None, will load from storage)
            
        Returns:
            tuple: (is_valid, message) indicating validity and any error message
        """
        try:
            if not exploit_content:
                # Load the exploit content from file or database
                exploit_file_path = os.path.join(DEFAULT_EXPLOIT_FILES_DIR, f"{exploit_id}.txt")
                if os.path.exists(exploit_file_path):
                    with open(exploit_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        exploit_content = f.read()
                else:
                    # Try from database
                    db_path = DEFAULT_EXPLOIT_DB_PATH
                    if os.path.exists(db_path):
                        conn = sqlite3.connect(db_path)
                        cursor = conn.cursor()
                        cursor.execute("SELECT code FROM exploit_code WHERE id = ?", (exploit_id,))
                        result = cursor.fetchone()
                        conn.close()
                        
                        if result and result[0]:
                            exploit_content = result[0]
                        else:
                            return False, f"Exploit {exploit_id} not found in local storage"
                    else:
                        return False, f"Exploit {exploit_id} not found in local storage"
            
            # Verify the exploit has minimal content
            if not exploit_content or len(exploit_content.strip()) < 20:
                return False, f"Exploit {exploit_id} is empty or too short"
            
            # Check for common error messages that would indicate a failed download
            error_indicators = [
                "404 not found",
                "not available",
                "no such exploit",
                "access denied",
                "could not find",
                "error occurred",
                "page not found"
            ]
            
            lower_content = exploit_content.lower()
            for indicator in error_indicators:
                if indicator in lower_content:
                    return False, f"Exploit {exploit_id} appears to contain an error message: '{indicator}'"
            
            # Check if it contains typical HTML tags which would indicate
            # we got a webpage instead of the actual exploit code
            html_indicators = ["<!doctype html>", "<html", "<head", "<body", "<script", "<div", "<span"]
            for indicator in html_indicators:
                if indicator in lower_content:
                    return False, f"Exploit {exploit_id} appears to contain HTML instead of code"
            
            # Calculate and store checksum for future verification
            checksum = ExploitDBAdapter.calculate_exploit_checksum(exploit_content)
            if checksum:
                # Store the checksum in the database
                db_path = DEFAULT_EXPLOIT_DB_PATH
                if os.path.exists(db_path):
                    conn = sqlite3.connect(db_path)
                    cursor = conn.cursor()
                    
                    # Add checksum column if it doesn't exist
                    cursor.execute("PRAGMA table_info(exploit_code)")
                    columns = [col[1] for col in cursor.fetchall()]
                    if "checksum" not in columns:
                        cursor.execute("ALTER TABLE exploit_code ADD COLUMN checksum TEXT")
                    
                    # Update the checksum
                    cursor.execute(
                        "UPDATE exploit_code SET checksum = ? WHERE id = ?",
                        (checksum, exploit_id)
                    )
                    conn.commit()
                    conn.close()
            
            return True, "Exploit appears valid"
            
        except Exception as e:
            logger.error(f"Error verifying exploit {exploit_id}: {e}")
            return False, f"Error during verification: {str(e)}"
    
    @staticmethod
    def verify_all_exploits(repair=True):
        """
        Verify all downloaded exploits and optionally repair or remove invalid ones.
        
        Args:
            repair: Whether to attempt to repair invalid exploits
            
        Returns:
            dict: Statistics about the verification process
        """
        try:
            stats = {
                "total": 0,
                "valid": 0,
                "invalid": 0,
                "repaired": 0,
                "removed": 0,
                "errors": []
            }
            
            # Get all locally available exploit IDs
            exploit_ids = ExploitDBAdapter.get_locally_available_exploits()
            stats["total"] = len(exploit_ids)
            
            logger.info(f"Verifying {len(exploit_ids)} locally stored exploits...")
            
            for exploit_id in exploit_ids:
                is_valid, message = ExploitDBAdapter.verify_exploit_integrity(exploit_id)
                
                if is_valid:
                    stats["valid"] += 1
                else:
                    stats["invalid"] += 1
                    logger.warning(f"Invalid exploit {exploit_id}: {message}")
                    stats["errors"].append({"id": exploit_id, "message": message})
                    
                    if repair:
                        # Try to repair by re-downloading
                        logger.info(f"Attempting to repair exploit {exploit_id} by re-downloading...")
                        
                        # Remove existing files
                        file_path = os.path.join(DEFAULT_EXPLOIT_FILES_DIR, f"{exploit_id}.txt")
                        if os.path.exists(file_path):
                            os.remove(file_path)
                        
                        # Re-download
                        result = ExploitDBAdapter.download_and_store_exploit(exploit_id)
                        if result:
                            # Verify again
                            is_valid_now, new_message = ExploitDBAdapter.verify_exploit_integrity(exploit_id)
                            if is_valid_now:
                                stats["repaired"] += 1
                                logger.info(f"Successfully repaired exploit {exploit_id}")
                            else:
                                # If still invalid, remove it
                                stats["removed"] += 1
                                logger.warning(f"Could not repair exploit {exploit_id}, removing: {new_message}")
                                
                                # Remove from database
                                db_path = DEFAULT_EXPLOIT_DB_PATH
                                if os.path.exists(db_path):
                                    conn = sqlite3.connect(db_path)
                                    cursor = conn.cursor()
                                    cursor.execute("DELETE FROM exploit_code WHERE id = ?", (exploit_id,))
                                    # Just reset download status in metadata
                                    cursor.execute("UPDATE exploit_metadata SET download_status = 0 WHERE id = ?", (exploit_id,))
                                    conn.commit()
                                    conn.close()
                                
                                # Remove file if it exists
                                if os.path.exists(file_path):
                                    os.remove(file_path)
                        else:
                            stats["removed"] += 1
                            logger.warning(f"Could not repair exploit {exploit_id}, removing")
                            
                            # Remove from database
                            db_path = DEFAULT_EXPLOIT_DB_PATH
                            if os.path.exists(db_path):
                                conn = sqlite3.connect(db_path)
                                cursor = conn.cursor()
                                cursor.execute("DELETE FROM exploit_code WHERE id = ?", (exploit_id,))
                                # Just reset download status in metadata
                                cursor.execute("UPDATE exploit_metadata SET download_status = 0 WHERE id = ?", (exploit_id,))
                                conn.commit()
                                conn.close()
            
            logger.info(f"Exploit verification complete: {stats['valid']} valid, {stats['invalid']} invalid, {stats['repaired']} repaired, {stats['removed']} removed")
            return stats
            
        except Exception as e:
            logger.error(f"Error during exploit verification: {e}")
            return {
                "total": 0,
                "valid": 0,
                "invalid": 0,
                "repaired": 0,
                "removed": 0,
                "errors": [{"id": "system", "message": str(e)}]
            }