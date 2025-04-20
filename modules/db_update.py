"""
Enhanced database update task for the CVE database.
Imports data from multiple sources, including historical data back to 1992.
"""

import threading
import time
import logging
from datetime import datetime
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker
from modules.nvdapi import fetch_all_nvd_data, determine_severity
from modules.additional_sources import fetch_all_additional_sources, fetch_historical_cve_data, enrich_cve_data

# Configure logging
logging.basicConfig(filename='db_manager.log', level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global variable to track database update status
db_update_status = {
    'is_updating': False,
    'progress': 0,
    'total_years': 0,
    'current_year': None,
    'current_source': None,
    'error': None,
    'cves_added': 0,
    'sources_processed': 0,
    'total_sources': 3  # NVD, Historical, Additional sources
}

def parse_nvd_datetime(date_string):
    """
    Parse NVD datetime format strings into Python datetime objects.
    
    Args:
        date_string: String date from NVD API (e.g. '2025-04-17T11:15Z')
        
    Returns:
        datetime object or None if parsing fails
    """
    if not date_string:
        return None
        
    # Try different formats because data from different sources might have variations
    formats_to_try = [
        '%Y-%m-%dT%H:%M:%SZ',       # Format with seconds and Z
        '%Y-%m-%dT%H:%MZ',          # Format without seconds but with Z
        '%Y-%m-%dT%H:%M:%S',        # Format with seconds without Z
        '%Y-%m-%dT%H:%M',           # Format without seconds or Z
        '%Y-%m-%dT%H:%M:%S.%fZ',    # Format with milliseconds and Z
        '%Y-%m-%d',                 # Simple date format
        '%Y-%m',                    # Year and month only
        '%Y'                        # Year only
    ]
    
    for date_format in formats_to_try:
        try:
            # Remove trailing Z if present and not in format
            if date_string.endswith('Z') and not date_format.endswith('Z'):
                clean_date = date_string[:-1]
            else:
                clean_date = date_string
                
            return datetime.strptime(clean_date, date_format)
        except ValueError:
            continue
            
    # If all parsing attempts fail, log and return None
    logger.warning(f"Could not parse date string: {date_string}")
    return None

def import_cve_data_to_db(cve_list, engine, CVE):
    """
    Import CVE data into the database, checking for duplicates.
    
    Args:
        cve_list: List of CVE data dicts from any source
        engine: SQLAlchemy engine object
        CVE: CVE class for table operations
        
    Returns:
        int: Count of new CVEs added to the database
    """
    try:
        Session = sessionmaker(bind=engine)
        session = Session()
        
        # Count of new CVEs added to the database
        new_cve_count = 0
        skipped_count = 0
        error_count = 0
        
        # Create a set of existing CVE IDs for efficient lookup
        existing_cve_ids = set()
        for cve_id_tuple in session.query(CVE.cve_id).all():
            existing_cve_ids.add(cve_id_tuple[0])
        
        logger.info(f"Found {len(existing_cve_ids)} existing CVE IDs in the database")
        
        for cve_item in cve_list:
            try:
                cve_id = cve_item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
                
                if not cve_id:
                    error_count += 1
                    continue
                
                # Check if CVE already exists in database using the set
                if cve_id in existing_cve_ids:
                    skipped_count += 1
                    continue
                
                # Try to enrich the CVE item with data from other sources
                enriched_cve_item = enrich_cve_data(cve_item)
                
                # Extract basic CVE information
                published_date = parse_nvd_datetime(enriched_cve_item.get('publishedDate'))
                last_modified_date = parse_nvd_datetime(enriched_cve_item.get('lastModifiedDate'))
                
                # Extract description (use English if available)
                descriptions = enriched_cve_item.get('cve', {}).get('description', {}).get('description_data', [])
                description = next((item.get('value') for item in descriptions if item.get('lang') == 'en'), '')
                
                # Extract CVSS scores if available
                impact = enriched_cve_item.get('impact', {})
                cvss_v3 = None
                cvss_v2 = None
                
                # Try to get CVSS v3 score
                if 'baseMetricV3' in impact and 'cvssV3' in impact['baseMetricV3']:
                    cvss_v3 = impact['baseMetricV3']['cvssV3'].get('baseScore')
                
                # Try to get CVSS v2 score
                if 'baseMetricV2' in impact and 'cvssV2' in impact['baseMetricV2']:
                    cvss_v2 = impact['baseMetricV2']['cvssV2'].get('baseScore')
                
                # Determine severity based on CVSS scores
                severity = None
                if cvss_v3 is not None:
                    severity = determine_severity(cvss_v3)
                elif cvss_v2 is not None:
                    severity = determine_severity(cvss_v2)
                else:
                    severity = "UNKNOWN"
                
                # Extract CPE affected configurations
                cpe_affected = []
                nodes = enriched_cve_item.get('configurations', {}).get('nodes', [])
                for node in nodes:
                    for cpe_match in node.get('cpe_match', []):
                        cpe_affected.append(cpe_match.get('cpe23Uri', ''))
                
                # Extract CWE IDs if available
                problem_type_data = enriched_cve_item.get('cve', {}).get('problemtype', {}).get('problemtype_data', [])
                cwe_ids = []
                for pt in problem_type_data:
                    for desc in pt.get('description', []):
                        if desc.get('value', '').startswith('CWE-'):
                            cwe_ids.append(desc.get('value'))
                cwe_id = ', '.join(cwe_ids)
                
                # Extract references
                reference_data = enriched_cve_item.get('cve', {}).get('references', {}).get('reference_data', [])
                references = [ref.get('url') for ref in reference_data if ref.get('url')]
                
                # Create new CVE record
                new_cve = CVE(
                    cve_id=cve_id,
                    published_date=published_date,
                    last_modified_date=last_modified_date,
                    description=description,
                    cvss_v3_score=cvss_v3,
                    cvss_v2_score=cvss_v2,
                    severity=severity,
                    cpe_affected=','.join(cpe_affected),
                    cwe_id=cwe_id,
                    references=','.join(references)
                )
                
                session.add(new_cve)
                new_cve_count += 1
                
                # Add to the set of existing IDs to avoid duplicates within this batch
                existing_cve_ids.add(cve_id)
                
                # Commit in batches to prevent memory issues
                if new_cve_count % 1000 == 0:
                    session.commit()
                    logger.info(f"Committed {new_cve_count} new records so far")
                
            except Exception as e:
                error_count += 1
                logger.error(f"Error processing CVE item: {e}")
                continue
            
        session.commit()
        logger.info(f"Import completed: {new_cve_count} CVEs added, {skipped_count} skipped (already exist), {error_count} errors")
        return new_cve_count
    except Exception as e:
        session.rollback()
        logger.error(f"Error in import_cve_data_to_db: {e}")
        return 0
    finally:
        session.close()

def comprehensive_database_update(engine, CVE_Model):
    """
    Perform a comprehensive update of the CVE database from all available sources.
    
    Args:
        engine: SQLAlchemy engine object
        CVE_Model: CVE class for table operations
        
    Returns:
        dict: Summary of update operation
    """
    global db_update_status
    
    total_cves_added = 0
    current_progress = 0
    update_summary = {
        'total_sources': db_update_status['total_sources'],
        'sources_completed': 0,
        'sources_details': {},
        'total_cves_added': 0,
        'errors': []
    }
    
    try:
        # 1. Standard NVD data (2002-present)
        db_update_status['current_source'] = "NVD API Feed"
        logger.info("Starting NVD Feed data import...")
        
        nvd_feed_cves = fetch_all_nvd_data()
        if nvd_feed_cves:
            nvd_cves_added = import_cve_data_to_db(nvd_feed_cves, engine, CVE_Model)
            total_cves_added += nvd_cves_added
            
            update_summary['sources_details']['nvd_feed'] = {
                'cves_processed': len(nvd_feed_cves),
                'cves_added': nvd_cves_added
            }
            
            logger.info(f"Added {nvd_cves_added} CVEs from NVD feed")
        else:
            error_msg = "Failed to fetch data from NVD feed"
            update_summary['errors'].append(error_msg)
            logger.error(error_msg)
        
        # Update progress
        current_progress = 33
        db_update_status['progress'] = current_progress
        db_update_status['sources_processed'] = 1
        update_summary['sources_completed'] = 1
        
        # 2. Historical data (1992-2002)
        db_update_status['current_source'] = "Historical Data (1992-2002)"
        logger.info("Starting historical CVE data import (1992-2002)...")
        
        historical_cves = fetch_historical_cve_data()
        if historical_cves:
            historical_cves_added = import_cve_data_to_db(historical_cves, engine, CVE_Model)
            total_cves_added += historical_cves_added
            
            update_summary['sources_details']['historical'] = {
                'cves_processed': len(historical_cves),
                'cves_added': historical_cves_added
            }
            
            logger.info(f"Added {historical_cves_added} historical CVEs (1992-2002)")
        else:
            error_msg = "Failed to fetch historical CVE data"
            update_summary['errors'].append(error_msg)
            logger.error(error_msg)
        
        # Update progress
        current_progress = 66
        db_update_status['progress'] = current_progress
        db_update_status['sources_processed'] = 2
        update_summary['sources_completed'] = 2
        
        # 3. Additional sources (CIRCL, etc.)
        db_update_status['current_source'] = "Additional CVE Sources"
        logger.info("Starting import from additional CVE sources...")
        
        additional_cves = fetch_all_additional_sources()
        if additional_cves:
            additional_cves_added = import_cve_data_to_db(additional_cves, engine, CVE_Model)
            total_cves_added += additional_cves_added
            
            update_summary['sources_details']['additional'] = {
                'cves_processed': len(additional_cves),
                'cves_added': additional_cves_added
            }
            
            logger.info(f"Added {additional_cves_added} CVEs from additional sources")
        else:
            error_msg = "Failed to fetch data from additional sources"
            update_summary['errors'].append(error_msg)
            logger.error(error_msg)
        
        # Update final progress
        db_update_status['progress'] = 100
        db_update_status['sources_processed'] = 3
        update_summary['sources_completed'] = 3
        update_summary['total_cves_added'] = total_cves_added
        
        logger.info(f"Comprehensive database update completed. Added a total of {total_cves_added} new CVEs.")
        return update_summary
        
    except Exception as e:
        error_msg = f"Error in comprehensive_database_update: {e}"
        update_summary['errors'].append(error_msg)
        logger.error(error_msg)
        return update_summary

def enhanced_update_database_task():
    """
    Enhanced background task for updating the database from multiple sources.
    This is a drop-in replacement for the original update_database_task function.
    """
    global db_update_status
    global CVE_Model
    
    try:
        db_update_status['is_updating'] = True
        db_update_status['error'] = None
        db_update_status['progress'] = 0
        db_update_status['cves_added'] = 0
        db_update_status['sources_processed'] = 0
        db_update_status['current_source'] = "Initializing"
        
        # Updated total years to include historical data
        db_update_status['total_years'] = datetime.now().year - 1992 + 1
        
        logger.info("Starting enhanced comprehensive CVE database update...")
        
        # Create/update database
        from app import create_local_cve_db, create_cve_table
        engine = create_local_cve_db()
        CVE_Model = create_cve_table(engine)
        
        # Run the comprehensive update
        update_summary = comprehensive_database_update(engine, CVE_Model)
        
        # Update status with results
        db_update_status['cves_added'] = update_summary['total_cves_added']
        
        if update_summary['errors']:
            db_update_status['error'] = "; ".join(update_summary['errors'])
            logger.warning(f"Database update completed with errors: {db_update_status['error']}")
        else:
            logger.info(f"Database update completed successfully. Added {db_update_status['cves_added']} new CVEs.")
        
    except Exception as e:
        db_update_status['error'] = str(e)
        logger.error(f"Error in enhanced_update_database_task: {e}")
    finally:
        db_update_status['is_updating'] = False
        db_update_status['current_source'] = None