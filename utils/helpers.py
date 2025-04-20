import logging
from sqlalchemy import func, case
from collections import defaultdict
import re

def generate_slug(name):
    """Generate a URL-friendly slug from a name."""
    name = name.lower()
    name = re.sub(r'[^a-z0-9\s-]', '', name)  # Remove invalid chars
    name = re.sub(r'[\s-]+', '-', name)  # Replace spaces/hyphens with single hyphen
    name = name.strip('-')  # Trim leading/trailing hyphens
    return name if name else 'unknown-vendor'

def extract_vendor_from_cpe(cpe_string):
    """Extracts the vendor part from a CPE 2.3 string."""
    # cpe:2.3:a:vendor:product:version:...
    parts = cpe_string.split(':')
    if len(parts) > 3 and parts[0] == 'cpe' and parts[1] == '2.3':
        return parts[3]
    return None

def get_vendor_data(session, CVE_Model):
    """
    Queries the database to get CVE counts and severity distribution per vendor.

    Args:
        session: SQLAlchemy session object.
        CVE_Model: The SQLAlchemy model class for CVEs.

    Returns:
        A list of dictionaries, each representing a vendor with its CVE counts.
        Example: [{'name': 'Microsoft', 'cve_count': 500, 'critical': 50, ... 'slug': 'microsoft'}, ...]
    """
    # Check if CVE_Model was passed correctly
    if CVE_Model is None:
        logging.error("CVE_Model was not provided to get_vendor_data. Cannot perform vendor analysis.")
        return []

    logging.info("Starting vendor data aggregation...")
    vendor_cve_details = defaultdict(lambda: {'cve_count': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0})

    try:
        # Query all CVEs that have CPE data using the passed CVE_Model
        cves_with_cpe = session.query(CVE_Model.cpe_affected, CVE_Model.severity).filter(CVE_Model.cpe_affected != '').all()

        # Handle case where no CVEs are found
        if not cves_with_cpe:
            logging.warning("No CVEs with CPE data found in the database.")
            return []

        logging.info(f"Processing {len(cves_with_cpe)} CVEs with CPE data for vendor analysis.")

        for cpe_list_str, severity in cves_with_cpe:
            if not cpe_list_str:
                continue

            cpes = cpe_list_str.split(',')
            current_cve_vendors = set()

            for cpe_uri in cpes:
                vendor = extract_vendor_from_cpe(cpe_uri)
                if vendor and vendor != '*':  # Ignore wildcard vendors
                    vendor_name = vendor.replace('_', ' ').title()  # Capitalize vendor name
                    current_cve_vendors.add(vendor_name)

            severity_upper = (severity or 'UNKNOWN').upper()

            for vendor_name in current_cve_vendors:
                details = vendor_cve_details[vendor_name]
                details['cve_count'] += 1

                if severity_upper == 'CRITICAL':
                    details['critical'] += 1
                elif severity_upper == 'HIGH':
                    details['high'] += 1
                elif severity_upper == 'MEDIUM':
                    details['medium'] += 1
                elif severity_upper == 'LOW':
                    details['low'] += 1
                else:
                    details['unknown'] += 1

        # Convert defaultdict to list of dicts and add slugs
        vendor_list = []
        for name, counts in vendor_cve_details.items():
            vendor_list.append({
                'name': name,
                'slug': generate_slug(name),
                **counts  # Unpack the counts dict
            })

        # Sort by total CVE count descending
        vendor_list.sort(key=lambda x: x['cve_count'], reverse=True)

        logging.info(f"Aggregated data for {len(vendor_list)} vendors.")
        return vendor_list

    except Exception as e:
        logging.error(f"Error in get_vendor_data: {e}", exc_info=True)
        return []

# You can add other helper functions here if needed
