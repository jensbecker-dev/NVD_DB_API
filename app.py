import os
import logging
import sqlalchemy as sa
# Update declarative_base import for SQLAlchemy 2.0 compatibility
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import func, extract, case
from flask import Flask, render_template, request, jsonify, redirect, url_for, json
from modules.nvdapi import NVDApi, fetch_all_nvd_data, determine_severity
from datetime import datetime
import threading
import calendar
from werkzeug.routing.exceptions import BuildError
from functools import lru_cache
import hashlib
import requests

# Note: The 'RequestsDependencyWarning' suggests installing 'chardet' or 'charset_normalizer'
# for optimal character encoding detection by the requests library (likely used in nvdapi.py).
# Example: pip install chardet

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

Base = declarative_base()

# Define route constants - update to include all routes
class Routes:
    INDEX = 'index'
    SEARCH = 'search'
    VIEW_ALL = 'view_all'
    CVE_DETAILS = 'cve_details'
    VENDOR_ANALYSIS = 'vendor_analysis'
    SEVERITY_DISTRIBUTION = 'severity_distribution'
    MONTHLY_SUMMARY = 'monthly_summary'
    TOP_VENDORS = 'top_vendors'
    UPDATE_DATABASE = 'update_database'
    UPDATE_STATUS = 'check_update_status'
    # ... other routes ...

# Create Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'NVD_CVE_Secret_Key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cve_database.db'

# Am Anfang der Datei, nach der app-Initialisierung:
app.config['TEMPLATES_AUTO_RELOAD'] = True

@app.after_request
def add_header(response):
    """
    Sorge dafür, dass die Antworten nicht gecached werden während der Entwicklung
    """
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

# Define the static folder explicitly to ensure CSS files are served correctly
app.static_folder = 'static'

# Add the current year to all templates
@app.context_processor
def inject_now():
    return {'now': datetime.now}

# Add CVSS color helper function
@app.context_processor
def utility_functions():
    def get_cvss_color(score):
        if score is None:
            return '#6c757d'  # Default gray for unknown
        score = float(score)
        if score >= 9.0:
            return '#ea4335'  # Critical (red)
        elif score >= 7.0:
            return '#ff6d41'  # High (orange)
        elif score >= 4.0:
            return '#fbbc04'  # Medium (yellow)
        else:
            return '#34a853'  # Low (green)
    
    def get_cvss_bar_color(score):
        return get_cvss_color(score)  # Same function, different name for clarity
        
    return dict(
        get_cvss_color=get_cvss_color,
        get_cvss_bar_color=get_cvss_bar_color
    )

# Database setup
def create_local_cve_db():
    """
    Create a SQLite database connection for storing CVE data.
    """
    try:
        db_path = os.path.join(os.path.dirname(__file__), 'cve_database.db')
        engine = sa.create_engine(f'sqlite:///{db_path}', echo=False)
        logging.info(f"Created database at {db_path}")
        return engine
    except Exception as e:
        logging.error(f"Error creating database: {e}")
        return None

# Ensure sessions are properly closed
def get_session(engine):
    """
    Create a new SQLAlchemy session.
    """
    Session = sessionmaker(bind=engine)
    return Session()

def create_cve_table(engine):
    """Create the CVE table in the database with optimized indexes."""
    try:
        class CVE(Base):
            __tablename__ = 'cves'
            
            # Add extend_existing=True to handle multiple definitions
            __table_args__ = {
                'extend_existing': True,
                # Add composite indexes for common queries
                'sqlite_autoincrement': True, 
                'mysql_engine': 'InnoDB',
                'mysql_charset': 'utf8mb4'
            }
            
            id = sa.Column(sa.Integer, primary_key=True)
            cve_id = sa.Column(sa.String(20), unique=True, index=True)
            published_date = sa.Column(sa.DateTime, index=True)  # Add index
            last_modified_date = sa.Column(sa.DateTime)
            description = sa.Column(sa.Text)
            cvss_v3_score = sa.Column(sa.Float, nullable=True)
            cvss_v2_score = sa.Column(sa.Float, nullable=True)
            severity = sa.Column(sa.String(20), nullable=True, index=True)  # Add index
            cpe_affected = sa.Column(sa.Text)
            cwe_id = sa.Column(sa.String(50), nullable=True, index=True)  # Add index
            references = sa.Column(sa.Text)
            
        Base.metadata.create_all(engine)
        logging.info("CVE table created successfully")
        return CVE
    except Exception as e:
        logging.error(f"Error creating CVE table: {e}")
        return None

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
        
    # Try different formats because NVD data might have variations
    formats_to_try = [
        '%Y-%m-%dT%H:%M:%SZ',  # Format with seconds
        '%Y-%m-%dT%H:%MZ',     # Format without seconds
        '%Y-%m-%dT%H:%M:%S',   # Format without Z
        '%Y-%m-%dT%H:%M'       # Format without Z or seconds
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
    logging.warning(f"Could not parse date string: {date_string}")
    return None

def import_cve_data_to_db(cve_list, engine, CVE):
    """
    Import CVE data into the database.
    
    Args:
        cve_list: List of CVE data dicts from NVD
        engine: SQLAlchemy engine object
        CVE: CVE class for table operations
    """
    try:
        Session = sessionmaker(bind=engine)
        session = Session()
        
        # Count of new CVEs added to the database
        new_cve_count = 0
        
        for cve_item in cve_list:
            cve_id = cve_item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
            
            if not cve_id:
                continue
                
            # Check if CVE already exists in database
            existing_cve = session.query(CVE).filter_by(cve_id=cve_id).first()
            if existing_cve:
                continue
                
            # Extract basic CVE information
            published_date = parse_nvd_datetime(cve_item.get('publishedDate'))
            last_modified_date = parse_nvd_datetime(cve_item.get('lastModifiedDate'))
            
            # Extract description (use English if available)
            descriptions = cve_item.get('cve', {}).get('description', {}).get('description_data', [])
            description = next((item.get('value') for item in descriptions if item.get('lang') == 'en'), '')
            
            # Extract CVSS scores if available
            impact = cve_item.get('impact', {})
            cvss_v3 = impact.get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore')
            cvss_v2 = impact.get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore')
            
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
            nodes = cve_item.get('configurations', {}).get('nodes', [])
            for node in nodes:
                for cpe_match in node.get('cpe_match', []):
                    cpe_affected.append(cpe_match.get('cpe23Uri', ''))
            
            # Extract CWE IDs if available
            problem_type_data = cve_item.get('cve', {}).get('problemtype', {}).get('problemtype_data', [])
            cwe_ids = []
            for pt in problem_type_data:
                for desc in pt.get('description', []):
                    if desc.get('value', '').startswith('CWE-'):
                        cwe_ids.append(desc.get('value'))
            cwe_id = ', '.join(cwe_ids)
            
            # Extract references
            reference_data = cve_item.get('cve', {}).get('references', {}).get('reference_data', [])
            references = [ref.get('url') for ref in reference_data]
            
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
            
            # Commit in batches to prevent memory issues
            if new_cve_count % 1000 == 0:
                session.commit()
                logging.info(f"Committed {new_cve_count} records so far")
            
        session.commit()
        logging.info(f"Imported {new_cve_count} new CVEs to the database")
        return new_cve_count
    except Exception as e:
        session.rollback()
        logging.error(f"Error importing CVE data to database: {e}")
        return 0

# Add caching for expensive operations
@lru_cache(maxsize=32)
def get_severity_distribution(cache_key=None):
    """Cached function to get severity distribution statistics"""
    engine = create_local_cve_db()
    session = get_session(engine)
    
    try:
        severity_query = session.query(
            CVE_Model.severity, func.count(CVE_Model.id).label('count')
        ).group_by(CVE_Model.severity).all()
        
        severity_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for severity, count in severity_query:
            s_upper = (severity or 'UNKNOWN').upper()
            if s_upper in severity_map:
                severity_map[s_upper] = count
                
        return severity_map, sum(severity_map.values())
    finally:
        session.close()

# Global variable to track database update status
db_update_status = {
    'is_updating': False,
    'progress': 0,
    'total_years': 0,
    'current_year': None,
    'error': None,
    'cves_added': 0
}

def update_database_task():
    """Background task for updating the database"""
    global db_update_status
    global CVE_Model
    
    try:
        db_update_status['is_updating'] = True
        db_update_status['error'] = None
        db_update_status['progress'] = 0
        
        # Fetch all CVE data
        logging.info("Starting comprehensive CVE database update...")
        all_cve_items = fetch_all_nvd_data()
        
        if not all_cve_items:
            db_update_status['error'] = "Failed to fetch CVE data"
            db_update_status['is_updating'] = False
            return
        
        # Create/update database
        engine = create_local_cve_db()
        CVE_Model = create_cve_table(engine)
        
        # Import data
        cves_added = import_cve_data_to_db(all_cve_items, engine, CVE_Model)
        db_update_status['cves_added'] = cves_added
        
        db_update_status['progress'] = 100
        logging.info(f"Database update completed. Added {cves_added} new CVEs.")
    except Exception as e:
        db_update_status['error'] = str(e)
        logging.error(f"Error in database update task: {e}")
    finally:
        db_update_status['is_updating'] = False

# Create a global reference to our CVE class
CVE_Model = None

# Flask routes
@app.route('/')
@app.route('/index')
def index():
    """Home page showing overview and search form"""
    # Get cached severity counts
    severity_counts, total_cve_count = get_severity_distribution()
    # Force logo update on home page by adding a timestamp to prevent caching issues
    logo_timestamp = int(datetime.now().timestamp())
    results = []
    search_term = request.args.get('search_term', '')
    search_performed = request.args.get('search_performed', 'false').lower() == 'true'
    exploitable_only = request.args.get('exploitable', 'false').lower() == 'true'
    severity_filter = request.args.get('severity', '')
    page = request.args.get('page', 1, type=int)
    per_page = 100
    
    # Lade Exploit-DB Statistiken
    exploitdb_stats = None
    try:
        # API-Endpunkt abfragen für die Exploit-Statistiken
        response = requests.get(f"http://localhost:{request.host.split(':')[1] if ':' in request.host else '8080'}/api/exploitdb/status")
        if response.status_code == 200:
            exploitdb_stats = response.json()
    except Exception as e:
        logging.warning(f"Fehler beim Laden der Exploit-DB Statistiken: {e}")

    try:
        engine = create_local_cve_db()
        session = get_session(engine)

        if CVE_Model is None:
            return render_template('index.html', error_message="Database model not initialized. Please update the database first.", results=[], search_term=search_term, search_performed=search_performed, severity_counts={}, total_cve_count=0, exploitdb_stats=exploitdb_stats)

        if request.method == 'POST':
            search_performed = True
            search_term = request.form.get('search_term', '').strip()
            exploitable_only = request.form.get('exploitable') == 'on'
            severity_filter = request.form.get('severity', '')

            return redirect(url_for(Routes.INDEX, search_term=search_term, exploitable=exploitable_only, severity=severity_filter, search_performed=True))

        if search_performed or search_term:
            query = session.query(CVE_Model)
            is_cve_pattern = search_term.upper().startswith('CVE-') and len(search_term.split('-')) == 3

            if is_cve_pattern:
                query = query.filter(CVE_Model.cve_id.ilike(search_term))
            else:
                keywords = search_term.split()
                for keyword in keywords:
                    query = query.filter(CVE_Model.description.ilike(f"%{keyword}%"))

            if severity_filter in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
                query = query.filter(CVE_Model.severity == severity_filter)

            if exploitable_only:
                query = query.filter(CVE_Model.references.ilike('%exploit%'))

            total_results = query.count()
            query = query.order_by(CVE_Model.published_date.desc())
            paginated_results = query.limit(per_page).offset((page - 1) * per_page).all()
            results = paginated_results
            total_pages = (total_results + per_page - 1) // per_page

            if not results and is_cve_pattern:
                nvd_api = NVDApi()
                cve_api_details = nvd_api.get_cve(search_term)
                if cve_api_details:
                    return render_template('cve_details.html', cve=cve_api_details, from_api=True)
        else:
            # Initialize these variables when no search is performed
            total_results = 0
            total_pages = 1

    except Exception as e:
        logging.error(f"Error during search or getting counts: {e}")
        return render_template('index.html', error_message=f"Operation failed: {e}", results=[], search_term=search_term, search_performed=search_performed, severity_counts={}, total_cve_count=0, exploitdb_stats=exploitdb_stats)
    finally:
        session.close()

    return render_template('index.html', results=results, search_term=search_term, search_performed=search_performed, severity=severity_filter, severity_counts=severity_counts, total_cve_count=total_cve_count, current_page=page, total_pages=total_pages, total_results=total_results, exploitable=exploitable_only, exploitdb_stats=exploitdb_stats)

@app.route('/search', methods=['GET', 'POST'])
def search():
    """
    Dedicated search endpoint that redirects to index with search parameters.
    This route exists to handle search references in templates.
    """
    if request.method == 'POST':
        search_term = request.form.get('search_term', '')
        severity = request.form.get('severity', '')
        exploitable = 'true' if request.form.get('exploitable') == 'on' else 'false'
    else:
        search_term = request.args.get('search_term', '')
        severity = request.args.get('severity', '')
        exploitable = request.args.get('exploitable', 'false')
    
    # Redirect to index with search parameters
    return redirect(url_for(Routes.INDEX, 
                           search_term=search_term, 
                           severity=severity,
                           exploitable=exploitable,
                           search_performed='true'))

@app.route('/view_all')
def view_all():  # Geändert von view_all_entries zu view_all
    """Display all CVEs in the database, with sorting options"""
    sort_by = request.args.get('sort', 'published_desc')
    page = request.args.get('page', 1, type=int)
    per_page = 100

    try:
        engine = create_local_cve_db()
        session = get_session(engine)

        if CVE_Model is None:
            return render_template('error.html', error="Database model not initialized. Please update the database first.")

        severity_query = session.query(
            CVE_Model.severity, func.count(CVE_Model.id)
        ).group_by(CVE_Model.severity).all()

        severity_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for severity, count in severity_query:
            s_upper = (severity or 'UNKNOWN').upper()
            severity_map[s_upper] = count
        severity_counts = severity_map
        total_cve_count = sum(severity_counts.values())

        query = session.query(CVE_Model)
        severity_order = sa.case(
            (CVE_Model.severity == 'CRITICAL', 5),
            (CVE_Model.severity == 'HIGH', 4),
            (CVE_Model.severity == 'MEDIUM', 3),
            (CVE_Model.severity == 'LOW', 2),
            else_=1
        )

        if sort_by == 'severity_asc':
            query = query.order_by(severity_order.asc(), CVE_Model.published_date.desc())
        elif sort_by == 'severity_desc':
            query = query.order_by(severity_order.desc(), CVE_Model.published_date.desc())
        elif sort_by == 'published_asc':
            query = query.order_by(CVE_Model.published_date.asc())
        else:
            query = query.order_by(CVE_Model.published_date.desc())

        total_results = query.count()
        paginated_results = query.limit(per_page).offset((page - 1) * per_page).all()
        total_pages = (total_results + per_page - 1) // per_page

        return render_template('index.html', results=paginated_results, search_term='All Database Entries', search_performed=True, sort_by=sort_by, is_view_all=True, severity_counts=severity_counts, total_cve_count=total_cve_count, current_page=page, total_pages=total_pages, total_results=total_results)

    except Exception as e:
        logging.error(f"Error fetching all entries: {e}")
        return render_template('error.html', error=str(e))
    finally:
        session.close()

@app.route('/cve/<cve_id>')
def cve_details(cve_id):
    """Show details for a specific CVE"""
    try:
        cve_data = None
        from_api = False
        exploits = []

        # Try database first
        if CVE_Model is not None:
            engine = create_local_cve_db()
            session = get_session(engine)
            cve_data = session.query(CVE_Model).filter(CVE_Model.cve_id.ilike(cve_id)).first()
            session.close()

        # If not in DB, try API
        if not cve_data:
            return redirect(url_for(Routes.CVE_DETAILS, cve_id=cve_id))

        # Exploits für diese CVE abrufen
        if cve_data:
            try:
                from modules.additional_sources import ExploitDBAdapter
                exploits = ExploitDBAdapter.get_exploits_for_cve(cve_id)
                
                # Setzen Sie Exploit-Flags
                if exploits:
                    cve_data.has_exploit = True
                    cve_data.exploit_data = json.dumps(exploits)
            except Exception as e:
                logging.error(f"Error fetching exploits for {cve_id}: {e}")
                # Exploit-Fehler sollten nicht die gesamte Seite scheitern lassen
                pass

            return render_template('cve_details.html', cve=cve_data, from_api=from_api, exploits=exploits)
        else:
            return redirect(url_for(Routes.CVE_DETAILS, cve_id=cve_id))

    except Exception as e:
        logging.error(f"Error fetching CVE details for {cve_id}: {e}")
        return render_template('error.html', error=f"An error occurred while fetching details for {cve_id}.")

@app.route('/api/exploit-code/<exploit_id>')
def get_exploit_code(exploit_id):
    """API endpoint to get exploit code for a specific exploit ID"""
    try:
        from modules.additional_sources import ExploitDBAdapter
        
        # Versuche, den Exploit-Code abzurufen
        exploit_code = ExploitDBAdapter.get_exploit_code_content(exploit_id)
        
        if exploit_code:
            return exploit_code, 200, {'Content-Type': 'text/plain'}
        else:
            return f"Exploit code not found for ID: {exploit_id}", 404, {'Content-Type': 'text/plain'}
    
    except Exception as e:
        logging.error(f"Error fetching exploit code for ID {exploit_id}: {e}")
        return f"Error fetching exploit code: {str(e)}", 500, {'Content-Type': 'text/plain'}

@app.route('/api/cve/<cve_id>/exploits')
def get_cve_exploits(cve_id):
    """API endpoint to get exploits for a specific CVE ID"""
    try:
        from modules.additional_sources import ExploitDBAdapter
        
        # Hole alle Exploits für diese CVE
        exploits = ExploitDBAdapter.get_exploits_for_cve(cve_id)
        
        # Wenn als Parameter angegeben, füge auch den Code hinzu
        include_code = request.args.get('include_code') == 'true'
        if include_code:
            for exploit in exploits:
                exploit_id = exploit.get('exploit_id')
                if exploit_id:
                    code = ExploitDBAdapter.get_exploit_code_content(exploit_id)
                    if code:
                        exploit['code_content'] = code
        
        return jsonify({
            'status': 'success',
            'cve_id': cve_id,
            'count': len(exploits),
            'exploits': exploits
        })
    
    except Exception as e:
        logging.error(f"Error fetching exploits for CVE {cve_id}: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'cve_id': cve_id
        }), 500

@app.route('/update_exploitdb')
def update_exploitdb():
    """Update the exploit database with the latest entries from Exploit-DB"""
    try:
        from modules.additional_sources import ExploitDBAdapter
        
        # Initialisiere die Exploit-Datenbank, falls sie noch nicht existiert
        ExploitDBAdapter.init_exploit_db()
        
        # Importiere die Metadaten
        metadata_count = ExploitDBAdapter.import_all_exploit_metadata()
        
        # Starte den Download-Prozess im Hintergrund
        download_thread = threading.Thread(
            target=ExploitDBAdapter.download_all_exploits,
            kwargs={'limit': 1000, 'filter_cve_only': True}
        )
        download_thread.daemon = True
        download_thread.start()
        
        return render_template('update_status.html', 
                              status={
                                  'is_updating': True,
                                  'type': 'exploit_db',
                                  'message': f'Imported {metadata_count} exploit metadata entries. Downloading exploit code in the background.',
                                  'progress': 50
                              })
    
    except Exception as e:
        logging.error(f"Error updating exploit database: {e}")
        return render_template('error.html', 
                              error_message=f"Failed to update exploit database: {str(e)}")

@app.route('/api/exploitdb/status')
def get_exploitdb_status():
    """Get status information about the exploit database"""
    try:
        from modules.additional_sources import ExploitDBAdapter
        
        # Get counts of locally available exploits
        local_exploits = ExploitDBAdapter.get_locally_available_exploits()
        
        # Verbinde mit der Datenbank und hole Statistiken
        import sqlite3
        import os
        
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'exploit_cache.db')
        stats = {
            'total_exploits': 0,
            'with_cve': 0,
            'downloaded': 0,
            'recent_exploits': []
        }
        
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Gesamtzahl der Exploits
            cursor.execute("SELECT COUNT(*) FROM exploit_metadata")
            stats['total_exploits'] = cursor.fetchone()[0]
            
            # Anzahl der Exploits mit CVE-ID
            cursor.execute("SELECT COUNT(*) FROM exploit_metadata WHERE cve_id != ''")
            stats['with_cve'] = cursor.fetchone()[0]
            
            # Anzahl der heruntergeladenen Exploits
            cursor.execute("SELECT COUNT(*) FROM exploit_metadata WHERE download_status = 1")
            stats['downloaded'] = cursor.fetchone()[0]
            
            # Neueste Exploits (10 Einträge)
            cursor.execute("""
                SELECT id, description, date, cve_id FROM exploit_metadata 
                WHERE cve_id != '' 
                ORDER BY date DESC LIMIT 10
            """)
            stats['recent_exploits'] = [
                {
                    'id': row[0],
                    'description': row[1],
                    'date': row[2],
                    'cve_id': row[3]
                } for row in cursor.fetchall()
            ]
            
            conn.close()
            
        return jsonify({
            'status': 'success',
            'local_exploit_count': len(local_exploits),
            'stats': stats
        })
    
    except Exception as e:
        logging.error(f"Error getting exploit database status: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/verify_exploits')
def verify_exploits():
    """Verify the integrity of all downloaded exploits and repair if needed"""
    try:
        from modules.additional_sources import ExploitDBAdapter
        
        # Run verification with auto-repair
        verification_results = ExploitDBAdapter.verify_all_exploits(repair=True)
        
        return render_template('exploits_verification.html', 
                              results=verification_results,
                              status={
                                  'success': f"Verification complete: {verification_results['valid']} valid, {verification_results['invalid']} invalid, {verification_results['repaired']} repaired"
                              })
    
    except Exception as e:
        logging.error(f"Error verifying exploits: {e}")
        return render_template('error.html', 
                              error_message=f"Failed to verify exploits: {str(e)}")

@app.route('/vulnerability_category/<string:category_slug>')
def vulnerability_category(category_slug):
    """Display CVEs belonging to a specific vulnerability category."""
    page = request.args.get('page', 1, type=int)
    per_page = 50  # Adjust as needed
    results = []
    total_results = 0
    total_pages = 1
    category_name = category_slug.replace('-', ' ').title()  # Simple name generation
    severity_counts = {} # Initialize severity_counts
    total_cve_count = 0 # Initialize total_cve_count

    # --- TODO: Define mapping from category_slug to search criteria ---
    # This is a crucial part you need to implement based on your data.
    # Example mapping (adjust CWE IDs and keywords):
    category_criteria = {
        'sql-injection': {'cwe_ids': ['CWE-89']},
        'remote-code-execution': {'keywords': ['remote code execution', 'RCE']},
        'cross-site-scripting': {'cwe_ids': ['CWE-79']},
        'authentication-bypass': {'keywords': ['authentication bypass', 'auth bypass']},
        'denial-of-service': {'cwe_ids': ['CWE-400', 'CWE-770'], 'keywords': ['denial of service', 'DoS']},
        'information-disclosure': {'cwe_ids': ['CWE-200']},
        'buffer-overflow': {'cwe_ids': ['CWE-119', 'CWE-120', 'CWE-121', 'CWE-122']}
        # Add more categories as needed
    }

    criteria = category_criteria.get(category_slug)

    if not criteria:
        return render_template('error.html', error_message=f"Unknown vulnerability category: {category_name}"), 404

    try:
        engine = create_local_cve_db()
        session = get_session(engine)

        if CVE_Model is None:
            return render_template('error.html', error_message="Database model not initialized.")

        # --- Calculate overall severity counts (same as in index route) ---
        severity_query = session.query(
            CVE_Model.severity, func.count(CVE_Model.id)
        ).group_by(CVE_Model.severity).all()

        severity_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for severity, count in severity_query:
            s_upper = (severity or 'UNKNOWN').upper()
            if s_upper in severity_map:
                severity_map[s_upper] = count
        severity_counts = severity_map
        total_cve_count = sum(severity_counts.values())
        # --- End of severity counts calculation ---

        query = session.query(CVE_Model)

        # Apply filters based on criteria
        filters = []
        if 'cwe_ids' in criteria:
            cwe_filters = [CVE_Model.cwe_id.ilike(f"%{cwe}%") for cwe in criteria['cwe_ids']]
            if cwe_filters:
                filters.append(sa.or_(*cwe_filters))

        if 'keywords' in criteria:
            keyword_filters = [CVE_Model.description.ilike(f"%{kw}%") for kw in criteria['keywords']]
            if keyword_filters:
                filters.append(sa.or_(*keyword_filters))

        if filters:
            query = query.filter(sa.or_(*filters))  # Combine CWE and keyword searches with OR
        else:
            # If no specific criteria defined for slug, maybe return empty or error
            return render_template('error.html', error_message=f"No search criteria defined for category: {category_name}")

        total_results = query.count()
        query = query.order_by(CVE_Model.published_date.desc())
        paginated_results = query.limit(per_page).offset((page - 1) * per_page).all()
        results = paginated_results
        total_pages = (total_results + per_page - 1) // per_page

    except Exception as e:
        logging.error(f"Error fetching CVEs for category {category_slug}: {e}")
        return render_template('error.html', error_message=f"An error occurred while fetching data for {category_name}.")
    finally:
        if 'session' in locals() and session:
            session.close()

    # Reuse index.html or create a specific template like vulnerability_category.html
    return render_template('index.html',
                           results=results,
                           search_term=f"Category: {category_name}",  # Use category name as search term display
                           search_performed=True,  # Indicate that a filter is active
                           is_category_view=True,  # Flag for template logic if needed
                           category_slug=category_slug,  # Pass slug for potential use in template
                           current_page=page,
                           total_pages=total_pages,
                           total_results=total_results,
                           severity_counts=severity_counts, # Pass severity_counts
                           total_cve_count=total_cve_count) # Pass total_cve_count

@app.route('/monthly_summary')
def monthly_summary():
    """Displays a summary of CVEs published per month, including severity breakdown."""
    summary_data = {}
    all_years_in_data = []
    month_names_list = list(calendar.month_name)[1:]  # ["January", ..., "December"]
    
    try:
        engine = create_local_cve_db()
        session = get_session(engine)

        if CVE_Model is None:
            return render_template('error.html', error_message="Database model not initialized.")

        # Query to get counts and severity breakdown grouped by year and month
        monthly_severity_counts = session.query(
            extract('year', CVE_Model.published_date).label('year'),
            extract('month', CVE_Model.published_date).label('month'),
            CVE_Model.severity,
            func.count(CVE_Model.id).label('count')
        ).filter(CVE_Model.published_date.isnot(None)) \
         .group_by('year', 'month', CVE_Model.severity) \
         .order_by(sa.desc('year'), sa.desc('month')) \
         .all()

        # Process data into the nested dictionary format required by the template
        # { year: { month: { count: X, critical: Y, high: Z, medium: A, low: B, unknown: C } } }
        for year, month, severity, count in monthly_severity_counts:
            if year is not None and month is not None:  # Ensure valid data
                year = int(year)  # Convert to integer for proper dictionary indexing
                month = int(month)

                if year not in summary_data:
                    summary_data[year] = {}
                    # Initialize all months for the year to ensure they exist
                    for m in range(1, 13):
                        summary_data[year][m] = {'count': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0}

                if month not in summary_data[year]:
                    # This should not happen due to initialization above, but as a safeguard
                    summary_data[year][month] = {'count': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0}

                # Increment total count for the month
                summary_data[year][month]['count'] += count

                # Increment severity count
                severity_key = (severity or 'unknown').lower()
                if severity_key in summary_data[year][month]:
                    summary_data[year][month][severity_key] += count
                else:
                    # Handle unexpected severity values if necessary
                    summary_data[year][month]['unknown'] += count

        # Determine available years and selected year
        current_year = datetime.now().year
        all_years_in_data = sorted(summary_data.keys(), reverse=True)
        selected_year = request.args.get('year', type=int)  # Get year from query param

        # If no year requested or requested year not in data, default to the latest year with data
        if not all_years_in_data:
             all_years_in_data = [current_year]  # Default to current year if no data at all
             selected_year = current_year
        elif selected_year is None or selected_year not in all_years_in_data:
             selected_year = all_years_in_data[0]  # Default to the latest year found in data

        # Prepare data for Chart.js
        # Prepare monthly count chart data
        monthly_chart_data = {
            'labels': month_names_list,
            'datasets': [{
                'label': f'CVEs in {selected_year}',
                'data': [summary_data.get(selected_year, {}).get(month, {}).get('count', 0) for month in range(1, 13)],
                'backgroundColor': 'rgba(54, 162, 235, 0.5)',
                'borderColor': 'rgba(54, 162, 235, 1)',
                'borderWidth': 1
            }]
        }

        # Prepare severity breakdown chart data
        severity_datasets = []
        for severity, color in [
            ('critical', 'rgba(220, 53, 69, 0.7)'),   # Red
            ('high', 'rgba(253, 126, 20, 0.7)'),      # Orange
            ('medium', 'rgba(255, 193, 7, 0.7)'),     # Yellow
            ('low', 'rgba(25, 135, 84, 0.7)'),        # Green
            ('unknown', 'rgba(108, 117, 125, 0.7)')   # Gray
        ]:
            severity_datasets.append({
                'label': severity.title(),
                'data': [summary_data.get(selected_year, {}).get(month, {}).get(severity, 0) for month in range(1, 13)],
                'backgroundColor': color
            })

        severity_chart_data = {
            'labels': month_names_list,
            'datasets': severity_datasets
        }

        logging.info(f"Monthly summary data: Found data for {len(all_years_in_data)} years")
        if selected_year in summary_data:
            year_total = sum(summary_data[selected_year][m]['count'] for m in range(1, 13))
            logging.info(f"Selected year {selected_year}: {year_total} CVEs")

        # Pass the structured data to the template
        return render_template(
            'monthly_summary.html',
            summary_data=summary_data,         # Nested dict: {year: {month: {count: X, critical: Y, ...}}}
            years=all_years_in_data,           # List of years with data
            selected_year=selected_year,       # The year to display initially
            month_names=month_names_list,      # List of full month names
            monthly_chart_json=json.dumps(monthly_chart_data),
            severity_chart_json=json.dumps(severity_chart_data)
        )

    except Exception as e:
        logging.error(f"Error fetching monthly summary: {e}")
        import traceback
        logging.error(traceback.format_exc())
        return render_template('error.html', error_message=f"An error occurred while generating the monthly summary: {str(e)}")
    finally:
        if 'session' in locals() and session:
            session.close()

@app.route('/severity_distribution')
def severity_distribution():
    """Displays the distribution of CVEs by severity level, trends, and CVSS scores."""
    severity_counts = {}
    severity_percents = {}
    years_for_template = []
    critical_series = []
    high_series = []
    medium_series = []
    low_series = []
    unknown_series = []
    cvss_ranges = [0] * 10  # Initialize list for 10 ranges (0-1, 1-2, ..., 9-10)
    total_cve_count = 0  # Initialize to avoid reference before assignment

    try:
        engine = create_local_cve_db()
        session = get_session(engine)

        if CVE_Model is None:
            return render_template('error.html', error_message="Database model not initialized.")

        # Prüfen, ob überhaupt Daten in der Datenbank sind
        count_check = session.query(func.count(CVE_Model.id)).scalar()
        if count_check == 0:
            logging.warning("No CVE data found in database for severity distribution")
            # Dummy data for template
            dummy_data = {
                'labels': [],
                'datasets': []
            }
            return render_template('severity_distribution.html',
                              total_cves=0,
                              severity_counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
                              severity_percents={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
                              years=[],
                              critical_series=[],
                              high_series=[],
                              medium_series=[],
                              low_series=[],
                              unknown_series=[],
                              cvss_ranges=[0]*10,
                              years_json=json.dumps([]),
                              severity_trend_data=json.dumps(dummy_data),
                              cvss_chart_data=json.dumps(dummy_data),
                              no_data=True)

        # 1. Overall Severity Counts and Percentages
        severity_query = session.query(
            CVE_Model.severity, func.count(CVE_Model.id).label('count')
        ).group_by(CVE_Model.severity).all()

        severity_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for severity, count in severity_query:
            s_upper = (severity or 'UNKNOWN').upper()
            if s_upper in severity_map:
                severity_map[s_upper] = count
        severity_counts = severity_map
        total_cve_count = sum(severity_counts.values())

        if total_cve_count > 0:
            for severity, count in severity_counts.items():
                severity_percents[severity] = round((count / total_cve_count) * 100, 1)  # Use 1 decimal place
        else:
            for severity in severity_counts:
                severity_percents[severity] = 0.0

        # 2. Severity Trends Over Time
        yearly_severity_query = session.query(
            extract('year', CVE_Model.published_date).label('year'),
            CVE_Model.severity,
            func.count(CVE_Model.id).label('count')
        ).filter(CVE_Model.published_date.isnot(None)) \
            .group_by('year', CVE_Model.severity) \
            .order_by('year') \
            .all()

        yearly_data = {}  # {year: {severity: count}}
        all_years = set()
        for year, severity, count in yearly_severity_query:
            if year:  # Ensure year is not None
                all_years.add(int(year))
                if year not in yearly_data:
                    yearly_data[year] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
                s_upper = (severity or 'UNKNOWN').upper()
                if s_upper in yearly_data[year]:
                    yearly_data[year][s_upper] += count

        if all_years:
            years_for_template = sorted(list(all_years))
            # Ensure all years have entries for all severities
            for year in years_for_template:
                year_data = yearly_data.get(year, {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0})
                critical_series.append(year_data.get("CRITICAL", 0))
                high_series.append(year_data.get("HIGH", 0))
                medium_series.append(year_data.get("MEDIUM", 0))
                low_series.append(year_data.get("LOW", 0))
                unknown_series.append(year_data.get("UNKNOWN", 0))

        # 3. CVSS Score Distribution (Prioritize v3, fallback to v2)
        # Define score ranges (0-1, 1-2, ..., 9-10)
        score_case = case(
            (CVE_Model.cvss_v3_score.isnot(None), CVE_Model.cvss_v3_score),
            else_=CVE_Model.cvss_v2_score
        ).label('score')

        cvss_query = session.query(
            func.floor(score_case).label('score_floor'),  # Use floor to group into integer bins 0, 1, ..., 9
            func.count(CVE_Model.id).label('count')
        ).filter(score_case.isnot(None)) \
            .group_by('score_floor') \
            .all()

        for score_floor, count in cvss_query:
            if score_floor is not None:
                index = int(score_floor)
                if 0 <= index < 10:  # Ensure index is within bounds (0-9)
                    cvss_ranges[index] = count
                elif index == 10:  # Handle score 10.0, place it in the last bin (9-10)
                    cvss_ranges[9] += count

        # Logging für Debug-Zwecke
        logging.info(f"Severity distribution: total CVEs: {total_cve_count}")
        logging.info(f"Severity counts: {severity_counts}")
        logging.info(f"Years: {years_for_template}")
        
        # Bereite Chart.js Daten vor
        # Years for chart
        years_json = json.dumps(years_for_template)
        
        # Severity trends data
        severity_trend_data = json.dumps({
            'labels': years_for_template,
            'datasets': [
                {
                    'label': 'Critical',
                    'data': critical_series,
                    'backgroundColor': 'rgba(220, 53, 69, 0.6)',  # Red
                    'borderColor': 'rgba(220, 53, 69, 1)',
                    'borderWidth': 1
                },
                {
                    'label': 'High',
                    'data': high_series,
                    'backgroundColor': 'rgba(253, 126, 20, 0.6)',  # Orange
                    'borderColor': 'rgba(253, 126, 20, 1)',
                    'borderWidth': 1
                },
                {
                    'label': 'Medium',
                    'data': medium_series,
                    'backgroundColor': 'rgba(255, 193, 7, 0.6)',  # Yellow
                    'borderColor': 'rgba(255, 193, 7, 1)',
                    'borderWidth': 1
                },
                {
                    'label': 'Low',
                    'data': low_series,
                    'backgroundColor': 'rgba(25, 135, 84, 0.6)',  # Green
                    'borderColor': 'rgba(25, 135, 84, 1)',
                    'borderWidth': 1
                },
                {
                    'label': 'Unknown',
                    'data': unknown_series,
                    'backgroundColor': 'rgba(108, 117, 125, 0.6)',  # Gray
                    'borderColor': 'rgba(108, 117, 125, 1)',
                    'borderWidth': 1
                }
            ]
        })
        
        # CVSS distribution data
        cvss_labels = ['0-1', '1-2', '2-3', '3-4', '4-5', '5-6', '6-7', '7-8', '8-9', '9-10']
        cvss_chart_data = json.dumps({
            'labels': cvss_labels,
            'datasets': [{
                'label': 'CVSS Score Distribution',
                'data': cvss_ranges,
                'backgroundColor': 'rgba(54, 162, 235, 0.6)',  # Blue
                'borderColor': 'rgba(54, 162, 235, 1)',
                'borderWidth': 1
            }]
        })

        return render_template('severity_distribution.html',
                           total_cves=total_cve_count,
                           severity_counts=severity_counts,
                           severity_percents=severity_percents,
                           years=years_for_template,
                           critical_series=critical_series,
                           high_series=high_series,
                           medium_series=medium_series,
                           low_series=low_series,
                           unknown_series=unknown_series,
                           cvss_ranges=cvss_ranges,
                           years_json=years_json,
                           severity_trend_data=severity_trend_data,
                           cvss_chart_data=cvss_chart_data,
                           no_data=False)

    except Exception as e:
        logging.error(f"Error fetching severity distribution data: {e}")
        import traceback
        logging.error(traceback.format_exc())
        return render_template('error.html', error_message=f"An error occurred while generating the severity distribution: {str(e)}")
    finally:
        if 'session' in locals() and session:
            session.close()

@app.route('/update_database')
def update_database():
    """Update the local CVE database with latest data"""
    global db_update_status
    
    if db_update_status['is_updating']:
        return render_template('update_status.html', status=db_update_status)
    
    db_update_status = {
        'is_updating': True,
        'progress': 0,
        'total_years': datetime.now().year - 2002 + 2,
        'current_year': None,
        'error': None,
        'cves_added': 0
    }
    
    update_thread = threading.Thread(target=update_database_task)
    update_thread.daemon = True
    update_thread.start()
    
    return render_template('update_status.html', status=db_update_status)

@app.route('/update_status')
def check_update_status():
    """Check the status of the database update"""
    return jsonify(db_update_status)

@app.route('/api/cve/<cve_id>')
def api_cve_details(cve_id):
    """API endpoint to get CVE details in JSON format"""
    nvd_api = NVDApi()
    cve_details = nvd_api.get_cve(cve_id)
    if cve_details:
        return jsonify(cve_details)
    return jsonify({"error": f"CVE {cve_id} not found"}), 404

@app.route('/db_status')
def db_status():
    """Check database status and table records"""
    try:
        if CVE_Model is None:
            return jsonify({
                "status": "error",
                "message": "CVE_Model is not initialized"
            })
            
        engine = create_local_cve_db()
        session = get_session(engine)
        
        record_count = session.query(CVE_Model).count()
        sample = session.query(CVE_Model).first()
        session.close()
        
        sample_data = None
        if sample:
            sample_data = {
                "cve_id": sample.cve_id,
                "description": sample.description[:100] + "..." if sample.description else None,
                "published_date": str(sample.published_date) if sample.published_date else None
            }
        
        return jsonify({
            "status": "ok",
            "database_initialized": True,
            "record_count": record_count,
            "sample_record": sample_data
        })
    except Exception as e:
        logging.error(f"Error checking database status: {e}")
        return jsonify({
            "status": "error",
            "message": str(e)
        })

@app.route('/vendor_analysis')
def vendor_analysis():
    """
    Route to display an analysis of CVEs by vendor, including severity breakdown.
    """
    top_n = 30  # Number of top vendors to display
    vendor_details = {}

    try:
        engine = create_local_cve_db()
        session = get_session(engine)

        if CVE_Model is None:
            return render_template('error.html', error_message="Database model not initialized.")

        # Query necessary data: cpe_affected and severity for all relevant CVEs
        cve_data_query = session.query(CVE_Model.cpe_affected, CVE_Model.severity)\
                                .filter(CVE_Model.cpe_affected != '', CVE_Model.cpe_affected.isnot(None))\
                                .all()

        # Process data to aggregate vendor counts and severity distributions
        for cpe_string, severity in cve_data_query:
            if cpe_string:
                cpes = cpe_string.split(',')
                vendors_in_cve = set()
                for cpe in cpes:
                    parts = cpe.split(':')
                    # cpe:2.3:a:vendor:product:version:...
                    if len(parts) >= 4 and parts[0] == 'cpe' and parts[1] == '2.3':
                        vendor = parts[3].replace('_', ' ').title()
                        vendors_in_cve.add(vendor)

                processed_severity = (severity or 'UNKNOWN').upper()

                for vendor in vendors_in_cve:
                    if vendor not in vendor_details:
                        vendor_details[vendor] = {
                            'count': 0,
                            'severities': {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
                        }
                    vendor_details[vendor]['count'] += 1
                    if processed_severity in vendor_details[vendor]['severities']:
                        vendor_details[vendor]['severities'][processed_severity] += 1

        # Sort vendors by total CVE count
        sorted_vendors_list = sorted(vendor_details.items(), key=lambda item: item[1]['count'], reverse=True)

        # Get top N vendors
        top_vendors_list = sorted_vendors_list[:top_n]
        top_vendors_dict = dict(top_vendors_list)

        # Prepare data for Chart.js (Top N Vendors by Count)
        chart_labels = [v[0] for v in top_vendors_list]  # Vendor names
        chart_data = [v[1]['count'] for v in top_vendors_list]  # Total counts
        
        # Prepare severity breakdown data for stacked bar chart
        severity_datasets = []
        for severity, color in [
            ("CRITICAL", "rgba(220, 53, 69, 0.8)"),   # Red
            ("HIGH", "rgba(253, 126, 20, 0.8)"),      # Orange  
            ("MEDIUM", "rgba(255, 193, 7, 0.8)"),     # Yellow
            ("LOW", "rgba(25, 135, 84, 0.8)"),        # Green
            ("UNKNOWN", "rgba(108, 117, 125, 0.8)")   # Gray
        ]:
            severity_datasets.append({
                'label': severity,
                'data': [v[1]['severities'][severity] for v in top_vendors_list],
                'backgroundColor': color,
            })
            
        chart_json = json.dumps({
            'labels': chart_labels,
            'datasets': [{
                'label': 'Total CVEs',
                'data': chart_data,
                'backgroundColor': 'rgba(54, 162, 235, 0.6)',  # Blue
                'borderColor': 'rgba(54, 162, 235, 1)',
                'borderWidth': 1
            }]
        })
        
        # Prepare severity breakdown data
        severity_chart_json = json.dumps({
            'labels': chart_labels,
            'datasets': severity_datasets
        })

        return render_template('vendor_analysis.html',
                              vendors=top_vendors_dict,  # Pass the dict of top vendors
                              chart_json=chart_json,
                              severity_chart_json=severity_chart_json,
                              top_n=top_n)
    except Exception as e:
        logging.error(f"Error in /vendor_analysis route: {e}")
        import traceback
        logging.error(traceback.format_exc())
        return render_template('error.html', error_message=f"An error occurred while loading vendor analysis data: {str(e)}"), 500
    finally:
        if 'session' in locals() and session:
            session.close()

# Add a temporary dummy route to test the BuildError
@app.route('/top_vendors_placeholder')
def top_vendors_placeholder():
    # This is a placeholder. Replace with actual logic or remove if not needed.
    # You might want to return a simple template or just text.
    return "Top Vendors Page (Placeholder)", 200

# Füge die top_vendors-Route mit Umleitung hinzu
@app.route('/top_vendors')
def top_vendors():
    """Redirect to vendor_analysis which shows top vendors."""
    return redirect(url_for(Routes.VENDOR_ANALYSIS))

@app.route('/static/logo.png')
def serve_logo():
    """
    Spezielle Route, um das Logo zu liefern.
    Dadurch wird der 404-Fehler bei der Anfrage nach /static/logo.png vermieden.
    """
    return redirect(url_for('static', filename='img/logo.png', v=int(datetime.now().timestamp())))

@app.errorhandler(BuildError)
def handle_build_error(error):
    """Handle URL build errors by redirecting to home page."""
    logging.error(f"Build Error occurred: {error}")
    return redirect(url_for(Routes.INDEX))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_message="Page not found. The requested URL does not exist."), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error_message="Internal server error. Please try again later."), 500

# Run the application
if __name__ == '__main__':
    with app.app_context():
        engine = create_local_cve_db()
        if engine is not None:
            CVE_Model = create_cve_table(engine)

    app.run(debug=True, host='0.0.0.0', port=8080)
