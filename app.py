import os
import logging
import sqlalchemy as sa
# Update declarative_base import for SQLAlchemy 2.0 compatibility
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import func, extract
from flask import Flask, render_template, request, jsonify, redirect, url_for
from modules.nvdapi import NVDApi, fetch_nvd_data_feed, fetch_all_nvd_data, determine_severity
from datetime import datetime
import threading
from utils.helpers import get_vendor_data, generate_slug

# Note: The 'RequestsDependencyWarning' suggests installing 'chardet' or 'charset_normalizer'
# for optimal character encoding detection by the requests library (likely used in nvdapi.py).
# Example: pip install chardet

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

Base = declarative_base()

# Create Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'NVD_CVE_Secret_Key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cve_database.db'

# Define the static folder explicitly to ensure CSS files are served correctly
app.static_folder = 'static'

# Add the current year to all templates
@app.context_processor
def inject_now():
    return {'now': datetime.now}

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
    """
    Create the CVE table in the database.
    
    Args:
        engine: SQLAlchemy engine object
        
    Returns:
        CVE class for table operations
    """
    try:
        class CVE(Base):
            __tablename__ = 'cves'
            
            # Add extend_existing=True to handle multiple definitions
            __table_args__ = {'extend_existing': True}
            
            id = sa.Column(sa.Integer, primary_key=True)
            cve_id = sa.Column(sa.String(20), unique=True, index=True)
            published_date = sa.Column(sa.DateTime)
            last_modified_date = sa.Column(sa.DateTime)
            description = sa.Column(sa.Text)
            cvss_v3_score = sa.Column(sa.Float, nullable=True)
            cvss_v2_score = sa.Column(sa.Float, nullable=True)
            severity = sa.Column(sa.String(20), nullable=True)
            cpe_affected = sa.Column(sa.Text)
            cwe_id = sa.Column(sa.String(50), nullable=True)
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
@app.route('/', methods=['GET', 'POST'])
def index():
    """Home page showing overview and search form"""
    results = []
    search_term = request.args.get('search_term', '')
    search_performed = request.args.get('search_performed', 'false').lower() == 'true'
    exploitable_only = request.args.get('exploitable', 'false').lower() == 'true'
    severity_filter = request.args.get('severity', '')
    severity_counts = {}
    page = request.args.get('page', 1, type=int)
    per_page = 100

    try:
        engine = create_local_cve_db()
        session = get_session(engine)

        if CVE_Model is None:
            return render_template('index.html', error_message="Database model not initialized. Please update the database first.", results=[], search_term=search_term, search_performed=search_performed, severity_counts={}, total_cve_count=0)

        # Calculate severity counts
        severity_query = session.query(
            CVE_Model.severity, func.count(CVE_Model.id)
        ).group_by(CVE_Model.severity).all()

        severity_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for severity, count in severity_query:
            s_upper = (severity or 'UNKNOWN').upper()
            severity_map[s_upper] = count
        severity_counts = severity_map
        total_cve_count = sum(severity_counts.values())

        if request.method == 'POST':
            search_performed = True
            search_term = request.form.get('search_term', '').strip()
            exploitable_only = request.form.get('exploitable') == 'on'
            severity_filter = request.form.get('severity', '')

            return redirect(url_for('index', search_term=search_term, exploitable=exploitable_only, severity=severity_filter, search_performed=True))

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

    except Exception as e:
        logging.error(f"Error during search or getting counts: {e}")
        return render_template('index.html', error_message=f"Operation failed: {e}", results=[], search_term=search_term, search_performed=search_performed, severity_counts={}, total_cve_count=0)
    finally:
        session.close()

    return render_template('index.html', results=results, search_term=search_term, search_performed=search_performed, severity=severity_filter, severity_counts=severity_counts, total_cve_count=total_cve_count, current_page=page, total_pages=total_pages if 'total_pages' in locals() else 1, total_results=total_results if 'total_results' in locals() else 0, exploitable=exploitable_only)

@app.route('/view_all')
def view_all_entries():
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

        # Try database first
        if CVE_Model is not None:
            engine = create_local_cve_db()
            session = get_session(engine)
            cve_data = session.query(CVE_Model).filter(CVE_Model.cve_id.ilike(cve_id)).first()
            session.close()

        # If not in DB, try API
        if not cve_data:
            return redirect(url_for('api_cve_details', cve_id=cve_id))

        if cve_data:
            return render_template('cve_details.html', cve=cve_data, from_api=from_api)
        else:
            return redirect(url_for('api_cve_details', cve_id=cve_id))

    except Exception as e:
        logging.error(f"Error fetching CVE details for {cve_id}: {e}")
        return render_template('error.html', error=f"An error occurred while fetching details for {cve_id}.")

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
    """Display vendor analysis based on CVE data."""
    session = None # Initialize session to None
    try:
        if CVE_Model is None:
            return render_template('error.html', error="Database model not initialized. Please update the database first.")

        engine = create_local_cve_db()
        session = get_session(engine) # Assign session here

        # Fetch vendor data using helper function
        # IMPORTANT: The get_vendor_data function in utils/helpers.py MUST be updated
        # to accept two arguments: session and CVE_Model. This is the cause of the
        # "takes 1 positional argument but 2 were given" TypeError.
        vendor_list = get_vendor_data(session, CVE_Model)

        # Handle case where no vendor data is available
        if not vendor_list:
            # Note: Returning an error page here is the correct handling within this function
            # if get_vendor_data returns no data. The root cause for empty vendor_list
            # might be an empty database, missing CPE data, or an issue within the
            # get_vendor_data function itself (in utils/helpers.py).
            return render_template('error.html', error="No vendor data available. Please update the database or check helper function.")

        # Sanitize vendor data to ensure all keys exist
        sanitized_vendor_list = []
        for vendor in vendor_list:
            name = vendor.get('name', 'Unknown')
            slug = vendor.get('slug', generate_slug(name))
            sanitized_vendor = {
                'name': name,
                'slug': slug,
                'cve_count': vendor.get('cve_count', 0),
                'critical': vendor.get('critical', 0),
                'high': vendor.get('high', 0),
                'medium': vendor.get('medium', 0),
                'low': vendor.get('low', 0),
                'unknown': vendor.get('unknown', 0)
            }
            sanitized_vendor_list.append(sanitized_vendor)

        # Calculate total counts for each severity
        total_critical = sum(v['critical'] for v in sanitized_vendor_list)
        total_high = sum(v['high'] for v in sanitized_vendor_list)
        total_medium = sum(v['medium'] for v in sanitized_vendor_list)
        total_low = sum(v['low'] for v in sanitized_vendor_list)
        total_unknown = sum(v['unknown'] for v in sanitized_vendor_list)
        total_cve_count = sum(v['cve_count'] for v in sanitized_vendor_list)

        # Prevent division by zero
        percent_critical = round((total_critical / total_cve_count) * 100, 2) if total_cve_count > 0 else 0
        percent_high = round((total_high / total_cve_count) * 100, 2) if total_cve_count > 0 else 0

        # Ensure all variables passed to the template are defined
        return render_template(
            'vendor_analysis.html',
            vendors=sanitized_vendor_list,
            total_critical=total_critical,
            total_high=total_high,
            total_medium=total_medium,
            total_low=total_low,
            total_unknown=total_unknown,
            percent_critical=percent_critical,
            percent_high=percent_high,
            total_vendor_count=len(sanitized_vendor_list),  # Ensure this is passed
            vendors_with_critical_count=sum(1 for v in sanitized_vendor_list if v['critical'] > 0),
            vendors_with_high_count=sum(1 for v in sanitized_vendor_list if v['high'] > 0)
        )
    except TypeError as te:
        # Catch the specific error if the helper function signature is wrong
        if 'takes 1 positional argument but 2 were given' in str(te):
             logging.error("Vendor analysis failed: get_vendor_data function needs update.", exc_info=True)
             return render_template('error.html', error="Configuration Error: The vendor analysis helper function (get_vendor_data in utils/helpers.py) needs to be updated to accept the database model. Please contact the administrator.")
        else:
             # Re-raise other TypeErrors
             logging.error(f"Error generating vendor analysis page: {te}", exc_info=True)
             return render_template('error.html', error=f"An unexpected error occurred during vendor analysis: {te}")
    except Exception as e:
        # Catch other potential errors
        logging.error(f"Error generating vendor analysis page: {e}", exc_info=True)
        return render_template('error.html', error=f"An error occurred during vendor analysis: {e}")
    finally:
        # Ensure session is closed even if vendor_list was empty and returned early
        if session is not None:
            session.close()

@app.route('/vulnerability_category/<category_slug>')
def vulnerability_category(category_slug):
    """Display CVEs for a specific vulnerability category."""
    session = None # Initialize session to None
    try:
        if CVE_Model is None:
            return render_template('error.html', error="Database model not initialized. Please update the database first.")

        engine = create_local_cve_db()
        session = get_session(engine)

        # Define category mapping
        category_map = {
            'sql-injection': {'name': 'SQL Injection', 'keywords': ['SQL Injection', 'CWE-89']},
            'remote-code-execution': {'name': 'Remote Code Execution', 'keywords': ['Remote Code Execution', 'RCE', 'CWE-94']},
            'cross-site-scripting': {'name': 'Cross-Site Scripting', 'keywords': ['Cross-Site Scripting', 'XSS', 'CWE-79']},
            'authentication-bypass': {'name': 'Authentication Bypass', 'keywords': ['Authentication Bypass', 'CWE-287']},
            'denial-of-service': {'name': 'Denial of Service', 'keywords': ['Denial of Service', 'DoS', 'CWE-400']},
            'information-disclosure': {'name': 'Information Disclosure', 'keywords': ['Information Disclosure', 'CWE-200']},
            'buffer-overflow': {'name': 'Buffer Overflow', 'keywords': ['Buffer Overflow', 'CWE-119', 'CWE-120']}
        }

        if category_slug not in category_map:
            return render_template('error.html', error=f"Unknown vulnerability category: {category_slug}")

        category_info = category_map[category_slug]
        category_name = category_info['name']
        keywords = category_info['keywords']

        # Build query based on keywords
        query = session.query(CVE_Model)
        filters = []
        for keyword in keywords:
            filters.append(CVE_Model.description.ilike(f"%{keyword}%"))
            if keyword.startswith('CWE-'):
                filters.append(CVE_Model.cwe_id.ilike(f"%{keyword}%"))
        query = query.filter(sa.or_(*filters))

        # Debugging: Log the generated SQL query and keyword filters
        logging.info(f"Category: {category_name}, Keywords: {keywords}")
        logging.info(f"Generated SQL Query: {query}")

        # Fetch all results for debugging
        all_results = query.all()
        logging.info(f"Total CVEs matching filters: {len(all_results)}")

        # Pagination
        page = request.args.get('page', 1, type=int)
        per_page = 50  # Define per_page explicitly
        total_cves = len(all_results)
        total_pages = (total_cves + per_page - 1) // per_page

        # Debugging: Log total CVEs and pagination details
        logging.info(f"Total CVEs: {total_cves}, Total Pages: {total_pages}, Current Page: {page}")

        # Ensure the current page is within valid bounds
        if page < 1:
            page = 1
        elif page > total_pages and total_pages > 0:
            page = total_pages

        # Fetch paginated results
        paginated_cves = all_results[(page - 1) * per_page: page * per_page]

        # Debugging: Log the number of CVEs fetched for the current page
        logging.info(f"CVEs fetched for page {page}: {len(paginated_cves)}")

        # Handle case where no CVEs are found
        if not paginated_cves and total_cves > 0:
            return render_template('error.html', error="No CVEs found for the current page. Please try a different page.")

        # Data for charts
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        yearly_counts_dict = {}
        all_category_cves = query.all()
        for cve in all_category_cves:
            sev = (cve.severity or 'UNKNOWN').upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["UNKNOWN"] += 1

            if cve.published_date:
                year = cve.published_date.year
                yearly_counts_dict[year] = yearly_counts_dict.get(year, 0) + 1

        yearly_labels = sorted(yearly_counts_dict.keys())
        yearly_counts = [yearly_counts_dict[year] for year in yearly_labels]

        # Calculate severity percentages
        total_severity_count = sum(severity_counts.values())
        severity_percents = {
            key: round((value / total_severity_count) * 100, 2) if total_severity_count > 0 else 0
            for key, value in severity_counts.items()
        }

        # NOTE: Check 'vulnerability_category.html' template.
        # Ensure it correctly uses 'yearly_labels' and 'yearly_counts'
        # (and other variables like severity_counts) with the |tojson filter.
        # The "Object of type Undefined is not JSON serializable" error likely originates here.
        return render_template('vulnerability_category.html',
                               category_name=category_name,
                               cves=paginated_cves,
                               total_cves=total_cves,
                               severity_counts=severity_counts,
                               severity_percents=severity_percents,
                               yearly_labels=yearly_labels,
                               yearly_counts=yearly_counts,
                               current_page=page,
                               total_pages=total_pages,
                               per_page=per_page,  # Pass per_page to the template
                               category_slug=category_slug)
    except Exception as e:
        logging.error(f"Error generating vulnerability category page for {category_slug}: {e}", exc_info=True)
        return render_template('error.html', error=f"An error occurred: {e}")
    finally:
        session.close()

@app.route('/severity_distribution')
def severity_distribution():
    """Display the severity distribution of CVEs."""
    session = None # Initialize session to None
    try:
        if CVE_Model is None:
            return render_template('error.html', error="Database model not initialized. Please update the database first.")

        engine = create_local_cve_db()
        session = get_session(engine) # Assign session here

        # Query to calculate severity distribution
        severity_query = session.query(
            CVE_Model.severity, func.count(CVE_Model.id)
        ).group_by(CVE_Model.severity).all()

        # Prepare severity counts
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0
        }
        total_count = 0
        for severity, count in severity_query:
            s_upper = (severity or 'UNKNOWN').upper()
            if s_upper in severity_counts:
                severity_counts[s_upper] = count
            total_count += count

        # Calculate percentages
        severity_percents = {
            key: round((value / total_count) * 100, 2) if total_count > 0 else 0
            for key, value in severity_counts.items()
        }

        # Query to get yearly data
        yearly_query = session.query(
            extract('year', CVE_Model.published_date).label('year'),
            func.count(CVE_Model.id).label('count')
        ).filter(CVE_Model.published_date != None)\
         .group_by('year')\
         .order_by('year')\
         .all()

        # Process yearly data
        yearly_labels = []
        yearly_counts = []
        for item in yearly_query:
            if item.year:  # Ensure year is not None
                yearly_labels.append(str(int(item.year)))
                yearly_counts.append(item.count)

        # Ensure all variables passed to the template are defined
        # Standardize yearly data variable names
        # NOTE: Check 'severity_distribution.html' template.
        # Ensure it correctly uses 'yearly_labels' and 'yearly_counts'
        # (and other variables like severity_counts) with the |tojson filter.
        # The "Object of type Undefined is not JSON serializable" error likely originates here.
        return render_template(
            'severity_distribution.html',
            severity_counts=severity_counts,
            severity_percents=severity_percents,
            total_count=total_count,
            yearly_labels=yearly_labels,  # Standardized name
            yearly_counts=yearly_counts, # Standardized name
            yearly_data={},  # Empty dict as default (Consider removing if unused)
            # Add other potential variables with defaults
            top_vendor_names=[],
            top_vendor_counts=[]
        )
    except Exception as e:
        logging.error(f"Error generating severity distribution page: {e}", exc_info=True)
        return render_template('error.html', error=f"An error occurred: {e}")
    finally:
        # Ensure session is closed in the finally block
        if session is not None:
            session.close()

@app.route('/monthly_summary')
def monthly_summary():
    """Display a monthly summary of CVEs."""
    session = None # Initialize session to None
    try:
        if CVE_Model is None:
            return render_template('error.html', error="Database model not initialized. Please update the database first.")

        engine = create_local_cve_db()
        session = get_session(engine) # Assign session here

        # Query to get counts per month/year
        monthly_data = session.query(
            extract('year', CVE_Model.published_date).label('year'),
            extract('month', CVE_Model.published_date).label('month'),
            func.count(CVE_Model.id).label('count')
        ).filter(CVE_Model.published_date != None)\
         .group_by('year', 'month')\
         .order_by('year', 'month')\
         .all()

        # Process data for the chart - use standardized names
        monthly_labels = []
        monthly_counts = []
        for item in monthly_data:
            if item.year and item.month:  # Ensure year and month are not None
                monthly_labels.append(f"{int(item.year)}-{int(item.month):02d}")  # Format as YYYY-MM
                monthly_counts.append(item.count)

        # Pass standardized variable names to the template
        # NOTE: Check 'monthly_summary.html' template.
        # Ensure it correctly uses 'monthly_labels' and 'monthly_counts'
        # with the |tojson filter.
        # The "Object of type Undefined is not JSON serializable" error likely originates here.
        return render_template('monthly_summary.html',
                               monthly_labels=monthly_labels,
                               monthly_counts=monthly_counts)
    except Exception as e:
        logging.error(f"Error generating monthly summary page: {e}", exc_info=True)
        return render_template('error.html', error=f"An error occurred: {e}")
    finally:
        # Ensure session is closed in the finally block
        if session is not None:
            session.close()

# Run the application
if __name__ == '__main__':
    with app.app_context():
        engine = create_local_cve_db()
        if engine is not None:
            CVE_Model = create_cve_table(engine)

    app.run(debug=True, host='0.0.0.0', port=8080)
