import os
import logging
import sqlalchemy as sa
# Update declarative_base import for SQLAlchemy 2.0 compatibility
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import func, extract
from flask import Flask, render_template, request, jsonify, redirect, url_for, json
from modules.nvdapi import NVDApi, fetch_nvd_data_feed, fetch_all_nvd_data, determine_severity
from datetime import datetime
import threading
from utils.helpers import get_vendor_data, generate_slug
import calendar

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
            if year not in summary_data:
                summary_data[year] = {}
                # Initialize all months for the year to ensure they exist
                for m in range(1, 13):
                    summary_data[year][m] = {'count': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0}

            if month not in summary_data[year]:
                 # This case should ideally not happen if initialized above, but as a safeguard
                 summary_data[year][month] = {'count': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0}

            # Increment total count for the month
            summary_data[year][month]['count'] += count

            # Increment severity count
            severity_key = (severity or 'unknown').lower()
            if severity_key in summary_data[year][month]:
                summary_data[year][month][severity_key] += count
            else:
                 # Handle unexpected severity values if necessary, though 'unknown' should catch most
                 summary_data[year][month]['unknown'] += count


        # Determine available years and selected year
        current_year = datetime.now().year
        all_years_in_data = sorted(summary_data.keys(), reverse=True)
        selected_year = request.args.get('year', type=int) # Get year from query param

        # If no year requested or requested year not in data, default to the latest year with data
        if not all_years_in_data:
             all_years_in_data = [current_year] # Default to current year if no data at all
             selected_year = current_year
        elif selected_year is None or selected_year not in all_years_in_data:
             selected_year = all_years_in_data[0] # Default to the latest year found in data


        month_names_list = list(calendar.month_name)[1:]  # ["January", ..., "December"]

    except Exception as e:
        logging.error(f"Error fetching monthly summary: {e}")
        return render_template('error.html', error_message="An error occurred while generating the monthly summary.")
    finally:
        if 'session' in locals() and session:
            session.close()

    # Pass the structured data to the template
    return render_template(
        'monthly_summary.html',
        summary_data=summary_data,         # Nested dict: {year: {month: {count: X, critical: Y, ...}}}
        years=all_years_in_data,           # List of years with data
        selected_year=selected_year,       # The year to display initially
        month_names=month_names_list       # List of full month names
    )

@app.route('/severity_distribution')
def severity_distribution():
    """Displays the distribution of CVEs by severity level."""
    severity_counts = {}
    severity_percents = {} # Initialize the dictionary
    try:
        engine = create_local_cve_db()
        session = get_session(engine)

        if CVE_Model is None:
            return render_template('error.html', error_message="Database model not initialized.")

        # Query to get counts grouped by severity
        severity_query = session.query(
            CVE_Model.severity, func.count(CVE_Model.id).label('count')
        ).group_by(CVE_Model.severity).all()

        # Initialize counts for all expected severities
        severity_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for severity, count in severity_query:
            s_upper = (severity or 'UNKNOWN').upper()
            if s_upper in severity_map: # Ensure we only count expected severities
                 severity_map[s_upper] = count
        severity_counts = severity_map

        # Calculate total CVE count
        total_cve_count = sum(severity_counts.values())

        # Calculate percentages
        if total_cve_count > 0:
            for severity, count in severity_counts.items():
                severity_percents[severity] = round((count / total_cve_count) * 100, 2)
        else:
            # Handle case with no CVEs
            for severity in severity_counts:
                severity_percents[severity] = 0.0

    except Exception as e:
        logging.error(f"Error fetching severity distribution: {e}")
        return render_template('error.html', error_message="An error occurred while generating the severity distribution.")
    finally:
        if 'session' in locals() and session:
            session.close()

    # Prepare data for Chart.js (Overall Distribution Pie/Bar Chart)
    labels = list(severity_counts.keys())
    data = list(severity_counts.values())
    chart_data = json.dumps({
        'labels': labels,
        'data': data
    })

    # Define years as an empty list to prevent template error (from previous fix)
    years_for_template = []

    # Define default empty lists for time-series data expected by the template
    # TODO: Implement actual time-series data fetching if needed for charts
    critical_series = []
    high_series = []
    medium_series = []
    low_series = []
    unknown_series = []

    # Define default empty dict for CVSS ranges data expected by the template
    # TODO: Implement actual CVSS range data fetching if needed for charts
    cvss_ranges = {}

    return render_template('severity_distribution.html',
                           severity_counts=severity_counts,
                           severity_percents=severity_percents, # Pass the percentages to the template
                           chart_data=chart_data,
                           years=years_for_template, # Pass an empty list for 'years'
                           # Pass empty lists for time-series data
                           critical_series=critical_series,
                           high_series=high_series,
                           medium_series=medium_series,
                           low_series=low_series,
                           unknown_series=unknown_series,
                           cvss_ranges=cvss_ranges) # Pass empty dict for cvss_ranges

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
    Fetches vendor data and renders the vendor analysis template.
    """
    top_n = 30 # Number of top vendors to display
    vendor_details = {}

    try:
        engine = create_local_cve_db()
        session = get_session(engine)

        if CVE_Model is None:
             return render_template('error.html', error_message="Database model not initialized.")

        # Query necessary data: cpe_affected and severity for all relevant CVEs
        # Optimization: Query only necessary columns
        cve_data_query = session.query(CVE_Model.cpe_affected, CVE_Model.severity)\
                                .filter(CVE_Model.cpe_affected != '', CVE_Model.cpe_affected.isnot(None))\
                                .all()

        # Process data to aggregate vendor counts and severity distributions
        for cpe_string_tuple, severity in cve_data_query:
            if cpe_string_tuple:
                cpes = cpe_string_tuple.split(',')
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

        session.close()

        # Prepare data for Chart.js (Top N Vendors by Count)
        chart_labels = [v[0] for v in top_vendors_list] # Vendor names
        chart_data = [v[1]['count'] for v in top_vendors_list] # Total counts
        chart_json = json.dumps({
            'labels': chart_labels,
            'datasets': [{
                'label': 'Total CVEs',
                'data': chart_data,
                'backgroundColor': 'rgba(54, 162, 235, 0.6)', # Example color
                'borderColor': 'rgba(54, 162, 235, 1)',
                'borderWidth': 1
            }]
        })

        return render_template('vendor_analysis.html',
                               vendors=top_vendors_dict, # Pass the dict of top vendors
                               chart_json=chart_json,
                               top_n=top_n)
    except Exception as e:
        logging.error(f"Error in /vendor_analysis route: {e}")
        # Log the full traceback for debugging
        import traceback
        logging.error(traceback.format_exc())
        return render_template('error.html', error_message="An error occurred while loading vendor analysis data. Please try again later."), 500

# Add a temporary dummy route to test the BuildError
@app.route('/top_vendors_placeholder')
def top_vendors():
    # This is a placeholder. Replace with actual logic or remove if not needed.
    # You might want to return a simple template or just text.
    return "Top Vendors Page (Placeholder)", 200

# Run the application
if __name__ == '__main__':
    with app.app_context():
        engine = create_local_cve_db()
        if engine is not None:
            CVE_Model = create_cve_table(engine)

    app.run(debug=True, host='0.0.0.0', port=8080)

