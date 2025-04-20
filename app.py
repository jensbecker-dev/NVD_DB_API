import os
import logging
import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import func
from flask import Flask, render_template, request, jsonify, redirect, url_for
from modules.nvdapi import NVDApi, fetch_nvd_data_feed, fetch_all_nvd_data, determine_severity
from datetime import datetime
import threading

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
    
    Returns:
        SQLAlchemy engine object
    """
    try:
        # Fixed path to create database in the app directory
        db_path = os.path.join(os.path.dirname(__file__), 'cve_database.db')
        engine = sa.create_engine(f'sqlite:///{db_path}', echo=False)
        logging.info(f"Created database at {db_path}")
        return engine
    except Exception as e:
        logging.error(f"Error creating database: {e}")
        return None

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

# Initialize database at module level
engine = create_local_cve_db()
if engine is not None:
    CVE_Model = create_cve_table(engine)

# Flask routes
@app.route('/', methods=['GET', 'POST'])
def index():
    """Home page showing overview and search form"""
    results = []
    search_term = request.args.get('search_term', '') # Get search term from URL args for redirects
    search_performed = request.args.get('search_performed', 'false').lower() == 'true'
    exploitable_only = request.args.get('exploitable', 'false').lower() == 'true'
    severity_filter = request.args.get('severity', '') # Get the severity filter value
    severity_counts = {} # Initialize severity counts
    
    # For pagination
    page = request.args.get('page', 1, type=int)
    per_page = 100  # Show 100 results per page

    try:
        engine = create_local_cve_db()
        Session = sessionmaker(bind=engine)
        session = Session()

        if CVE_Model is None:
            # Still render index but show error and no counts
            return render_template('index.html', error_message="Database model not initialized. Please update the database first.", results=[], search_term=search_term, search_performed=search_performed, severity_counts={}, total_cve_count=0) # Pass empty counts and total

        # Calculate severity counts
        severity_query = session.query(
            CVE_Model.severity, func.count(CVE_Model.id)
        ).group_by(CVE_Model.severity).all()

        # Convert to dict, handling None severity
        severity_map = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0
        }
        for severity, count in severity_query:
            s_upper = (severity or 'UNKNOWN').upper() # Treat None as UNKNOWN
            if s_upper in severity_map:
                severity_map[s_upper] = count
            else: # Catch any unexpected values
                severity_map["UNKNOWN"] += count
        severity_counts = severity_map
        total_cve_count = sum(severity_counts.values()) # Calculate total count

        if request.method == 'POST':
            search_performed = True
            search_term = request.form.get('search_term', '').strip() # Trim whitespace
            exploitable_only = request.form.get('exploitable') == 'on'
            severity_filter = request.form.get('severity', '')  # Get the selected severity

            # Redirect to GET request with search parameters to avoid form resubmission issues
            return redirect(url_for('index', 
                            search_term=search_term, 
                            exploitable=exploitable_only,
                            severity=severity_filter, 
                            search_performed=True))

        if search_performed or search_term: # Only search if requested and term is not empty
            # Build the base query
            query = session.query(CVE_Model)

            # Check if search term is likely a CVE ID pattern (more robust check)
            is_cve_pattern = search_term.upper().startswith('CVE-') and len(search_term.split('-')) == 3

            if is_cve_pattern:
                # Search specifically by CVE ID (case-insensitive)
                # Use exact match for specific CVE ID search for better performance
                query = query.filter(CVE_Model.cve_id.ilike(search_term))
            else:
                # Search in descriptions for keywords (case-insensitive)
                # Split search term into words and search for all words
                keywords = search_term.split()
                for keyword in keywords:
                    query = query.filter(CVE_Model.description.ilike(f"%{keyword}%"))

            # Apply severity filter if specified
            if severity_filter and severity_filter in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
                query = query.filter(CVE_Model.severity == severity_filter)

            # Filter by exploitable if requested
            # This filter remains basic, checking for 'exploit' in references.
            # A more robust solution would involve a dedicated flag or better data source.
            if exploitable_only:
                query = query.filter(CVE_Model.references.ilike('%exploit%'))

            # Count total results before applying pagination
            total_results = query.count()

            # Apply pagination
            query = query.order_by(CVE_Model.published_date.desc())
            paginated_results = query.limit(per_page).offset((page - 1) * per_page).all()
            results = paginated_results

            # Calculate number of pages
            total_pages = (total_results + per_page - 1) // per_page  # ceiling division

            # If no results in DB and it was a specific CVE ID search, try API
            if not results and is_cve_pattern:
                nvd_api = NVDApi()
                # Pass the exact search term to get_cve
                cve_api_details = nvd_api.get_cve(search_term)
                if cve_api_details:
                    # Render details directly instead of redirecting to avoid losing context
                    return render_template('cve_details.html', cve=cve_api_details, from_api=True)
                # If API also fails, the 'no results' message will be shown below

    except Exception as e:
        logging.error(f"Error during search or getting counts: {e}")
        # Render index page but show an error message within it
        return render_template('index.html',
                              error_message=f"Operation failed: {e}",
                              results=[],
                              search_term=search_term,
                              search_performed=search_performed,
                              severity_counts={}, # Pass empty counts on error
                              total_cve_count=0) # Pass 0 total on error

    # Render the index page with or without results, and with severity counts
    return render_template('index.html',
                          results=results,
                          search_term=search_term,
                          search_performed=search_performed,
                          severity=severity_filter,  # Pass the severity filter value to the template
                          severity_counts=severity_counts, # Pass severity counts
                          total_cve_count=total_cve_count,
                          current_page=page,
                          total_pages=total_pages if 'total_pages' in locals() else 1,
                          total_results=total_results if 'total_results' in locals() else 0,
                          exploitable=exploitable_only) # Pass total count

@app.route('/view_all')
def view_all_entries():
    """Display all CVEs in the database, with sorting options"""
    sort_by = request.args.get('sort', 'published_desc') # Default sort
    
    # For pagination
    page = request.args.get('page', 1, type=int)
    per_page = 100  # Show 100 results per page
    
    try:
        engine = create_local_cve_db()
        Session = sessionmaker(bind=engine)
        session = Session()

        if CVE_Model is None:
            return render_template('error.html', error="Database model not initialized. Please update the database first.")

        # Calculate severity counts (same logic as in index function)
        severity_query = session.query(
            CVE_Model.severity, func.count(CVE_Model.id)
        ).group_by(CVE_Model.severity).all()

        # Convert to dict, handling None severity
        severity_map = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0
        }
        for severity, count in severity_query:
            s_upper = (severity or 'UNKNOWN').upper() # Treat None as UNKNOWN
            if s_upper in severity_map:
                severity_map[s_upper] = count
            else: # Catch any unexpected values
                severity_map["UNKNOWN"] += count
        
        severity_counts = severity_map
        total_cve_count = sum(severity_counts.values()) # Calculate total count

        query = session.query(CVE_Model)

        # Define severity order for sorting
        severity_order = sa.case(
            (CVE_Model.severity == 'CRITICAL', 5),
            (CVE_Model.severity == 'HIGH', 4),
            (CVE_Model.severity == 'MEDIUM', 3),
            (CVE_Model.severity == 'LOW', 2),
            else_=1 # Group UNKNOWN/NONE/Other as lowest
        )

        # Apply sorting based on parameter
        if sort_by == 'severity_asc':
            query = query.order_by(severity_order.asc(), CVE_Model.published_date.desc())
        elif sort_by == 'severity_desc':
            query = query.order_by(severity_order.desc(), CVE_Model.published_date.desc())
        elif sort_by == 'published_asc':
             query = query.order_by(CVE_Model.published_date.asc())
        else: # Default: published_desc
            query = query.order_by(CVE_Model.published_date.desc())

        # Count total results before applying pagination
        total_results = query.count()
        
        # Apply pagination
        paginated_results = query.limit(per_page).offset((page - 1) * per_page).all()
        
        # Calculate number of pages
        total_pages = (total_results + per_page - 1) // per_page  # ceiling division

        # Use the index template to display results, passing the sort parameter
        return render_template('index.html',
                              results=paginated_results,
                              search_term='All Database Entries',
                              search_performed=True, # Flag to show the results section
                              sort_by=sort_by, # Pass current sort order
                              is_view_all=True, # Flag to distinguish from search
                              severity_counts=severity_counts, # Add severity counts
                              total_cve_count=total_cve_count,
                              current_page=page,
                              total_pages=total_pages,
                              total_results=total_results) # Add total count

    except Exception as e:
        logging.error(f"Error fetching all entries: {e}")
        return render_template('error.html', error=str(e))

@app.route('/cve/<cve_id>')
def cve_details(cve_id):
    """Show details for a specific CVE"""
    try:
        cve_data = None
        from_api = False

        # Try database first
        if CVE_Model is not None:
            engine = create_local_cve_db()
            Session = sessionmaker(bind=engine)
            session = Session()
            # Use exact match for CVE ID lookup
            cve_data = session.query(CVE_Model).filter(CVE_Model.cve_id.ilike(cve_id)).first()

        # If not in DB, try API
        if not cve_data:
            return redirect(url_for('api_cve_details', cve_id=cve_id))

        if cve_data:
            # If data came from API, it's a dict, otherwise it's a CVE_Model object.
            # The template needs to handle both structures or we need to normalize here.
            # For simplicity, the template cve_details.html already handles potential differences.
            return render_template('cve_details.html', cve=cve_data, from_api=from_api)
        else:
            # CVE not found in DB, redirect to API details
            return redirect(url_for('api_cve_details', cve_id=cve_id))

    except Exception as e:
        logging.error(f"Error fetching CVE details for {cve_id}: {e}")
        return render_template('error.html', error=f"An error occurred while fetching details for {cve_id}.")

@app.route('/update_database')
def update_database():
    """Update the local CVE database with latest data"""
    global db_update_status
    
    # If already updating, show status page
    if db_update_status['is_updating']:
        return render_template('update_status.html', status=db_update_status)
    
    # Start update in background thread
    db_update_status = {
        'is_updating': True,
        'progress': 0,
        'total_years': datetime.now().year - 2002 + 2,  # From 2002 to current year + future year
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

# Add this route to check database status
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
        Session = sessionmaker(bind=engine)
        session = Session()
        
        # Count records
        record_count = session.query(CVE_Model).count()
        
        # Get sample record
        sample = session.query(CVE_Model).first()
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

@app.route('/monthly_summary')
def monthly_summary():
    """Display a monthly summary of CVE publications"""
    try:
        if CVE_Model is None:
            return render_template('error.html', error="Database model not initialized. Please update the database first.")
        
        engine = create_local_cve_db()
        Session = sessionmaker(bind=engine)
        session = Session()
        
        # Get all CVEs with valid published dates
        all_cves = session.query(CVE_Model).filter(CVE_Model.published_date.isnot(None)).all()
        
        # Organize data by month and year
        monthly_data = {}
        
        for cve in all_cves:
            if not cve.published_date:
                continue
                
            year = cve.published_date.year
            month = cve.published_date.month
            
            # Create year entry if it doesn't exist
            if year not in monthly_data:
                monthly_data[year] = {m: {'count': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0}
                                    for m in range(1, 13)}
            
            # Increment the count for this month
            monthly_data[year][month]['count'] += 1
            
            # Count by severity
            severity = (cve.severity or 'UNKNOWN').upper()
            if severity == 'CRITICAL':
                monthly_data[year][month]['critical'] += 1
            elif severity == 'HIGH':
                monthly_data[year][month]['high'] += 1
            elif severity == 'MEDIUM':
                monthly_data[year][month]['medium'] += 1
            elif severity == 'LOW':
                monthly_data[year][month]['low'] += 1
            else:
                monthly_data[year][month]['unknown'] += 1
        
        # Get list of years in descending order
        years = sorted(monthly_data.keys(), reverse=True)
        
        # Get month names for the template
        month_names = ['January', 'February', 'March', 'April', 'May', 'June', 
                      'July', 'August', 'September', 'October', 'November', 'December']
        
        # Chart data for the most recent year
        most_recent_year = years[0] if years else datetime.now().year
        chart_months = [month_names[m-1] for m in range(1, 13)]
        chart_data = [monthly_data[most_recent_year][m]['count'] if most_recent_year in monthly_data else 0 for m in range(1, 13)]
        
        # Critical vulnerability data for chart
        critical_data = [monthly_data[most_recent_year][m]['critical'] if most_recent_year in monthly_data else 0 for m in range(1, 13)]
        
        return render_template('monthly_summary.html',
                              monthly_data=monthly_data,
                              years=years,
                              most_recent_year=most_recent_year,
                              month_names=month_names,
                              chart_months=chart_months,
                              chart_data=chart_data,
                              critical_data=critical_data)
    
    except Exception as e:
        logging.error(f"Error generating monthly summary: {e}")
        return render_template('error.html', error=f"An error occurred: {e}")

# Helper function to get vendor data
def get_vendor_data(session):
    """Extract vendor information from CVE data"""
    vendors = {}
    all_cves = session.query(CVE_Model).all()
    
    for cve in all_cves:
        if not cve.cpe_affected:
            continue
        
        # Split CPE string and extract vendor names
        cpe_items = cve.cpe_affected.split(',')
        for cpe in cpe_items:
            # CPE format: cpe:2.3:part:vendor:product:version:...
            parts = cpe.split(':')
            if len(parts) >= 5:
                vendor = parts[3].lower()
                # Skip generic/empty vendors
                if vendor in ('', '*', '-', 'n/a'):
                    continue
                
                # Add or update vendor stats
                if vendor not in vendors:
                    vendors[vendor] = {
                        'name': vendor,
                        'slug': vendor.replace(' ', '-').lower(),
                        'cve_count': 0,
                        'critical': 0,
                        'high': 0,
                        'medium': 0,
                        'low': 0,
                        'unknown': 0,
                        'has_critical': False,
                        'has_high': False,
                        'has_medium': False,
                        'has_low': False
                    }
                
                vendors[vendor]['cve_count'] += 1
                
                # Count by severity
                severity = (cve.severity or 'UNKNOWN').upper()
                if severity == 'CRITICAL':
                    vendors[vendor]['critical'] += 1
                    vendors[vendor]['has_critical'] = True
                elif severity == 'HIGH':
                    vendors[vendor]['high'] += 1
                    vendors[vendor]['has_high'] = True
                elif severity == 'MEDIUM':
                    vendors[vendor]['medium'] += 1
                    vendors[vendor]['has_medium'] = True
                elif severity == 'LOW':
                    vendors[vendor]['low'] += 1
                    vendors[vendor]['has_low'] = True
                else:
                    vendors[vendor]['unknown'] += 1
    
    # Convert to list and sort by CVE count
    vendor_list = sorted(vendors.values(), key=lambda x: x['cve_count'], reverse=True)
    return vendor_list

@app.route('/top_vendors')
def top_vendors():
    """Display a list of top vendors with most CVEs"""
    try:
        if CVE_Model is None:
            return render_template('error.html', error="Database model not initialized. Please update the database first.")
        
        engine = create_local_cve_db()
        Session = sessionmaker(bind=engine)
        session = Session()
        
        # Get the vendor list from our helper function
        vendor_list = get_vendor_data(session)
        
        # Prepare data for the top vendors chart
        top_vendor_names = []
        top_vendor_counts = []
        
        # Get top 20 vendors for the chart (we'll show top 10 by default, with option to show 20)
        for vendor in vendor_list[:20]:
            top_vendor_names.append(vendor['name'])
            top_vendor_counts.append(vendor['cve_count'])
        
        return render_template('top_vendors.html',
                              vendors=vendor_list,
                              top_vendor_names=top_vendor_names,
                              top_vendor_counts=top_vendor_counts)
    
    except Exception as e:
        logging.error(f"Error generating top vendors page: {e}")
        return render_template('error.html', error=f"An error occurred: {e}")

@app.route('/vendor/<vendor>')
def vendor_detail(vendor):
    """Display detailed information about a specific vendor"""
    try:
        if CVE_Model is None:
            return render_template('error.html', error="Database model not initialized. Please update the database first.")
        
        # For pagination
        page = request.args.get('page', 1, type=int)
        per_page = 50  # Show 50 results per page
        
        engine = create_local_cve_db()
        Session = sessionmaker(bind=engine)
        session = Session()
        
        # Map vendor slugs to proper names and any alternate names to search for
        vendor_mapping = {
            'microsoft': {
                'name': 'Microsoft',
                'alternates': ['microsoft', 'msft', 'ms']
            },
            'adobe': {
                'name': 'Adobe',
                'alternates': ['adobe']
            },
            'oracle': {
                'name': 'Oracle',
                'alternates': ['oracle', 'sun microsystems', 'sun', 'java']
            },
            'google': {
                'name': 'Google',
                'alternates': ['google', 'android', 'chrome']
            },
            'apple': {
                'name': 'Apple',
                'alternates': ['apple', 'macos', 'ios', 'iphone', 'ipad', 'safari']
            }
        }
        
        # If vendor not found in our mapping, generate a default name from the slug
        if vendor not in vendor_mapping:
            # Handle unknown vendor by using the slug as the name
            vendor_name = vendor.replace('-', ' ').title()
            search_terms = [vendor.replace('-', ' ')]
        else:
            vendor_name = vendor_mapping[vendor]['name']
            search_terms = vendor_mapping[vendor]['alternates']
        
        # Query CVEs for this vendor
        all_cves = session.query(CVE_Model).all()
        
        vendor_cves = []
        product_data = {}
        
        for cve in all_cves:
            is_vendor_match = False
            
            # Check based on CPE data
            if cve.cpe_affected:
                cpe_items = cve.cpe_affected.split(',')
                for cpe in cpe_items:
                    # CPE format: cpe:2.3:part:vendor:product:version:...
                    parts = cpe.split(':')
                    if len(parts) >= 5:
                        cpe_vendor = parts[3].lower()
                        if cpe_vendor in search_terms:
                            is_vendor_match = True
                            
                            # Track product data if we have it
                            if len(parts) >= 6:
                                product = parts[4]
                                if product and product != '*':
                                    if product not in product_data:
                                        product_data[product] = {
                                            'name': product,
                                            'cve_count': 0,
                                            'critical': 0,
                                            'high': 0,
                                            'medium': 0,
                                            'low': 0,
                                            'unknown': 0
                                        }
                                    
                                    product_data[product]['cve_count'] += 1
                                    
                                    # Count by severity
                                    severity = (cve.severity or 'UNKNOWN').upper()
                                    if severity == 'CRITICAL':
                                        product_data[product]['critical'] += 1
                                    elif severity == 'HIGH':
                                        product_data[product]['high'] += 1
                                    elif severity == 'MEDIUM':
                                        product_data[product]['medium'] += 1
                                    elif severity == 'LOW':
                                        product_data[product]['low'] += 1
                                    else:
                                        product_data[product]['unknown'] += 1
            
            # As a fallback, check description for vendor name
            if not is_vendor_match and cve.description:
                desc_lower = cve.description.lower()
                for term in search_terms:
                    if term.lower() in desc_lower:
                        is_vendor_match = True
                        break
            
            if is_vendor_match:
                vendor_cves.append(cve)
        
        # Sort vendor_cves by published date (newest first)
        vendor_cves.sort(key=lambda x: x.published_date if x.published_date else datetime.min, reverse=True)
        
        # Calculate pagination
        total_cves = len(vendor_cves)
        total_pages = (total_cves + per_page - 1) // per_page  # ceiling division
        
        # Get only the CVEs for the current page
        start_idx = (page - 1) * per_page
        end_idx = min(start_idx + per_page, total_cves)
        paginated_cves = vendor_cves[start_idx:end_idx]
        
        # Get top products by CVE count
        top_products = sorted(product_data.values(), key=lambda x: x['cve_count'], reverse=True)[:6]
        
        # Generate severity statistics
        severity_counts = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0
        }
        
        for cve in vendor_cves:
            severity = (cve.severity or 'UNKNOWN').upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts['UNKNOWN'] += 1
        
        # Get yearly trend data
        yearly_data = {}
        for cve in vendor_cves:
            if cve.published_date:
                year = cve.published_date.year
                if year not in yearly_data:
                    yearly_data[year] = 0
                yearly_data[year] += 1
        
        # Sort years for the chart
        yearly_labels = sorted(yearly_data.keys())
        yearly_counts = [yearly_data[year] for year in yearly_labels]
        
        # Calculate a risk score based on CVE counts and severity
        if total_cves > 0:
            # Weight critical and high more heavily
            weighted_score = (
                (severity_counts['CRITICAL'] * 10) + 
                (severity_counts['HIGH'] * 5) + 
                (severity_counts['MEDIUM'] * 2) + 
                severity_counts['LOW']
            ) / total_cves
            
            # Scale to 0-100
            risk_score = min(100, round(weighted_score * 10))
        else:
            risk_score = 0
        
        # Get common issue types (simplified version)
        top_issues = [
            {'name': 'Remote Code Execution', 'count': round(total_cves * 0.2)},  # Simplified assumption
            {'name': 'Information Disclosure', 'count': round(total_cves * 0.15)},
            {'name': 'Denial of Service', 'count': round(total_cves * 0.12)}
        ]
        
        # Get similar vendors for the "Similar Vendors" section
        similar_vendors = []
        for v_slug, v_data in vendor_mapping.items():
            if v_slug != vendor:  # Don't include the current vendor
                similar_vendors.append({
                    'name': v_data['name'],
                    'slug': v_slug,
                    'cve_count': len(session.query(CVE_Model).filter(CVE_Model.description.ilike(f'%{v_data["name"]}%')).all())
                })
        
        return render_template('vendor_detail.html',
                              vendor=vendor,
                              vendor_name=vendor_name,
                              total_cves=total_cves,
                              paginated_cves=paginated_cves,
                              current_page=page,
                              per_page=per_page,
                              total_pages=total_pages,
                              severity_counts=severity_counts,
                              top_products=top_products,
                              yearly_labels=yearly_labels,
                              yearly_counts=yearly_counts,
                              risk_score=risk_score,
                              top_issues=top_issues,
                              similar_vendors=similar_vendors[:3])  # Show only top 3 similar vendors
    
    except Exception as e:
        logging.error(f"Error generating vendor detail page: {e}")
        return render_template('error.html', error=f"An error occurred: {e}")

@app.route('/vulnerability_category/<category>')
def vulnerability_category(category):
    """Display CVEs for a specific vulnerability category"""
    try:
        if CVE_Model is None:
            return render_template('error.html', error="Database model not initialized. Please update the database first.")
        
        # For pagination
        page = request.args.get('page', 1, type=int)
        per_page = 50  # Show 50 results per page
        
        engine = create_local_cve_db()
        Session = sessionmaker(bind=engine)
        session = Session()
        
        # Define category mappings (slug to readable name and search terms)
        category_mappings = {
            'sql-injection': {
                'name': 'SQL Injection',
                'description': 'SQL injection vulnerabilities allow attackers to inject malicious SQL code into an application, potentially giving them unauthorized access to databases or the ability to manipulate data.',
                'search_terms': ['sql injection', 'sqli', 'sql', 'database injection']
            },
            'remote-code-execution': {
                'name': 'Remote Code Execution',
                'description': 'Remote Code Execution (RCE) vulnerabilities allow attackers to execute arbitrary code on affected systems, potentially gaining complete control over the target.',
                'search_terms': ['remote code execution', 'rce', 'code execution', 'command execution', 'arbitrary code']
            },
            'cross-site-scripting': {
                'name': 'Cross-Site Scripting (XSS)',
                'description': 'Cross-Site Scripting vulnerabilities allow attackers to inject malicious scripts into web pages, which can then be executed in users\' browsers, potentially stealing data or session tokens.',
                'search_terms': ['cross-site scripting', 'xss', 'script injection', 'client-side injection']
            },
            'authentication-bypass': {
                'name': 'Authentication Bypass',
                'description': 'Authentication bypass vulnerabilities allow attackers to gain unauthorized access to systems or data by circumventing authentication mechanisms.',
                'search_terms': ['authentication bypass', 'auth bypass', 'login bypass', 'privilege escalation']
            },
            'denial-of-service': {
                'name': 'Denial of Service',
                'description': 'Denial of Service (DoS) vulnerabilities allow attackers to make systems or networks unavailable to legitimate users by overwhelming resources or exploiting flaws.',
                'search_terms': ['denial of service', 'dos', 'resource exhaustion', 'crash']
            },
            'information-disclosure': {
                'name': 'Information Disclosure',
                'description': 'Information disclosure vulnerabilities allow attackers to access sensitive data that should be protected, such as system information, user data, or source code.',
                'search_terms': ['information disclosure', 'information leakage', 'data leak', 'sensitive information']
            },
            'buffer-overflow': {
                'name': 'Buffer Overflow',
                'description': 'Buffer overflow vulnerabilities occur when a program writes more data to a buffer than it can hold, potentially allowing attackers to execute arbitrary code or crash the system.',
                'search_terms': ['buffer overflow', 'stack overflow', 'heap overflow', 'memory corruption']
            }
        }
        
        # If category doesn't exist in our mappings, return an error
        if category not in category_mappings:
            return render_template('error.html', error=f"Unknown vulnerability category: {category}")
        
        # Get category info
        category_info = category_mappings[category]
        category_name = category_info['name']
        category_description = category_info['description']
        search_terms = category_info['search_terms']
        
        # Find CVEs matching this category
        matching_cves = []
        all_cves = session.query(CVE_Model).all()
        
        for cve in all_cves:
            if cve.description:
                description_lower = cve.description.lower()
                # Check if any search term is in the description
                if any(term.lower() in description_lower for term in search_terms):
                    matching_cves.append(cve)
        
        # Sort by published date (newest first)
        matching_cves.sort(key=lambda x: x.published_date if x.published_date else datetime.min, reverse=True)
        
        # Calculate pagination
        total_cves = len(matching_cves)
        total_pages = (total_cves + per_page - 1) // per_page  # ceiling division
        
        # Get only the CVEs for the current page
        start_idx = (page - 1) * per_page
        end_idx = min(start_idx + per_page, total_cves)
        paginated_cves = matching_cves[start_idx:end_idx]
        
        # Calculate severity counts
        severity_counts = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0
        }
        
        for cve in matching_cves:
            severity = (cve.severity or 'UNKNOWN').upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts['UNKNOWN'] += 1
        
        # Calculate percentages
        severity_percents = {}
        for severity, count in severity_counts.items():
            if total_cves > 0:
                severity_percents[severity] = round((count / total_cves) * 100, 1)
            else:
                severity_percents[severity] = 0
        
        # Get yearly distribution
        yearly_data = {}
        for cve in matching_cves:
            if cve.published_date:
                year = cve.published_date.year
                if year not in yearly_data:
                    yearly_data[year] = 0
                yearly_data[year] += 1
        
        # Prepare chart data
        yearly_labels = sorted(yearly_data.keys())
        yearly_counts = [yearly_data[year] for year in yearly_labels]
        
        # Related categories (exclude current)
        related_categories = []
        for cat_slug, cat_info in category_mappings.items():
            if cat_slug != category:
                related_categories.append({
                    'name': cat_info['name'],
                    'description': cat_info['description'],
                    'slug': cat_slug
                })
        
        # Limit to 3 related categories
        related_categories = related_categories[:3]
        
        return render_template('vulnerability_category.html',
                              category=category,
                              category_name=category_name,
                              category_description=category_description,
                              cves=matching_cves,
                              paginated_cves=paginated_cves,
                              current_page=page,
                              per_page=per_page,
                              total_pages=total_pages,
                              total_cves=total_cves,
                              severity_counts=severity_counts,
                              severity_percents=severity_percents,
                              yearly_labels=yearly_labels,
                              yearly_counts=yearly_counts,
                              related_categories=related_categories)
    
    except Exception as e:
        logging.error(f"Error generating vulnerability category page: {e}")
        return render_template('error.html', error=f"An error occurred: {e}")

@app.route('/severity_distribution')
def severity_distribution():
    """Display severity distribution of CVEs in the database"""
    try:
        if CVE_Model is None:
            return render_template('error.html', error="Database model not initialized. Please update the database first.")
        
        engine = create_local_cve_db()
        Session = sessionmaker(bind=engine)
        session = Session()
        
        # Get severity counts from the database
        severity_query = session.query(
            CVE_Model.severity, func.count(CVE_Model.id)
        ).group_by(CVE_Model.severity).all()
        
        # Convert to dict, handling None severity
        severity_map = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0
        }
        for severity, count in severity_query:
            s_upper = (severity or 'UNKNOWN').upper()
            if s_upper in severity_map:
                severity_map[s_upper] = count
            else:
                severity_map["UNKNOWN"] += count
        
        # Calculate total for percentages
        total_cves = sum(severity_map.values())
        
        # Calculate percentages
        severity_percents = {}
        for severity, count in severity_map.items():
            if total_cves > 0:
                severity_percents[severity] = round((count / total_cves) * 100, 1)
            else:
                severity_percents[severity] = 0
        
        # Get CVSS score distribution
        cvss_v3_scores = [cve.cvss_v3_score for cve in session.query(CVE_Model.cvss_v3_score).filter(CVE_Model.cvss_v3_score.isnot(None)).all()]
        
        # Group CVSS scores into ranges for histogram
        cvss_ranges = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]  # 0-1, 1-2, ..., 9-10
        for score in cvss_v3_scores:
            if score is not None:
                index = min(10, int(score))
                cvss_ranges[index] += 1
        
        # Get severity trend by year
        yearly_data = {}
        all_cves = session.query(CVE_Model).filter(CVE_Model.published_date.isnot(None)).all()
        
        for cve in all_cves:
            if not cve.published_date:
                continue
                
            year = cve.published_date.year
            severity = (cve.severity or 'UNKNOWN').upper()
            
            if year not in yearly_data:
                yearly_data[year] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
            
            if severity in yearly_data[year]:
                yearly_data[year][severity] += 1
        
        # Sort years and prepare data for chart
        years = sorted(yearly_data.keys())
        
        # Extract data series for each severity
        critical_series = [yearly_data[year]["CRITICAL"] for year in years]
        high_series = [yearly_data[year]["HIGH"] for year in years]
        medium_series = [yearly_data[year]["MEDIUM"] for year in years]
        low_series = [yearly_data[year]["LOW"] for year in years]
        unknown_series = [yearly_data[year]["UNKNOWN"] for year in years]
        
        return render_template('severity_distribution.html',
                              severity_counts=severity_map,
                              severity_percents=severity_percents,
                              total_cves=total_cves,
                              cvss_ranges=cvss_ranges,
                              years=years,
                              critical_series=critical_series,
                              high_series=high_series,
                              medium_series=medium_series,
                              low_series=low_series,
                              unknown_series=unknown_series)
    
    except Exception as e:
        logging.error(f"Error generating severity distribution page: {e}")
        return render_template('error.html', error=f"An error occurred: {e}")

@app.route('/vendor_analysis')
def vendor_analysis():
    """Display vendor analysis summary"""
    try:
        if CVE_Model is None:
            return render_template('error.html', error="Database model not initialized. Please update the database first.")
        
        engine = create_local_cve_db()
        Session = sessionmaker(bind=engine)
        session = Session()
        
        # Get top vendors
        vendor_list = get_vendor_data(session)
        top_vendors = vendor_list[:10]  # Get top 10 vendors
        
        # Prepare data for top vendor chart
        vendor_names = [v['name'] for v in top_vendors]
        vendor_cve_counts = [v['cve_count'] for v in top_vendors]
        
        # Get severity distribution across all vendors
        total_critical = sum(v['critical'] for v in vendor_list)
        total_high = sum(v['high'] for v in vendor_list)
        total_medium = sum(v['medium'] for v in vendor_list)
        total_low = sum(v['low'] for v in vendor_list)
        total_unknown = sum(v['unknown'] for v in vendor_list)
        
        # Get vendors with most critical vulnerabilities
        critical_vendors = sorted(vendor_list, key=lambda x: x['critical'], reverse=True)[:5]
        critical_vendor_names = [v['name'] for v in critical_vendors]
        critical_vendor_counts = [v['critical'] for v in critical_vendors]
        
        # Vendor diversity metrics - how many vendors have vulnerabilities
        vendor_count = len(vendor_list)
        vendors_with_critical = sum(1 for v in vendor_list if v['critical'] > 0)
        vendors_with_high = sum(1 for v in vendor_list if v['high'] > 0)
        
        return render_template('vendor_analysis.html',
                              vendor_count=vendor_count,
                              top_vendors=top_vendors,
                              vendor_names=vendor_names,
                              vendor_cve_counts=vendor_cve_counts,
                              total_critical=total_critical,
                              total_high=total_high,
                              total_medium=total_medium,
                              total_low=total_low,
                              total_unknown=total_unknown,
                              critical_vendor_names=critical_vendor_names,
                              critical_vendor_counts=critical_vendor_counts,
                              vendors_with_critical=vendors_with_critical,
                              vendors_with_high=vendors_with_high)
    
    except Exception as e:
        logging.error(f"Error generating vendor analysis page: {e}")
        return render_template('error.html', error=f"An error occurred: {e}")

# Run the application
if __name__ == '__main__':
    # Initialize the database when the app starts
    with app.app_context():
        # Only create the table if CVE_Model is None
        if CVE_Model is None:
            engine = create_local_cve_db()
            CVE_Model = create_cve_table(engine)

    # Run the application
    app.run(debug=True, host='0.0.0.0', port=8080)
    # Note: Use host='0.0.0.0' for external access, change to 'localhost' for local access only
