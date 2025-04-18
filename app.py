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
    severity_counts = {} # Initialize severity counts

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

            # Redirect to GET request with search parameters to avoid form resubmission issues
            return redirect(url_for('index', search_term=search_term, exploitable=exploitable_only, search_performed=True))

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

            # Filter by exploitable if requested
            # This filter remains basic, checking for 'exploit' in references.
            # A more robust solution would involve a dedicated flag or better data source.
            if exploitable_only:
                query = query.filter(CVE_Model.references.ilike('%exploit%'))

            # Order results (e.g., by published date descending)
            results = query.order_by(CVE_Model.published_date.desc()).all()

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
                          severity_counts=severity_counts, # Pass severity counts
                          total_cve_count=total_cve_count) # Pass total count

@app.route('/view_all')
def view_all_entries():
    """Display all CVEs in the database, with sorting options"""
    sort_by = request.args.get('sort', 'published_desc') # Default sort
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

        # Consider adding pagination for large datasets later
        results = query.all()

        # Use the index template to display results, passing the sort parameter
        return render_template('index.html',
                              results=results,
                              search_term='All Database Entries',
                              search_performed=True, # Flag to show the results section
                              sort_by=sort_by, # Pass current sort order
                              is_view_all=True, # Flag to distinguish from search
                              severity_counts=severity_counts, # Add severity counts
                              total_cve_count=total_cve_count) # Add total count

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
