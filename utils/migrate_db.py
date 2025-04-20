import os
import sqlite3
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def add_exploit_columns():
    """
    Add the exploit-related columns to the existing database
    """
    try:
        db_path = os.path.join(os.path.dirname(__file__), '..', 'cve_database.db')
        logger.info(f"Connecting to database at {db_path}")
        
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if the columns already exist
        cursor.execute("PRAGMA table_info(cves)")
        columns = [column[1] for column in cursor.fetchall()]
        
        # Add has_exploit column if it doesn't exist
        if 'has_exploit' not in columns:
            logger.info("Adding 'has_exploit' column to cves table")
            cursor.execute("ALTER TABLE cves ADD COLUMN has_exploit BOOLEAN DEFAULT 0")
        else:
            logger.info("Column 'has_exploit' already exists in cves table")
        
        # Add exploit_data column if it doesn't exist
        if 'exploit_data' not in columns:
            logger.info("Adding 'exploit_data' column to cves table")
            cursor.execute("ALTER TABLE cves ADD COLUMN exploit_data TEXT")
        else:
            logger.info("Column 'exploit_data' already exists in cves table")
        
        # Commit the changes
        conn.commit()
        conn.close()
        
        logger.info("Database schema update completed successfully")
        return True
    except Exception as e:
        logger.error(f"Error updating database schema: {e}")
        return False

if __name__ == "__main__":
    add_exploit_columns()