"""
WSGI entry point for the Flask application.
This file is used by Gunicorn to start the application.
"""

import os
import sys
import logging
from app import create_app

# Set up logging for production
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

try:
    # Create the Flask application instance
    app = create_app()
    logger.info("Flask application created successfully")
    
    # Ensure the app is properly configured for production
    if not app.config.get('SECRET_KEY'):
        logger.error("SECRET_KEY not configured")
        raise ValueError("SECRET_KEY must be set in environment variables")
    
    if not app.config.get('MONGO_URI'):
        logger.error("MONGO_URI not configured")
        raise ValueError("MONGO_URI must be set in environment variables")
    
    logger.info(f"Application configured for environment: {os.getenv('FLASK_ENV', 'production')}")
    
except Exception as e:
    logger.error(f"Failed to create Flask application: {str(e)}")
    raise

if __name__ == "__main__":
    # This allows running the app directly with python wsgi.py for testing
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
