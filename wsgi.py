import sys
import os

# Add your project directory to the Python path
path = '/home/YOUR_USERNAME/domain_checker_new'  # Replace YOUR_USERNAME with your actual PythonAnywhere username
if path not in sys.path:
    sys.path.append(path)

# Set environment variables
os.environ['PYTHONANYWHERE_SITE'] = 'True'

# Import your Flask app
from app import app as application 