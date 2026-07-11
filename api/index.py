import os
import sys

# Add project root to sys.path so Django can find its modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hardening_project.wsgi import application
app = application
