import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'hardening_project.settings')
django.setup()

from django.db import connection
from hardening_app.models import HardeningRule, UserProgress

def seed_db():
    print("[-] Seeding database from populate_rules.sql...")
    
    # Read the SQL file
    sql_file_path = os.path.join(os.path.dirname(__file__), 'populate_rules.sql')
    with open(sql_file_path, 'r', encoding='utf-8') as f:
        sql_script = f.read()
    
    # SQLite connections support executing multiple statements via executescript
    connection.ensure_connection()
    raw_conn = connection.connection
    cursor = raw_conn.cursor()
    try:
        cursor.executescript(sql_script)
        raw_conn.commit()
        print("[+] Raw SQL statements executed successfully.")
    except Exception as e:
        print(f"[!] Error executing SQL: {e}")
        raw_conn.rollback()
        return

    # Check that rules were successfully inserted
    rules = HardeningRule.objects.all()
    print(f"[+] Total HardeningRule rows in database: {rules.count()}")
    
    print("[+] Database seeding complete. UserProgress will be initialized dynamically on client logins.")

if __name__ == '__main__':
    seed_db()
