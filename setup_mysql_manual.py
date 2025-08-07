"""
Alternative MySQL Setup - Creates database without live connection test
This approach updates your configuration and provides SQL scripts to run manually
"""

import os
import shutil

print("🔄 Alternative MySQL Setup for Community Connect")
print("=" * 60)

print("\n📝 Your .env file has been updated with MySQL configuration:")
print("DATABASE_URL=mysql+pymysql://root:SYL12345@localhost:3306/community_connect")

print("\n🏗️  Manual Database Creation (if connection test fails):")
print("=" * 60)

print("\n📋 Step 1: Create Database Manually")
print("-" * 40)
print("If you have MySQL running, you can create the database manually:")
print("1. 🌐 Open MySQL Workbench or command line")
print("2. 🏗️  Run: CREATE DATABASE community_connect;")
print("3. ✅ Verify: SHOW DATABASES; (should see community_connect)")

print("\n📋 Step 2: Create Tables Using SQL Script")
print("-" * 40)
print("Use the provided mysql_schema.sql file:")
print("1. 📂 File location: mysql_schema.sql")  
print("2. 💻 In MySQL Workbench: File > Open SQL Script > mysql_schema.sql")
print("3. ⚡ Execute the script")
print("4. ✅ This creates all tables and sample data")

print("\n📋 Step 3: Alternative - Use Python Script")
print("-" * 40)

# Create a simplified table creation script
table_creation_script = '''#!/usr/bin/env python3
"""
Create tables using SQLAlchemy (when MySQL connection works)
"""
import os
import sys
from flask import Flask
from extensions import db

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def create_tables():
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:SYL12345@localhost:3306/community_connect"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    
    db.init_app(app)
    
    with app.app_context():
        # Import all models to register them
        import models
        
        print("🔧 Creating database tables...")
        db.create_all()
        print("✅ Tables created successfully!")
        
        # List tables
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        print(f"📋 Created tables: {', '.join(tables)}")
        
        return True

if __name__ == "__main__":
    try:
        create_tables()
        print("🎉 Database setup completed!")
    except Exception as e:
        print(f"❌ Error: {e}")
        print("💡 Make sure MySQL is running and credentials are correct")
'''

# Write the table creation script
with open("create_mysql_tables.py", "w") as f:
    f.write(table_creation_script)

print("✅ Created: create_mysql_tables.py")

print("\n📋 Step 4: Start Your Application")
print("-" * 40)
print("Once database and tables are ready:")
print("1. 👨‍💼 Create admin user: python create_admin.py")
print("2. 🚀 Start Flask app: python app.py")
print("3. 🌐 Visit: http://localhost:5000")

print("\n🔧 Troubleshooting:")
print("-" * 40)
print("❌ If MySQL connection still fails:")
print("  • Install XAMPP and start MySQL service")
print("  • Use empty password for XAMPP: configure_mysql.py (leave password blank)")
print("  • Check Windows Services for MySQL")
print("  • Try 127.0.0.1 instead of localhost")

print("\n✅ Your current configuration:")
print("  🌐 Host: localhost:3306")
print("  👤 User: root") 
print("  🔐 Password: SYL12345")
print("  🗄️  Database: community_connect")

print("\n🎯 Quick Commands to Try:")
print("1. Test table creation: python create_mysql_tables.py")
print("2. Show current DB: python setup_database.py (option 4)")
print("3. Reset if needed: python reset_database.py")

print("\n" + "=" * 60)
print("🎉 MySQL configuration ready!")
print("📞 Install MySQL server if you haven't already!")
print("=" * 60)
