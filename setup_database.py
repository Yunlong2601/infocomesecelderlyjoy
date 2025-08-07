#!/usr/bin/env python3
"""
Database Setup and Configuration Script
This script provides comprehensive database setup options for the Community Connect application.
Supports SQLite, MySQL, and PostgreSQL databases.
"""

import os
import sys
import subprocess
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask
from extensions import db
import models  # Import all models to ensure they're registered

def create_app(database_url=None):
    """Create and configure the Flask app for database operations."""
    app = Flask(__name__)
    
    # Use provided database URL or default from environment
    db_url = database_url or os.environ.get("DATABASE_URL", "sqlite:///community_connect.db")
    
    # Configure the database
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
        "echo": False,
        "pool_timeout": 20,
        "max_overflow": 0,
    }
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    
    # Initialize database with app
    db.init_app(app)
    
    return app

def setup_sqlite_database():
    """Setup SQLite database (recommended for development)."""
    print("🗄️  Setting up SQLite Database...")
    print("=" * 50)
    
    db_path = "community_connect.db"
    
    try:
        app = create_app("sqlite:///community_connect.db")
        
        with app.app_context():
            # Create all tables
            print("🔧 Creating database tables...")
            db.create_all()
            
            print("✅ SQLite database setup completed!")
            print(f"📁 Database file: {os.path.abspath(db_path)}")
            print("🎯 Database URL: sqlite:///community_connect.db")
            
        return True, "sqlite:///community_connect.db"
        
    except Exception as e:
        print(f"❌ SQLite setup failed: {str(e)}")
        return False, None

def setup_mysql_database():
    """Setup MySQL database with comprehensive configuration."""
    print("🐬 Setting up MySQL Database...")
    print("=" * 50)
    
    # Get MySQL connection details
    print("📝 Please provide MySQL connection details:")
    mysql_host = input("🌐 MySQL Host (default: localhost): ").strip() or "localhost"
    mysql_port = input("🔌 MySQL Port (default: 3306): ").strip() or "3306"
    mysql_user = input("👤 MySQL Username (default: root): ").strip() or "root"
    mysql_password = input("🔐 MySQL Password: ").strip()
    mysql_db_name = input("🗄️  Database Name (default: community_connect): ").strip() or "community_connect"
    
    # Construct database URLs
    mysql_url_without_db = f"mysql+pymysql://{mysql_user}:{mysql_password}@{mysql_host}:{mysql_port}"
    mysql_url_with_db = f"{mysql_url_without_db}/{mysql_db_name}"
    
    try:
        # Test connection without database first
        print("\n🔍 Testing MySQL connection...")
        test_app = create_app(mysql_url_without_db + "/mysql")  # Connect to mysql system database
        
        with test_app.app_context():
            # Test connection
            db.session.execute(db.text("SELECT 1"))
            print("✅ MySQL connection successful!")
        
        # Create database if it doesn't exist
        print(f"🏗️  Creating database '{mysql_db_name}' if it doesn't exist...")
        with test_app.app_context():
            db.session.execute(db.text(f"CREATE DATABASE IF NOT EXISTS `{mysql_db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"))
            db.session.commit()
            print(f"✅ Database '{mysql_db_name}' created successfully!")
        
        # Now connect to the specific database and create tables
        print("🔧 Creating application tables...")
        app = create_app(mysql_url_with_db)
        
        with app.app_context():
            # Create all tables
            db.create_all()
            print("✅ All tables created successfully!")
        
        print("\n🎉 MySQL database setup completed!")
        print(f"🌐 Host: {mysql_host}:{mysql_port}")
        print(f"🗄️  Database: {mysql_db_name}")
        print(f"👤 User: {mysql_user}")
        print(f"🎯 Database URL: {mysql_url_with_db}")
        
        # Update .env file
        update_env_file("DATABASE_URL", mysql_url_with_db)
        
        return True, mysql_url_with_db
        
    except Exception as e:
        print(f"❌ MySQL setup failed: {str(e)}")
        print("\n💡 Troubleshooting tips:")
        print("  • Make sure MySQL server is running")
        print("  • Check username and password")
        print("  • Ensure PyMySQL is installed: pip install pymysql")
        print("  • Check firewall settings")
        return False, None

def setup_postgresql_database():
    """Setup PostgreSQL database."""
    print("🐘 Setting up PostgreSQL Database...")
    print("=" * 50)
    
    # Get PostgreSQL connection details
    print("📝 Please provide PostgreSQL connection details:")
    pg_host = input("🌐 PostgreSQL Host (default: localhost): ").strip() or "localhost"
    pg_port = input("🔌 PostgreSQL Port (default: 5432): ").strip() or "5432"
    pg_user = input("👤 PostgreSQL Username (default: postgres): ").strip() or "postgres"
    pg_password = input("🔐 PostgreSQL Password: ").strip()
    pg_db_name = input("🗄️  Database Name (default: community_connect): ").strip() or "community_connect"
    
    # Construct database URLs
    pg_url_without_db = f"postgresql://{pg_user}:{pg_password}@{pg_host}:{pg_port}"
    pg_url_with_db = f"{pg_url_without_db}/{pg_db_name}"
    
    try:
        # Test connection with postgres system database first
        print("\n🔍 Testing PostgreSQL connection...")
        test_app = create_app(pg_url_without_db + "/postgres")
        
        with test_app.app_context():
            # Test connection
            db.session.execute(db.text("SELECT 1"))
            print("✅ PostgreSQL connection successful!")
        
        # Create database if it doesn't exist
        print(f"🏗️  Creating database '{pg_db_name}' if it doesn't exist...")
        with test_app.app_context():
            # Check if database exists
            result = db.session.execute(
                db.text("SELECT 1 FROM pg_catalog.pg_database WHERE datname = :dbname"), 
                {"dbname": pg_db_name}
            )
            if not result.fetchone():
                db.session.execute(db.text(f'CREATE DATABASE "{pg_db_name}"'))
                db.session.commit()
                print(f"✅ Database '{pg_db_name}' created successfully!")
            else:
                print(f"ℹ️  Database '{pg_db_name}' already exists.")
        
        # Now connect to the specific database and create tables
        print("🔧 Creating application tables...")
        app = create_app(pg_url_with_db)
        
        with app.app_context():
            # Create all tables
            db.create_all()
            print("✅ All tables created successfully!")
        
        print("\n🎉 PostgreSQL database setup completed!")
        print(f"🌐 Host: {pg_host}:{pg_port}")
        print(f"🗄️  Database: {pg_db_name}")
        print(f"👤 User: {pg_user}")
        print(f"🎯 Database URL: {pg_url_with_db}")
        
        # Update .env file
        update_env_file("DATABASE_URL", pg_url_with_db)
        
        return True, pg_url_with_db
        
    except Exception as e:
        print(f"❌ PostgreSQL setup failed: {str(e)}")
        print("\n💡 Troubleshooting tips:")
        print("  • Make sure PostgreSQL server is running")
        print("  • Check username and password")
        print("  • Ensure psycopg2 is installed: pip install psycopg2-binary")
        print("  • Check pg_hba.conf for authentication settings")
        return False, None

def update_env_file(key, value):
    """Update a key-value pair in the .env file."""
    env_path = ".env"
    
    try:
        # Read existing .env file
        lines = []
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                lines = f.readlines()
        
        # Update or add the key
        key_found = False
        for i, line in enumerate(lines):
            if line.strip().startswith(f"{key}="):
                lines[i] = f"{key}={value}\n"
                key_found = True
                break
        
        if not key_found:
            lines.append(f"{key}={value}\n")
        
        # Write back to .env file
        with open(env_path, 'w') as f:
            f.writelines(lines)
        
        print(f"✅ Updated .env file with {key}")
        
    except Exception as e:
        print(f"⚠️  Could not update .env file: {str(e)}")

def list_database_tables(database_url):
    """List all tables in the database."""
    try:
        app = create_app(database_url)
        
        with app.app_context():
            # Get table names
            inspector = db.inspect(db.engine)
            tables = inspector.get_table_names()
            
            if tables:
                print("\n📊 Database Tables:")
                for table in sorted(tables):
                    # Get row count
                    try:
                        result = db.session.execute(db.text(f"SELECT COUNT(*) FROM {table}"))
                        count = result.scalar()
                        print(f"  📋 {table}: {count} records")
                    except:
                        print(f"  📋 {table}: [could not count]")
            else:
                print("\n📊 No tables found in database.")
        
    except Exception as e:
        print(f"❌ Could not list tables: {str(e)}")

def main():
    """Main database setup function."""
    print("🏗️  Community Connect Database Setup")
    print("=" * 60)
    
    print("\n📚 Available Database Options:")
    print("1. 🗄️  SQLite (Recommended for development)")
    print("2. 🐬 MySQL (Production ready)")
    print("3. 🐘 PostgreSQL (Advanced features)")
    print("4. 📊 Show current database info")
    print("5. 🧹 Reset current database")
    
    choice = input("\n❓ Select an option (1-5): ").strip()
    
    if choice == "1":
        success, db_url = setup_sqlite_database()
        if success:
            list_database_tables(db_url)
    
    elif choice == "2":
        success, db_url = setup_mysql_database()
        if success:
            list_database_tables(db_url)
    
    elif choice == "3":
        success, db_url = setup_postgresql_database()
        if success:
            list_database_tables(db_url)
    
    elif choice == "4":
        current_url = os.environ.get("DATABASE_URL", "Not configured")
        print(f"\n📊 Current Database URL: {current_url}")
        if current_url != "Not configured":
            list_database_tables(current_url)
    
    elif choice == "5":
        print("\n🧹 Resetting current database...")
        current_url = os.environ.get("DATABASE_URL")
        if current_url:
            try:
                app = create_app(current_url)
                with app.app_context():
                    db.drop_all()
                    db.create_all()
                    print("✅ Database reset completed!")
                    list_database_tables(current_url)
            except Exception as e:
                print(f"❌ Reset failed: {str(e)}")
        else:
            print("❌ No database configured!")
    
    else:
        print("❌ Invalid choice!")
        return
    
    print("\n" + "=" * 60)
    print("🎉 Database setup process completed!")

if __name__ == "__main__":
    main()
