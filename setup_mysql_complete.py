#!/usr/bin/env python3
"""
Complete MySQL Setup for Community Connect
Creates database and tables step by step
"""

import os
import sys
from flask import Flask
from sqlalchemy import create_engine, text

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from extensions import db

def setup_mysql_complete():
    print("🐬 Complete MySQL Setup for Community Connect")
    print("=" * 60)
    
    # MySQL connection details from .env
    mysql_host = "localhost"
    mysql_port = "3306"
    mysql_user = "root"
    mysql_password = "SYL12345"
    database_name = "community_connect"
    
    print(f"📊 Connection Details:")
    print(f"   🌐 Host: {mysql_host}:{mysql_port}")
    print(f"   👤 User: {mysql_user}")
    print(f"   🗄️  Database: {database_name}")
    
    try:
        # Step 1: Connect to MySQL system database
        print("\n🔗 Step 1: Connecting to MySQL server...")
        mysql_system_url = f"mysql+pymysql://{mysql_user}:{mysql_password}@{mysql_host}:{mysql_port}/mysql"
        
        app = Flask(__name__)
        app.config["SQLALCHEMY_DATABASE_URI"] = mysql_system_url
        app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
        
        db.init_app(app)
        
        with app.app_context():
            # Test connection
            result = db.session.execute(text("SELECT VERSION()"))
            version = result.scalar()
            print(f"✅ Connected to MySQL! Version: {version}")
            
            # Step 2: Create database
            print(f"\n🏗️  Step 2: Creating database '{database_name}'...")
            db.session.execute(text(f"CREATE DATABASE IF NOT EXISTS `{database_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"))
            db.session.commit()
            print(f"✅ Database '{database_name}' created!")
            
            # Verify database exists
            result = db.session.execute(text("SHOW DATABASES"))
            databases = [row[0] for row in result]
            if database_name in databases:
                print(f"✅ Database '{database_name}' confirmed!")
            else:
                print(f"⚠️  Database '{database_name}' not found in database list")
        
        # Step 3: Connect to the new database and create tables
        print(f"\n🔧 Step 3: Creating tables in '{database_name}'...")
        database_url = f"mysql+pymysql://{mysql_user}:{mysql_password}@{mysql_host}:{mysql_port}/{database_name}"
        
        app.config["SQLALCHEMY_DATABASE_URI"] = database_url
        db.init_app(app)
        
        with app.app_context():
            # Import all models to register them
            import models
            
            # Create all tables
            db.create_all()
            print("✅ All tables created successfully!")
            
            # List created tables
            inspector = db.inspect(db.engine)
            tables = inspector.get_table_names()
            print(f"📋 Created {len(tables)} tables:")
            for table in sorted(tables):
                print(f"   📊 {table}")
            
            # Add some sample reward vouchers
            print("\n🎁 Adding sample reward vouchers...")
            from models import RewardVoucher
            
            sample_vouchers = [
                RewardVoucher(
                    title="Coffee Shop Discount",
                    description="10% off at participating coffee shops",
                    points_required=50,
                    value_description="$2 off any coffee purchase",
                    terms_conditions="Valid for 90 days. Cannot be combined with other offers."
                ),
                RewardVoucher(
                    title="Movie Theater Discount",
                    description="$5 off movie ticket",
                    points_required=75,
                    value_description="$5 discount on regular movie ticket",
                    terms_conditions="Valid for 90 days. Valid for regular 2D movies only."
                ),
                RewardVoucher(
                    title="Grocery Store Voucher",
                    description="$10 off grocery shopping",
                    points_required=150,
                    value_description="$10 off grocery purchase of $50 or more",
                    terms_conditions="Valid for 90 days. One-time use only."
                )
            ]
            
            # Check if vouchers already exist
            existing_vouchers = RewardVoucher.query.count()
            if existing_vouchers == 0:
                for voucher in sample_vouchers:
                    db.session.add(voucher)
                db.session.commit()
                print(f"✅ Added {len(sample_vouchers)} sample reward vouchers!")
            else:
                print(f"ℹ️  {existing_vouchers} reward vouchers already exist")
        
        print(f"\n🎉 MySQL Setup Completed Successfully!")
        print("=" * 60)
        print("📊 Database Summary:")
        print(f"   🌐 URL: {database_url}")
        print(f"   📋 Tables: {len(tables)}")
        print(f"   🎁 Rewards: {len(sample_vouchers) if existing_vouchers == 0 else existing_vouchers}")
        
        print("\n🚀 Next Steps:")
        print("1. 👨‍💼 Create admin user: python create_admin.py")
        print("2. 🌐 Start your app: python app.py")
        print("3. 🎯 Access at: http://localhost:5000")
        
        # Test a simple query
        print("\n🧪 Testing database functionality...")
        with app.app_context():
            from models import User, RewardVoucher
            user_count = User.query.count()
            voucher_count = RewardVoucher.query.count()
            print(f"✅ Database queries working! Users: {user_count}, Vouchers: {voucher_count}")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        print("\n🔧 Troubleshooting:")
        
        if "Access denied" in str(e):
            print("🚨 Access denied - Check your MySQL credentials!")
            print("   • Verify username: root")
            print("   • Verify password: SYL12345")
            print("   • Try MySQL Workbench to test connection")
        elif "Can't connect" in str(e):
            print("🚨 Can't connect - MySQL server not running!")
            print("   • Start MySQL service")
            print("   • Check XAMPP Control Panel")
            print("   • Verify port 3306 is available")
        elif "Unknown database" in str(e):
            print("🚨 Database creation failed!")
            print("   • Check MySQL permissions")
            print("   • Try creating database manually in MySQL Workbench")
        else:
            print(f"🚨 General error: {e}")
            print("   • Check MySQL installation")
            print("   • Verify all connection details")
        
        return False

if __name__ == "__main__":
    success = setup_mysql_complete()
    if success:
        print("\n🎉 Your MySQL database is ready to use!")
    else:
        print("\n💡 Please install/start MySQL and try again")
        print("📖 See mysql_install_guide.py for installation help")
