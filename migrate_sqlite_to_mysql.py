#!/usr/bin/env python3
"""
SQLite to MySQL Migration Script for Community Connect
This script migrates all data from your existing SQLite database to MySQL
"""

import os
import sys
from datetime import datetime
from flask import Flask
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import json

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from extensions import db
from models import User, Event, EventRSVP, VolunteerApplication, EmailVerification, RewardVoucher, UserReward

def create_app_with_db(database_url):
    """Create Flask app with specific database URL"""
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
        "echo": False,
    }
    
    db.init_app(app)
    return app

def migrate_data():
    """Migrate data from SQLite to MySQL"""
    
    print("🔄 SQLite to MySQL Migration Tool")
    print("=" * 50)
    
    # Database URLs
    sqlite_url = "sqlite:///instance/community_connect.db"
    mysql_url = "mysql+pymysql://root:SYL12345@localhost:3306/community_connect"
    
    print(f"📤 Source (SQLite): {sqlite_url}")
    print(f"📥 Target (MySQL): {mysql_url}")
    
    # Check if SQLite database exists
    if not os.path.exists("instance/community_connect.db"):
        print("❌ SQLite database not found!")
        print("💡 Make sure 'instance/community_connect.db' exists")
        return False
    
    try:
        # Create Flask apps for both databases
        print("\n🔗 Connecting to databases...")
        
        # SQLite connection
        sqlite_app = create_app_with_db(sqlite_url)
        
        # MySQL connection
        mysql_app = create_app_with_db(mysql_url)
        
        # Test MySQL connection first
        print("🧪 Testing MySQL connection...")
        with mysql_app.app_context():
            # Try to connect to MySQL system database first
            mysql_system_url = "mysql+pymysql://root:SYL12345@localhost:3306/mysql"
            system_app = create_app_with_db(mysql_system_url)
            
            with system_app.app_context():
                db.session.execute(text("SELECT 1"))
                print("✅ MySQL connection successful!")
                
                # Create database if it doesn't exist
                print("🏗️  Creating MySQL database if needed...")
                db.session.execute(text("CREATE DATABASE IF NOT EXISTS community_connect CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"))
                db.session.commit()
                print("✅ MySQL database ready!")
        
        # Create tables in MySQL
        print("🔧 Creating MySQL tables...")
        with mysql_app.app_context():
            # Import models to register them
            import models
            db.create_all()
            print("✅ MySQL tables created!")
        
        # Start migration
        print("\n📊 Starting data migration...")
        migration_stats = {
            'users': 0,
            'events': 0,
            'rsvps': 0,
            'applications': 0,
            'verifications': 0,
            'vouchers': 0,
            'rewards': 0
        }
        
        # Migrate Users
        print("👥 Migrating users...")
        with sqlite_app.app_context():
            sqlite_users = User.query.all()
            migration_stats['users'] = len(sqlite_users)
            
            user_data = []
            for user in sqlite_users:
                user_dict = {
                    'id': user.id,
                    'nric': user.nric,
                    'full_name': user.full_name,
                    'language_preference': user.language_preference,
                    'event_interests': user.event_interests,
                    'security_q1': user.security_q1,
                    'security_a1': user.security_a1,
                    'security_q2': user.security_q2,
                    'security_a2': user.security_a2,
                    'security_q3': user.security_q3,
                    'security_a3': user.security_a3,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'phone': user.phone,
                    'password_hash': user.password_hash,
                    'user_type': user.user_type,
                    'profile_picture': user.profile_picture,
                    'created_at': user.created_at,
                    'reward_points': user.reward_points,
                    'email_verified': user.email_verified,
                    'two_factor_enabled': user.two_factor_enabled,
                    'account_active': user.account_active
                }
                user_data.append(user_dict)
        
        # Insert users into MySQL
        with mysql_app.app_context():
            for user_dict in user_data:
                # Create new user object
                new_user = User()
                for key, value in user_dict.items():
                    if hasattr(new_user, key):
                        setattr(new_user, key, value)
                
                db.session.add(new_user)
            
            try:
                db.session.commit()
                print(f"✅ Migrated {migration_stats['users']} users")
            except Exception as e:
                print(f"⚠️  User migration warning: {e}")
                db.session.rollback()
        
        # Migrate Events
        print("📅 Migrating events...")
        with sqlite_app.app_context():
            sqlite_events = Event.query.all()
            migration_stats['events'] = len(sqlite_events)
            
            event_data = []
            for event in sqlite_events:
                event_dict = {
                    'id': event.id,
                    'title': event.title,
                    'description': event.description,
                    'category': event.category,
                    'date': event.date,
                    'duration_hours': event.duration_hours,
                    'location': event.location,
                    'max_participants': event.max_participants,
                    'volunteers_needed': event.volunteers_needed,
                    'organizer_id': event.organizer_id,
                    'status': event.status,
                    'reward_points': event.reward_points,
                    'created_at': event.created_at
                }
                event_data.append(event_dict)
        
        with mysql_app.app_context():
            for event_dict in event_data:
                new_event = Event()
                for key, value in event_dict.items():
                    if hasattr(new_event, key):
                        setattr(new_event, key, value)
                
                db.session.add(new_event)
            
            try:
                db.session.commit()
                print(f"✅ Migrated {migration_stats['events']} events")
            except Exception as e:
                print(f"⚠️  Event migration warning: {e}")
                db.session.rollback()
        
        # Migrate other tables (RSVPs, Applications, etc.)
        print("📝 Migrating RSVPs...")
        with sqlite_app.app_context():
            sqlite_rsvps = EventRSVP.query.all()
            migration_stats['rsvps'] = len(sqlite_rsvps)
            
        with mysql_app.app_context():
            for rsvp in sqlite_rsvps:
                new_rsvp = EventRSVP(
                    id=rsvp.id,
                    event_id=rsvp.event_id,
                    user_id=rsvp.user_id,
                    status=rsvp.status,
                    rsvp_date=rsvp.rsvp_date,
                    attendance_confirmed=rsvp.attendance_confirmed,
                    points_awarded=rsvp.points_awarded
                )
                db.session.add(new_rsvp)
            
            try:
                db.session.commit()
                print(f"✅ Migrated {migration_stats['rsvps']} RSVPs")
            except Exception as e:
                print(f"⚠️  RSVP migration warning: {e}")
                db.session.rollback()
        
        # Continue with other tables...
        print("🙋 Migrating volunteer applications...")
        with sqlite_app.app_context():
            sqlite_apps = VolunteerApplication.query.all()
            migration_stats['applications'] = len(sqlite_apps)
            
        with mysql_app.app_context():
            for app in sqlite_apps:
                new_app = VolunteerApplication(
                    id=app.id,
                    event_id=app.event_id,
                    volunteer_id=app.volunteer_id,
                    application_text=app.application_text,
                    status=app.status,
                    applied_at=app.applied_at,
                    reviewed_at=app.reviewed_at,
                    reviewer_id=app.reviewer_id
                )
                db.session.add(new_app)
            
            try:
                db.session.commit()
                print(f"✅ Migrated {migration_stats['applications']} applications")
            except Exception as e:
                print(f"⚠️  Application migration warning: {e}")
                db.session.rollback()
        
        # Print migration summary
        print("\n🎉 Migration Summary:")
        print("=" * 30)
        for table, count in migration_stats.items():
            print(f"📊 {table.title()}: {count} records")
        
        total_records = sum(migration_stats.values())
        print(f"📈 Total Records: {total_records}")
        
        if total_records > 0:
            print("\n✅ Migration completed successfully!")
            print("🎯 Your MySQL database now contains all your SQLite data!")
            
            # Backup original SQLite file
            import shutil
            backup_name = f"community_connect_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
            shutil.copy("instance/community_connect.db", f"instance/{backup_name}")
            print(f"💾 SQLite backup saved as: instance/{backup_name}")
            
        else:
            print("\n⚠️  No data found to migrate!")
            print("💡 Your SQLite database might be empty")
        
        print("\n🚀 Next Steps:")
        print("1. 🔍 Verify data: python -c \"from app import app, db; app.app_context().push(); from models import User; print(f'Users in MySQL: {User.query.count()}')\"")
        print("2. 👨‍💼 Create admin if needed: python create_admin.py")
        print("3. 🌐 Start your app: python app.py")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        print("\n🔧 Troubleshooting:")
        print("• Make sure MySQL server is running")
        print("• Verify MySQL credentials in .env file")
        print("• Check if community_connect database exists")
        print("• Try: python create_mysql_tables.py")
        return False

if __name__ == "__main__":
    migrate_data()
