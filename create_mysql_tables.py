#!/usr/bin/env python3
"""
Create MySQL tables using SQLAlchemy (when MySQL connection works)
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
        
        print("Creating database tables...")
        db.create_all()
        print("Tables created successfully!")
        
        # List tables
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        print(f"Created tables: {', '.join(tables)}")
        
        return True

if __name__ == "__main__":
    try:
        create_tables()
        print("Database setup completed!")
    except Exception as e:
        print(f"Error: {e}")
        print("Make sure MySQL is running and credentials are correct")
