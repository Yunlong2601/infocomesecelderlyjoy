#!/usr/bin/env python3
"""
Check SQLite Database Contents
"""
import sqlite3
import os

def check_sqlite_data():
    db_path = "instance/community_connect.db"
    
    if not os.path.exists(db_path):
        print("❌ SQLite database not found at instance/community_connect.db")
        return
    
    print("🔍 Checking SQLite Database Contents...")
    print("=" * 40)
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        print(f"📋 Tables found: {len(tables)}")
        
        total_records = 0
        for table_tuple in tables:
            table = table_tuple[0]
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                print(f"  📊 {table}: {count} records")
                total_records += count
            except Exception as e:
                print(f"  ⚠️  {table}: Could not count ({e})")
        
        print(f"\n📈 Total Records: {total_records}")
        
        if total_records > 0:
            print("\n✅ You have data to migrate!")
            print("🔄 Run: python migrate_sqlite_to_mysql.py")
        else:
            print("\n⚠️  No data found in SQLite database")
            print("💡 You can start fresh with MySQL")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error reading SQLite database: {e}")

if __name__ == "__main__":
    check_sqlite_data()
