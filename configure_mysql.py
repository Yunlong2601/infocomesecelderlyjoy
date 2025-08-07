"""
Quick MySQL Configuration for Community Connect
This script helps you quickly switch from SQLite to MySQL
"""
import os

print("🐬 MySQL Configuration Setup")
print("=" * 50)

print("\n📋 Before we start, make sure you have:")
print("1. ✅ MySQL Server installed and running")
print("2. ✅ MySQL credentials (username/password)")
print("3. ✅ Know your MySQL connection details")

print("\n🔧 Common MySQL Setups:")
print("• XAMPP: Host=localhost, Port=3306, User=root, Password=(empty or set by you)")
print("• MySQL Workbench: Use the connection you created")
print("• Standalone MySQL: Use your installation credentials")

proceed = input("\n❓ Ready to configure MySQL? (yes/no): ").lower().strip()
if proceed != 'yes':
    print("👋 Setup cancelled. Run this script again when ready!")
    exit()

# Get connection details
print("\n📝 Enter your MySQL connection details:")
host = input("🌐 MySQL Host [localhost]: ").strip() or "localhost"
port = input("🔌 MySQL Port [3306]: ").strip() or "3306"
username = input("👤 MySQL Username [root]: ").strip() or "root"
password = input("🔐 MySQL Password: ").strip()
database = input("🗄️  Database Name [community_connect]: ").strip() or "community_connect"

# Create database URL
mysql_url = f"mysql+pymysql://{username}:{password}@{host}:{port}/{database}"

print(f"\n🔗 Generated MySQL URL: {mysql_url}")

# Update .env file
env_path = ".env"
print(f"\n📝 Updating {env_path}...")

try:
    # Read current .env file
    lines = []
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            lines = f.readlines()
    
    # Update or add DATABASE_URL
    updated = False
    for i, line in enumerate(lines):
        if line.strip().startswith("DATABASE_URL="):
            lines[i] = f"DATABASE_URL={mysql_url}\n"
            updated = True
            print(f"✅ Updated existing DATABASE_URL")
            break
    
    if not updated:
        lines.append(f"\n# MySQL Database Configuration\n")
        lines.append(f"DATABASE_URL={mysql_url}\n")
        print(f"✅ Added new DATABASE_URL")
    
    # Write back to .env
    with open(env_path, 'w') as f:
        f.writelines(lines)
    
    print("✅ .env file updated successfully!")
    
    print("\n🎯 Next Steps:")
    print("1. 🔄 Test the connection:")
    print("   python -c \"from extensions import db; from flask import Flask; app = Flask(__name__); app.config['SQLALCHEMY_DATABASE_URI']='" + mysql_url + "'; db.init_app(app); print('Testing...'); app.app_context().push(); db.session.execute(db.text('SELECT 1')); print('✅ MySQL connection works!')\"")
    print("\n2. 🏗️  Create database and tables:")
    print("   python setup_database.py")
    print("\n3. 👨‍💼 Create admin user:")
    print("   python create_admin.py")
    print("\n4. 🚀 Start your application:")
    print("   python app.py")
    
    print(f"\n📊 Configuration Summary:")
    print(f"  🌐 Host: {host}:{port}")
    print(f"  👤 User: {username}")
    print(f"  🗄️  Database: {database}")
    print(f"  🔗 URL: {mysql_url}")
    
except Exception as e:
    print(f"❌ Error updating .env file: {e}")
    print(f"💡 Please manually update your .env file with:")
    print(f"DATABASE_URL={mysql_url}")

print("\n" + "=" * 50)
print("🎉 MySQL configuration completed!")
