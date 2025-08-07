# Community Connect - Elderly Joy

A secure Flask web application for community connections with enhanced security features.

## Setup Instructions

1. **Install Python 3.11+**

2. **Create and activate virtual environment:**
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  
   ```

3. **Install dependencies:**
   ```bash
   pip install -e .
   ```

4. **Set up database:**
   
   **Option A: MySQL (Recommended for production)**
   - Install MySQL Server and MySQL Workbench
   - Run the setup script: `python setup_mysql.py`
   - Follow the prompts to create the database
   
   **Option B: SQLite (Quick start/development)**
   - No additional setup required
   - Update .env file:
     ```
     DATABASE_URL=sqlite:///community_connect.db
     ```

5. **Set up environment variables:**
   - Copy `.env.example` to `.env` (if available)
   - Or create a `.env` file with required variables:
     ```
     SESSION_SECRET=your-super-secure-session-secret-key
     DATABASE_URL=mysql+pymysql://username:password@localhost:3306/community_connect
     GMAIL_APP_PASSWORD=your-gmail-app-password
     ENCRYPTION_KEY=your-encryption-key
     ```

6. **Initialize the database:**
   ```bash
   python -c "from app import app, db; app.app_context().push(); db.create_all()"
   ```

7. **Run the application:**
   ```bash
   python app.py
   ```

## Database Setup

### MySQL Setup (Recommended)

1. **Install MySQL:**
   - Download MySQL Server from https://dev.mysql.com/downloads/mysql/
   - Install MySQL Workbench from https://dev.mysql.com/downloads/workbench/

2. **Create Database:**
   ```bash
   python setup_mysql.py
   ```
   This script will:
   - Connect to your MySQL server
   - Create the `community_connect` database
   - Optionally create a dedicated app user
   - Update your `.env` file with the correct DATABASE_URL

3. **Using MySQL Workbench:**
   - Open MySQL Workbench
   - Connect to your local MySQL server
   - You can view and manage your `community_connect` database
   - Run queries, view tables, and monitor the application data

### SQLite Setup (Development)

For quick development setup, you can use SQLite:
```
DATABASE_URL=sqlite:///community_connect.db
```

## Security Features

- CSRF protection
- Session security with HTTPOnly and Secure cookies
- Content Security Policy headers
- SQL injection prevention
- XSS protection
- File upload security
- Enhanced logging
- Unified security system

## Important Notes

- Never commit the `.env` file to version control
- Use strong, unique passwords for production
- Enable HTTPS in production
- Regularly update dependencies

## Development

The application runs in debug mode by default. For production deployment, use a WSGI server like Gunicorn.
