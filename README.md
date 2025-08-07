# Community Connect - Elderly Joy

A secure Flask web application for community connections with enhanced security features.

## Setup Instructions

1. **Install Python 3.11+**

2. **Create and activate virtual environment:**
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # On Windows
   ```

3. **Install dependencies:**
   ```bash
   pip install -e .
   ```

4. **Set up environment variables:**
   - Copy `.env.example` to `.env` (if available)
   - Or create a `.env` file with required variables:
     ```
     SESSION_SECRET=your-super-secure-session-secret-key
     DATABASE_URL=sqlite:///community_connect.db
     GMAIL_APP_PASSWORD=your-gmail-app-password
     ENCRYPTION_KEY=your-encryption-key
     ```

5. **Run the application:**
   ```bash
   python app.py
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
