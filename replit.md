# Community Connect

## Overview
Community Connect is a Flask-based web application designed to foster community engagement among elderly individuals by connecting them with social events, recreational activities, and educational opportunities. The platform supports three distinct user types: community members (elderly users), event organizers, and volunteers, aiming to create a comprehensive ecosystem for interaction and participation. The vision is to enhance the social well-being of the elderly population by providing an accessible and user-friendly platform for various community activities, offering a significant market potential in elder care and community services.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### UI/UX Decisions
The application features an elderly-friendly light theme designed for enhanced readability, utilizing high-contrast colors, larger fonts, white backgrounds with dark text, and improved button sizing and spacing. The design emphasizes accessibility, with a mobile-first approach and large, accessible UI elements. Jinja2 templates with Bootstrap 5 are used, along with Font Awesome for consistent iconography.

### Technical Implementations
The backend is built with Flask and SQLAlchemy ORM, using PostgreSQL for the production database. Authentication is managed via Flask-Login, and forms are handled by Flask-WTF with WTForms for robust validation. 

**Comprehensive Security System**: All security features are consolidated in `comprehensive_security_system.py` for easy code walkthrough, including:
- Multi-Factor Authentication (2FA) with email-based verification
- Role-Based Access Control (RBAC) with fine-grained permissions
- Session Security with integrity validation and hijacking protection
- Data Encryption (AES-256) for sensitive data like NRIC and phone numbers
- Security Middleware with rate limiting and attack detection
- OWASP Top 10 protection with comprehensive logging and monitoring

The system implements enterprise-grade security preventing broken access control, cryptographic failures, injection attacks, and other common vulnerabilities. Role-specific homepage experiences are provided for elderly users, volunteers, and organizers, along with a complete admin system for database and user management.

### Feature Specifications
The application supports a role-based user system with distinct flows for elderly, organizers, and volunteers. It includes dynamic registration, comprehensive profile management (including profile picture uploads and secure password/security question management), and personalized email notifications. Event management features include full CRUD operations for events, an approval workflow for events, RSVP functionality for community members, and a volunteer application system with capacity management. The admin system allows for user management, event approval/rejection, and account termination with data cascade deletion.

### System Design Choices
The architecture prioritizes simplicity, accessibility, and maintainability. It employs a modular template system, secure session management, and robust input validation. The application is designed for easy deployment, with configurable database settings and environment-based configuration.

## External Dependencies

### Python Packages
- Flask
- Flask-SQLAlchemy
- Flask-Login
- Flask-WTF
- WTForms
- Werkzeug

### Frontend Assets
- Bootstrap 5
- Font Awesome 6
- Custom CSS

### Environment Configuration
- SESSION_SECRET
- DATABASE_URL (defaults to SQLite for development, configured for PostgreSQL in production)