# Community Connect

## Overview

Community Connect is a Flask-based web application designed to bring elderly community members together through social events, recreational activities, and educational opportunities. The platform serves three distinct user types: community members (elderly users), event organizers, and volunteers, creating a comprehensive ecosystem for community engagement.

### Current Status (July 30, 2025)
- ✅ Enhanced registration system with NRIC validation for elderly users
- ✅ Three distinct user roles with different registration flows:
  - **Elderly**: NRIC, full name, language preference, event interests, 3 security questions (2FA)
  - **Organizers**: Name, email, phone for event management
  - **Volunteers**: Name, email, phone for volunteering opportunities
- ✅ Language preferences: English, Mandarin, Malay, Tamil, Hokkien, Cantonese
- ✅ Event interest categories: Social, Recreational, Educational, Cultural, Health & Wellness
- ✅ Security questions system for elderly users (stored for password recovery)
- ✅ NRIC-based login for elderly users
- ✅ Email-based 2FA login for organizers and volunteers:
  * Secure email verification with 6-digit codes
  * 10-minute code expiration for security
  * Beautiful HTML email templates with branding
  * Login success notifications
  * Resend verification functionality
- ✅ PostgreSQL database with updated schema
- ✅ Dynamic registration form with conditional fields
- ✅ Comprehensive profile management for elderly users:
  - Profile picture upload and management
  - Edit personal information (name, language, interests)
  - Change password functionality
  - Secure security questions management with multi-layer protection:
    * Initial 2FA verification using existing security question
    * Password confirmation for final verification
    * Failed attempt protection (3 attempts max)
    * Session-based security verification
- ✅ Elderly-friendly light theme with enhanced readability:
  * High contrast colors and larger fonts
  * White backgrounds with dark text for better visibility
  * Enhanced button sizing and spacing
  * Improved form styling with clear borders
- 🚀 Application is running with enhanced elderly-focused features

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Backend Architecture
- **Framework**: Flask with SQLAlchemy ORM
- **Database**: SQLite for development (configurable via DATABASE_URL environment variable)
- **Authentication**: Flask-Login for session management
- **Forms**: Flask-WTF with WTForms for form handling and validation
- **Security**: Werkzeug for password hashing and proxy handling

### Frontend Architecture
- **Template Engine**: Jinja2 templates with Bootstrap 5 dark theme
- **UI Framework**: Bootstrap with custom CSS for accessibility
- **Icons**: Font Awesome for consistent iconography
- **Responsive Design**: Mobile-first approach with large, accessible UI elements

### Database Schema
The application uses four main models:
- **User**: Handles authentication and user profiles with role-based types (elderly, organizer, volunteer)
- **Event**: Stores event information including metadata, scheduling, and capacity limits
- **EventRSVP**: Manages event registrations for community members
- **VolunteerApplication**: Tracks volunteer applications for events

## Key Components

### User Management
- Role-based user system with three distinct types
- Secure password hashing using Werkzeug
- Profile management with contact information
- Session-based authentication with Flask-Login

### Event Management
- Full CRUD operations for events
- Categorization system (social, recreational, educational)
- RSVP functionality for community members
- Volunteer application system
- Capacity management and participant tracking

### Forms and Validation
- Comprehensive form validation using WTForms
- Custom styling for accessibility (large buttons, clear labels)
- Bootstrap integration for consistent UI
- Error handling and user feedback

### Templates and UI
- Modular template system with base layout
- Accessibility-focused design with large fonts and buttons
- Dark theme implementation for better readability
- Mobile-responsive design principles

## Data Flow

1. **User Registration**: New users select their role (elderly, organizer, volunteer) and complete profile setup
2. **Event Creation**: Organizers create events with details, scheduling, and volunteer requirements
3. **Event Discovery**: Community members browse and search events by category and date
4. **Registration Process**: Users can RSVP for events or apply to volunteer
5. **Profile Management**: Users can view their registered events, organized events, or volunteer applications

## External Dependencies

### Python Packages
- Flask: Web framework and core functionality
- Flask-SQLAlchemy: Database ORM and management
- Flask-Login: User session management
- Flask-WTF: Form handling and CSRF protection
- WTForms: Form validation and rendering
- Werkzeug: WSGI utilities and security features

### Frontend Assets
- Bootstrap 5: UI framework with dark theme variant
- Font Awesome 6: Icon library for consistent visual elements
- Custom CSS: Accessibility enhancements and responsive design

### Environment Configuration
- SESSION_SECRET: Session encryption key
- DATABASE_URL: Database connection string (defaults to SQLite)

## Deployment Strategy

The application is designed for simple deployment with minimal configuration:

### Development Setup
- SQLite database for local development
- Environment-based configuration
- Debug logging enabled
- Hot reloading for template and static file changes

### Production Considerations
- Configurable database URL for PostgreSQL migration
- Proxy-aware configuration for reverse proxy deployments
- Session secret management through environment variables
- Connection pooling and database optimization settings

### File Structure
- `app.py`: Application factory and configuration
- `models.py`: Database models and relationships
- `routes.py`: Blueprint-based route organization
- `forms.py`: Form definitions and validation
- `templates/`: Jinja2 templates with component organization
- `static/`: CSS and static assets
- `main.py`: Application entry point

The architecture prioritizes simplicity, accessibility, and maintainability while providing a robust foundation for community engagement features.