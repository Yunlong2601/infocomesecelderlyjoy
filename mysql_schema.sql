-- Community Connect Database Schema for MySQL
-- This script creates the complete database structure for the Community Connect application

-- Create database if it doesn't exist
CREATE DATABASE IF NOT EXISTS community_connect 
    CHARACTER SET utf8mb4 
    COLLATE utf8mb4_unicode_ci;

-- Use the database
USE community_connect;

-- Create Users table
CREATE TABLE IF NOT EXISTS user (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    
    -- Elderly user fields
    nric VARCHAR(9) UNIQUE NULL COMMENT 'NRIC for elderly users',
    full_name VARCHAR(100) NULL COMMENT 'Full name for elderly users',
    language_preference VARCHAR(20) NULL COMMENT 'Language preference for elderly users',
    event_interests TEXT NULL COMMENT 'JSON string of interests for elderly users',
    
    -- Security questions for 2FA (elderly users)
    security_q1 VARCHAR(100) NULL COMMENT 'Security question 1',
    security_a1 VARCHAR(200) NULL COMMENT 'Hashed security answer 1',
    security_q2 VARCHAR(100) NULL COMMENT 'Security question 2', 
    security_a2 VARCHAR(200) NULL COMMENT 'Hashed security answer 2',
    security_q3 VARCHAR(100) NULL COMMENT 'Security question 3',
    security_a3 VARCHAR(200) NULL COMMENT 'Hashed security answer 3',
    
    -- Organizer/Volunteer fields
    username VARCHAR(64) UNIQUE NULL COMMENT 'Username for organizers/volunteers',
    email VARCHAR(120) UNIQUE NULL COMMENT 'Email for organizers/volunteers',
    first_name VARCHAR(50) NULL COMMENT 'First name for organizers/volunteers',
    last_name VARCHAR(50) NULL COMMENT 'Last name for organizers/volunteers',
    phone VARCHAR(20) NULL COMMENT 'Phone number',
    
    -- Common fields
    password_hash VARCHAR(256) NOT NULL COMMENT 'Hashed password',
    user_type VARCHAR(20) NOT NULL DEFAULT 'elderly' COMMENT 'User type: elderly, organizer, volunteer, admin',
    profile_picture VARCHAR(255) NULL COMMENT 'Path to profile picture',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'Account creation timestamp',
    
    -- Reward system
    reward_points INTEGER DEFAULT 0 COMMENT 'Points earned from participation',
    
    -- Account status
    email_verified BOOLEAN DEFAULT FALSE COMMENT 'Email verification status',
    two_factor_enabled BOOLEAN DEFAULT FALSE COMMENT '2FA enabled status',
    account_active BOOLEAN DEFAULT TRUE COMMENT 'Account active status',
    
    INDEX idx_user_type (user_type),
    INDEX idx_email (email),
    INDEX idx_nric (nric),
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='User accounts table';

-- Create Events table
CREATE TABLE IF NOT EXISTS event (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(100) NOT NULL COMMENT 'Event title',
    description TEXT NULL COMMENT 'Event description',
    category VARCHAR(50) NOT NULL COMMENT 'Event category: social, recreational, educational',
    date DATETIME NOT NULL COMMENT 'Event date and time',
    duration_hours INTEGER DEFAULT 2 COMMENT 'Event duration in hours',
    location VARCHAR(200) NOT NULL COMMENT 'Event location',
    max_participants INTEGER NULL COMMENT 'Maximum number of participants',
    volunteers_needed INTEGER DEFAULT 0 COMMENT 'Number of volunteers needed',
    organizer_id INTEGER NOT NULL COMMENT 'ID of the event organizer',
    status VARCHAR(20) DEFAULT 'pending' COMMENT 'Event status: pending, approved, rejected, cancelled',
    reward_points INTEGER DEFAULT 10 COMMENT 'Points awarded for participation',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'Event creation timestamp',
    
    FOREIGN KEY (organizer_id) REFERENCES user(id) ON DELETE CASCADE,
    INDEX idx_organizer (organizer_id),
    INDEX idx_category (category),
    INDEX idx_date (date),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Events table';

-- Create Event RSVPs table
CREATE TABLE IF NOT EXISTS event_rsvp (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    event_id INTEGER NOT NULL COMMENT 'Event ID',
    user_id INTEGER NOT NULL COMMENT 'User ID',
    status VARCHAR(20) DEFAULT 'attending' COMMENT 'RSVP status: attending, maybe, not_attending',
    rsvp_date DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'RSVP timestamp',
    attendance_confirmed BOOLEAN DEFAULT FALSE COMMENT 'Attendance confirmation',
    points_awarded BOOLEAN DEFAULT FALSE COMMENT 'Whether points have been awarded',
    
    UNIQUE KEY unique_user_event (user_id, event_id),
    FOREIGN KEY (event_id) REFERENCES event(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
    INDEX idx_event (event_id),
    INDEX idx_user (user_id),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Event RSVPs table';

-- Create Volunteer Applications table
CREATE TABLE IF NOT EXISTS volunteer_application (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    event_id INTEGER NOT NULL COMMENT 'Event ID',
    volunteer_id INTEGER NOT NULL COMMENT 'Volunteer user ID',
    application_text TEXT NULL COMMENT 'Volunteer application message',
    status VARCHAR(20) DEFAULT 'pending' COMMENT 'Application status: pending, approved, rejected',
    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'Application timestamp',
    reviewed_at DATETIME NULL COMMENT 'Review timestamp',
    reviewer_id INTEGER NULL COMMENT 'ID of the user who reviewed the application',
    
    UNIQUE KEY unique_volunteer_event (volunteer_id, event_id),
    FOREIGN KEY (event_id) REFERENCES event(id) ON DELETE CASCADE,
    FOREIGN KEY (volunteer_id) REFERENCES user(id) ON DELETE CASCADE,
    FOREIGN KEY (reviewer_id) REFERENCES user(id) ON DELETE SET NULL,
    INDEX idx_event (event_id),
    INDEX idx_volunteer (volunteer_id),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Volunteer applications table';

-- Create Email Verification table
CREATE TABLE IF NOT EXISTS email_verification (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    user_id INTEGER NOT NULL COMMENT 'User ID',
    email VARCHAR(120) NOT NULL COMMENT 'Email to verify',
    token VARCHAR(100) NOT NULL COMMENT 'Verification token',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'Token creation timestamp',
    expires_at DATETIME NOT NULL COMMENT 'Token expiration timestamp',
    verified_at DATETIME NULL COMMENT 'Verification timestamp',
    
    UNIQUE KEY unique_token (token),
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
    INDEX idx_user (user_id),
    INDEX idx_token (token),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Email verification tokens table';

-- Create Reward Vouchers table
CREATE TABLE IF NOT EXISTS reward_voucher (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(100) NOT NULL COMMENT 'Voucher title',
    description TEXT NULL COMMENT 'Voucher description',
    points_required INTEGER NOT NULL COMMENT 'Points required to redeem',
    value_description VARCHAR(200) NULL COMMENT 'Description of voucher value',
    terms_conditions TEXT NULL COMMENT 'Terms and conditions',
    expiry_days INTEGER DEFAULT 90 COMMENT 'Days until voucher expires after redemption',
    quantity_available INTEGER DEFAULT 100 COMMENT 'Available quantity',
    active BOOLEAN DEFAULT TRUE COMMENT 'Whether voucher is currently available',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'Voucher creation timestamp',
    
    INDEX idx_points (points_required),
    INDEX idx_active (active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Available reward vouchers table';

-- Create User Rewards table (redeemed vouchers)
CREATE TABLE IF NOT EXISTS user_reward (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    user_id INTEGER NOT NULL COMMENT 'User ID',
    voucher_id INTEGER NOT NULL COMMENT 'Voucher ID',
    redeemed_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'Redemption timestamp',
    expires_at DATETIME NOT NULL COMMENT 'Voucher expiration timestamp',
    voucher_code VARCHAR(50) NOT NULL COMMENT 'Unique voucher code',
    status VARCHAR(20) DEFAULT 'active' COMMENT 'Voucher status: active, used, expired',
    used_at DATETIME NULL COMMENT 'Usage timestamp',
    
    UNIQUE KEY unique_voucher_code (voucher_code),
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
    FOREIGN KEY (voucher_id) REFERENCES reward_voucher(id) ON DELETE CASCADE,
    INDEX idx_user (user_id),
    INDEX idx_voucher (voucher_id),
    INDEX idx_code (voucher_code),
    INDEX idx_status (status),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='User redeemed rewards table';

-- Insert some sample reward vouchers
INSERT IGNORE INTO reward_voucher (title, description, points_required, value_description, terms_conditions) VALUES
('Coffee Shop Discount', '10% off at participating coffee shops', 50, '$2 off any coffee purchase', 'Valid for 90 days. Cannot be combined with other offers.'),
('Restaurant Meal Voucher', 'Free appetizer at participating restaurants', 100, 'One free appetizer up to $8 value', 'Valid for 90 days. Dine-in only. Cannot be combined with other offers.'),
('Movie Theater Discount', '$5 off movie ticket', 75, '$5 discount on regular movie ticket', 'Valid for 90 days. Valid for regular 2D movies only.'),
('Grocery Store Voucher', '$10 off grocery shopping', 150, '$10 off grocery purchase of $50 or more', 'Valid for 90 days. One-time use only.'),
('Public Transport Pass', 'Free bus rides for a day', 80, 'Unlimited bus rides for one day', 'Valid for 90 days from redemption. Must be activated on day of use.');

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_user_created_at ON user(created_at);
CREATE INDEX IF NOT EXISTS idx_event_created_at ON event(created_at);
CREATE INDEX IF NOT EXISTS idx_rsvp_date ON event_rsvp(rsvp_date);
CREATE INDEX IF NOT EXISTS idx_application_date ON volunteer_application(applied_at);

-- Show tables created
SHOW TABLES;

-- Show table structures
DESCRIBE user;
DESCRIBE event;
DESCRIBE event_rsvp;
DESCRIBE volunteer_application;
DESCRIBE email_verification;
DESCRIBE reward_voucher;
DESCRIBE user_reward;
