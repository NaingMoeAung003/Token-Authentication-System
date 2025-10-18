Advanced Authentication System

This is a secure, token-based authentication system built with Python and Flask. It serves as a comprehensive demonstration of modern web security practices, including email verification, two-factor authentication (2FA), and secure password handling.

Features

Secure User Registration:

Requires Username, unique Email, and Password.

Real-time password strength validation (length, numbers, special characters).

Includes a "Confirm Password" field.

Protected by a CAPTCHA to prevent automated bot sign-ups.

Mandatory Email Verification:

Accounts are created in an unverified state.

A unique, time-sensitive verification link is sent to the user's email.

Users cannot log in until their email has been verified.

Multi-Factor Authentication (2FA/MFA):

Users can enable Time-Based One-Time Passwords (TOTP) for enhanced security.

Simple setup process using a QR code compatible with apps like Google Authenticator.

Login process becomes a two-step verification for enabled accounts.

Secure Token-Based Sessions:

Uses JSON Web Tokens (JWTs) for authentication.

Tokens are digitally signed with a secret key to ensure integrity.

Tokens have a defined 1-hour expiration time, after which they are invalid.

"Login with Token" Feature:

A dedicated page to demonstrate how a valid, existing token can be used to gain access to protected areas, fulfilling a core assignment requirement.

Secure Password Handling:

Passwords are never stored in plain text.

Uses the bcrypt algorithm for secure hashing and salting.

Includes a secure "Forgot Password" flow that sends a time-sensitive reset link to the user's verified email.

Technology Stack

Backend: Python with Flask Framework

Database: MongoDB (NoSQL)

Security Libraries:

bcrypt for password hashing and salting.

PyJWT for creating and validating JSON Web Tokens.

pyotp & qrcode for Two-Factor Authentication.

Frontend: HTML, CSS, JavaScript (no external frameworks)

Environment Management: python-dotenv

Local Setup and Installation

Prerequisites

Python 3.x

Git

MongoDB installed and running locally.

A Gmail account with an App Password generated for sending emails.

Instructions

Clone the Repository:

git clone <your-repository-url>
cd <repository-name>


Create a Virtual Environment:

python -m venv venv


Activate the Virtual Environment:

On Windows: .\venv\Scripts\activate

On macOS/Linux: source venv/bin/activate

Install Dependencies:

pip install -r requirements.txt


Create the .env File:

In the main project folder, create a file named .env.

Add your secret credentials to this file. This file is ignored by Git and should never be shared.

# Your Gmail address for sending system emails
EMAIL_USER=your-email@gmail.com

# Your 16-character Google App Password
EMAIL_PASS=your16characterapppassword


Run the Application:

python app.py


The application will be running at http://127.0.0.1:5000.

How to Use the System

Register: Create a new staff account using the registration form.

Verify Email: Check your email for the verification link and click it. You must do this before you can log in.

Login: Log in with your new credentials.

Access Dashboard: You will be taken to the secure dashboard, where you can see your authentication token and its expiration time.

Enable 2FA (Optional): On the dashboard, scan the QR code with an authenticator app and enter the code to enable 2FA for your account. The next time you log in, you will be prompted for a code.