CET324 - Advanced Cyber Security Authentication System
This project is a secure, token-based authentication system developed for the CET324 Advanced Cyber Security module. It is built with Python and Flask on the backend, uses MongoDB for data storage, and has a dynamic, themed frontend.

Key Features
Secure User Registration & Login: Passwords are never stored directly. They are securely hashed and salted using the bcrypt algorithm.

JWT Authentication: Implements a professional two-token system:

Short-Lived Access Tokens (15 mins): Used to access protected resources, minimizing risk if a token is compromised.

Long-Lived Refresh Tokens (7 days): Used to seamlessly acquire new access tokens without forcing the user to log in again.

Role-Based Access Control (RBAC): Users are assigned user or admin roles. Protected API endpoints ensure that only users with the 'admin' role can access sensitive data.

Bot Prevention: A simple CAPTCHA on the registration form helps prevent automated account creation.

Cybersecurity-Themed UI: A modern, dark-mode interface built with HTML, CSS, and vanilla JavaScript.

Technology Stack
Backend: Python, Flask

Database: MongoDB

Security Libraries: PyJWT (for tokens), bcrypt (for password hashing)

Frontend: HTML, CSS, JavaScript

How to Run
Clone the repository:

git clone <your-repo-url>

Navigate into the project directory:

cd cybersecurity-auth-system

Create and activate a virtual environment:

python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

Install dependencies:

pip install flask bcrypt pyjwt pymongo

Ensure a local MongoDB instance is running.

Run the application:

python app.py

Open a web browser and navigate to http://127.0.0.1:5000.