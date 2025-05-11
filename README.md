# Smart Shop E-commerce Platform

A full-stack e-commerce platform built with Flask, featuring an AI-powered chatbot, secure user authentication, and comprehensive product management.

## Features

- **User Authentication & Security**
  - Secure user registration and login
  - Email verification system
  - Password reset functionality
  - Role-based access (seller and client)
  - Password complexity requirements

- **Product Management**
  - Product listing with images
  - Category-based organization
  - Stock management
  - Seller dashboard for product management
  - Product search and filtering

- **Shopping Experience**
  - Shopping cart functionality
  - Order processing system
  - Order status tracking
  - Multiple payment methods
  - Order history

- **AI-Powered Features**
  - Smart chatbot for customer support
  - Custom question submission
  - Automated responses
  - Interactive button-based navigation

- **Technical Features**
  - Responsive design with Bootstrap
  - Form validation
  - Image upload and processing
  - SQLite database with migrations
  - Email notifications

## Setup Instructions

1. Clone the repository:
```bash
git clone <repository-url>
cd smartshop
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
Create a `.env` file in the root directory with the following variables:
```env
# Flask Configuration
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here

# Database Configuration
DATABASE_URL=sqlite:///users.db

# Email Configuration
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-specific-password

# File Upload Configuration
UPLOAD_FOLDER=static/product_images
MAX_CONTENT_LENGTH=16777216  # 16MB in bytes

# OpenAI Configuration (for chatbot)
OPENAI_API_KEY=your-openai-api-key

# Allowed File Extensions (comma-separated)
ALLOWED_EXTENSIONS=png,jpg,jpeg,gif
```

Note: Never commit the `.env` file to version control. The `.env.example` file is provided as a template.

5. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

6. Run the application:
```bash
python app.py
```

7. Access the application:
```
http://localhost:5000
```

## Project Structure

```
smartshop/
├── app.py              # Main application file
├── requirements.txt    # Python dependencies
├── static/            # Static files
│   ├── css/          # Stylesheets
│   ├── js/           # JavaScript files
│   └── product_images/ # Product images
├── templates/         # HTML templates
│   ├── base.html     # Base template
│   ├── index.html    # Home page
│   ├── auth/         # Authentication templates
│   ├── products/     # Product-related templates
│   └── orders/       # Order-related templates
├── migrations/        # Database migrations
└── instance/         # Instance-specific files
    └── users.db      # SQLite database
```

## Security Features

- CSRF protection with Flask-WTF
- Password hashing with Werkzeug
- Secure session management
- Email verification system
- Rate limiting for sensitive routes
- Secure file upload handling
- Input validation and sanitization

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request
