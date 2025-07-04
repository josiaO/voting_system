# Voting System

A secure and user-friendly web-based voting system built with Flask. This application allows users to register, login, and cast votes for presidential and vice-presidential candidates.

## Features

- **User Authentication**: Secure login and registration system
- **Voting Interface**: Intuitive voting interface for presidential and vice-presidential elections
- **Admin Panel**: Comprehensive admin dashboard for managing users, candidates, and results
- **Real-time Results**: Live vote counting and percentage calculations
- **File Upload**: Support for candidate photo uploads
- **Password Recovery**: Forgot password functionality with email-based reset
- **Responsive Design**: Modern, mobile-friendly interface

## Technology Stack

- **Backend**: Flask (Python)
- **Database**: SQLite
- **Frontend**: HTML, CSS, JavaScript
- **Security**: Werkzeug password hashing
- **File Handling**: Secure file uploads with validation

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

### Setup Instructions

1. **Clone the repository:**
   ```bash
   git clone https://github.com/josiaO/voting_system.git
   cd voting_system
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   python src/app.py
   ```

4. **Access the application:**
   Open your browser and navigate to `http://localhost:5000`

## Default Admin Account

- **Registration Number**: ADMIN001
- **Password**: admin@may2025

## Usage

### For Voters

1. **Register**: Create a new account with your details
2. **Login**: Use your registration number and password
3. **Vote**: Select your preferred candidates for president and vice-president
4. **View Results**: See real-time voting results and percentages

### For Administrators

1. **Login**: Use the admin account credentials
2. **Manage Users**: View, edit, and delete user accounts
3. **Add Candidates**: Upload candidate photos and information
4. **Announce Winners**: Declare election winners
5. **Post Messages**: Broadcast messages to all users

## Project Structure

```
voting_system/
├── src/
│   ├── app.py                 # Main Flask application
│   ├── static/
│   │   ├── asset/            # Uploaded candidate photos
│   │   ├── scripts/          # JavaScript files
│   │   └── styles/           # CSS stylesheets
│   └── templates/            # HTML templates
├── voting.db                 # SQLite database
├── requirements.txt          # Python dependencies
└── README.md               # This file
```

## Database Schema

### Users Table
- Registration number, full name, email, phone, level
- Password (hashed), admin status, creation tracking

### Candidates Table
- Name, position (president/vice), photo path
- Education, course information

### Votes Table
- User ID, president choice, vice choice

### Winners Table
- Position, candidate ID, announcement timestamp

## Security Features

- Password hashing using Werkzeug
- Session management
- File upload validation
- SQL injection prevention
- XSS protection

## File Upload Configuration

- **Supported Formats**: JPG, JPEG, PNG
- **Maximum Size**: 5MB
- **Storage Location**: `src/static/asset/`

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Authorship

Created by Barney Rolland, 2025. All rights reserved.

## Support

For support and questions, please open an issue on GitHub or contact the development team.

---

**Note**: This is a demonstration voting system. For production use, additional security measures and compliance with local election laws should be implemented. 