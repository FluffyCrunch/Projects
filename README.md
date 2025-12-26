# Web Vulnerability Scanner

A comprehensive web application vulnerability scanner that detects various security vulnerabilities including XSS, SQL Injection, SSL/TLS issues, security headers, and more.

![Dashboard](screenshots/dashboard.png)
*Main Dashboard showing scan statistics and vulnerability reports*

## Features

- **Multiple Vulnerability Checks**: XSS, SQL Injection, CSRF, SSL/TLS, Security Headers, DNS Security, and more
- **Real-time Scanning**: WebSocket-based real-time scan progress and results
- **Interactive Dashboard**: Beautiful analytics dashboard with charts and statistics
- **Persistent Data Storage**: PostgreSQL database stores scan results and vulnerabilities
- **Date-Filtered Reports**: Download PDF reports filtered by specific dates
- **Notification System**: Real-time notifications for scan events and report downloads
- **Responsive Design**: Modern, professional UI with smooth animations

## Screenshots

### Dashboard
![Dashboard](screenshots/dashboard.png)
The main dashboard displays scan statistics, vulnerability counts, and real-time scan results.

### Reports Page
![Reports](screenshots/reports.png)
View all detected vulnerabilities with pagination, date filtering, and PDF export functionality.

### Charts & Analytics
![Charts](screenshots/charts.png)
Comprehensive analytics including severity distribution, vulnerability types, and scan activity over time.

## Prerequisites

- Node.js (v14 or higher)
- Python 3.7 or higher
- PostgreSQL database
- npm or yarn
- nmap (for port scanning)

## Installation

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd vulnerability-scanner
   ```

2. **Install Node.js dependencies**
   ```bash
   npm install
   ```

3. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up PostgreSQL database**
   - Create a PostgreSQL database named `vulnerability_scanner`
   - Run the schema.sql file to create tables:
   ```bash
   psql -U postgres -d vulnerability_scanner -f schema.sql
   ```

5. **Configure environment variables**
   - Create a `.env` file in the root directory:
   ```env
   DATABASE_URL=postgresql://username:password@localhost:5432/vulnerability_scanner
   PORT=5500
   ```

## Running the Application

1. **Start the server**
   ```bash
   npm start
   ```
   Or for development with auto-reload:
   ```bash
   npm run dev
   ```

2. **Access the application**
   - Open your browser and navigate to `http://localhost:5500`
   - The dashboard will be displayed with options to start scans

## Project Structure

```
vulnerability-scanner/
├── server.js              # Main Node.js server with Express and Socket.IO
├── package.json           # Node.js dependencies
├── requirements.txt       # Python dependencies
├── schema.sql            # PostgreSQL database schema
├── .env                  # Environment variables (create from template)
├── .gitignore            # Git ignore rules
├── static/               # Frontend files
│   ├── index.html        # Dashboard page
│   ├── report.html       # Reports page with pagination
│   ├── charts.html       # Analytics and charts page
│   ├── css/
│   │   └── app.css       # Main stylesheet
│   ├── js/
│   │   ├── app.js        # Main JavaScript
│   │   └── common.js      # Common utilities
│   └── img/              # Images and assets
└── scanner/              # Python vulnerability scanner
    └── vulnerability_scanner.py
```

## API Endpoints

- `POST /api/start-scan` - Start a vulnerability scan for a target URL
- `GET /api/vulnerabilities` - Get all detected vulnerabilities
- `GET /api/charts` - Get chart data for analytics dashboard
- `GET /api/dashboard-stats` - Get dashboard statistics (scan counts, etc.)

## WebSocket Events

- `scan_results` - Real-time scan results and completion status
- `notification` - Notifications for scan events and report downloads
- `dashboard_stats` - Real-time dashboard statistics updates

## Vulnerability Checks

The scanner performs comprehensive security checks:

1. **SSL/TLS Configuration** - Certificate validation, TLS version detection
2. **Security Headers** - X-Frame-Options, CSP, HSTS, X-Content-Type-Options, etc.
3. **Open Ports** - Nmap-based port scanning for exposed services
4. **XSS Vulnerabilities** - Reflected and stored XSS detection
5. **SQL Injection** - Error-based and time-based SQLi detection
6. **CSRF Protection** - Form CSRF token validation
7. **DNS Security** - SPF, DMARC records validation
8. **Information Disclosure** - Server version, error messages, stack traces
9. **HSTS Implementation** - HTTP Strict Transport Security validation
10. **Server Version** - Outdated software detection

## Key Features

### Dashboard
- Real-time scan statistics
- Interactive charts showing scan activity and vulnerability distribution
- Live vulnerability table showing only current scan results
- Notification system with persistent storage

### Reports
- Paginated vulnerability list (20 per page)
- Date-filtered PDF report downloads
- Professional pagination controls
- Detailed vulnerability descriptions

### Charts & Analytics
- Severity distribution (donut chart)
- Vulnerability types breakdown (pie chart)
- Scan activity over time (bar chart)
- Risk score distribution
- Vulnerability trends analysis

## Database Schema

The application uses PostgreSQL with the following main tables:
- `scan_jobs` - Stores scan job information
- `vulnerabilities` - Stores detected vulnerabilities with descriptions
- `scan_results` - Stores scan summary data
- `users` - User management (if authentication is enabled)

## Technologies Used

- **Backend**: Node.js, Express.js, Socket.IO
- **Database**: PostgreSQL
- **Frontend**: HTML5, CSS3, JavaScript, Chart.js
- **Scanner**: Python 3 with requests, nmap, dnspython
- **Styling**: Bootstrap, Custom CSS with gradients and animations

## Security Notes

⚠️ **Important**: 
- This scanner is for **educational and authorized testing purposes only**
- Always ensure you have **explicit permission** to scan target websites
- Some checks may require elevated permissions
- The scanner requires `nmap` to be installed for port scanning
- Use responsibly and ethically

## Troubleshooting

### Database Connection Errors
- Check PostgreSQL is running: `pg_isready`
- Verify credentials in `.env` file
- Ensure database `vulnerability_scanner` exists
- Run `schema.sql` to create required tables

### Python Scanner Errors
- Ensure all Python dependencies are installed: `pip install -r requirements.txt`
- Verify Python is in PATH: `python --version`
- Check nmap is installed: `nmap --version`

### Port Already in Use
- Change the PORT in `.env` file
- Or kill the process using the port

### Chart Not Displaying
- Check browser console for errors
- Verify API endpoint `/api/charts` is accessible
- Ensure database has scan data

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is for educational purposes only. Use responsibly and only on systems you own or have explicit permission to test.

## Author

Developed as a comprehensive web vulnerability scanning solution.

---

**Note**: Remember to never scan websites without proper authorization. Unauthorized scanning is illegal and unethical.
