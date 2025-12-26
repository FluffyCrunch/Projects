const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { spawn } = require('child_process');
const { createServer } = require('http');
const { Server } = require('socket.io');
const path = require('path');

// Load environment variables
dotenv.config();
const { Pool } = require('pg');

// PostgreSQL DB connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:password@localhost:5432/vulnerability_scanner',
});


const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());

// Serve static files
app.use(express.static(path.join(__dirname, 'static')));

// In-memory storage (synced with database)
let scanResults = [];
let vulnerabilities = [];

// ✅ In-memory user storage (for testing only)
let users = [];

// Test database connection endpoint
app.get('/api/test-db', async (req, res) => {
  try {
    // Test basic connection
    const testResult = await pool.query('SELECT NOW() as current_time');
    
    // Test if tables exist
    const tablesResult = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
      AND table_name IN ('users', 'scan_jobs', 'vulnerabilities', 'scan_results')
    `);
    
    const existingTables = tablesResult.rows.map(row => row.table_name);
    const requiredTables = ['users', 'scan_jobs', 'vulnerabilities', 'scan_results'];
    const missingTables = requiredTables.filter(t => !existingTables.includes(t));
    
    // Get actual column names for each table
    const scanJobsColumns = await pool.query(`
      SELECT column_name, data_type 
      FROM information_schema.columns 
      WHERE table_name = 'scan_jobs' AND table_schema = 'public'
      ORDER BY ordinal_position
    `);
    
    const vulnerabilitiesColumns = await pool.query(`
      SELECT column_name, data_type 
      FROM information_schema.columns 
      WHERE table_name = 'vulnerabilities' AND table_schema = 'public'
      ORDER BY ordinal_position
    `);
    
    res.json({
      success: true,
      connected: true,
      currentTime: testResult.rows[0].current_time,
      existingTables: existingTables,
      missingTables: missingTables,
      allTablesExist: missingTables.length === 0,
      scan_jobs_columns: scanJobsColumns.rows,
      vulnerabilities_columns: vulnerabilitiesColumns.rows
    });
  } catch (error) {
    console.error('Database test error:', error);
    res.status(500).json({
      success: false,
      connected: false,
      error: error.message,
      code: error.code,
      detail: error.detail
    });
  }
});

// Load existing data from database on startup
async function loadDataFromDatabase() {
  try {
    // First, check what columns actually exist in the table
    const columnCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'scan_jobs' 
      AND table_schema = 'public'
    `);
    console.log('scan_jobs columns:', columnCheck.rows.map(r => r.column_name));
    
    // Load scan jobs - use the actual column names from the database
    const scanJobsResult = await pool.query(
      'SELECT id, website_url, status, started_at, completed_at FROM scan_jobs ORDER BY started_at DESC'
    );
    scanResults = scanJobsResult.rows.map(row => ({
      id: row.id,
      targetUrl: row.website_url,
      status: row.status,
      createdAt: new Date(row.started_at),
      completedAt: row.completed_at ? new Date(row.completed_at) : null
    }));

    // Check vulnerabilities table columns
    const vulnColumnCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'vulnerabilities' 
      AND table_schema = 'public'
    `);
    console.log('vulnerabilities columns:', vulnColumnCheck.rows.map(r => r.column_name));
    
    // Load vulnerabilities - use the actual column names from the database
    const vulnsResult = await pool.query(
      'SELECT id, scan_id, url, type, severity, description, location, date_found FROM vulnerabilities ORDER BY date_found DESC'
    );
    vulnerabilities = vulnsResult.rows.map(row => ({
      id: row.id,
      scanId: row.scan_id,
      type: row.type,
      severity: row.severity,
      description: row.description || getVulnerabilityDescription(row.type),
      location: row.location || row.url,
      createdAt: new Date(row.date_found)
    }));

    console.log(`Loaded ${scanResults.length} scan jobs and ${vulnerabilities.length} vulnerabilities from database`);
  } catch (error) {
    console.error('Error loading data from database:', error);
    // Continue with empty arrays if database load fails
  }
}

// Data will be loaded before server starts (see below)

// ✅ Signup API Route
app.post('/api/signup', async (req, res) => {
  const { name, institute, email, password } = req.body;

  if (!name || !institute || !email || !password) {
    return res.status(400).json({ success: false, message: "All fields are required." });
  }

  try {
    // Check if user already exists
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ success: false, message: "User already exists." });
    }

    // Insert user into database
    await pool.query(
      'INSERT INTO users (name, institute, email, password) VALUES ($1, $2, $3, $4)',
      [name, institute, email, password]
    );

    res.status(201).json({ success: true, message: "Signup successful!" });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ success: false, message: "Internal server error." });
  }
});

// WebSocket connection
io.on('connection', (socket) => {
  console.log('Client connected');
  
  // Send current dashboard stats when client connects
  emitDashboardStats();
  
  // Handle report download notification
  socket.on('report_downloaded', (data) => {
    // Broadcast to all clients
    io.emit('notification', {
      type: 'report_downloaded',
      message: data.message || 'Vulnerability report downloaded successfully',
      timestamp: data.timestamp || new Date()
    });
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

// API Routes
app.post('/api/start-scan', async (req, res) => {
  const { targetUrl } = req.body;
  
  try {
    // Create scan job in database
    let scanJobResult;
    try {
      scanJobResult = await pool.query(
        'INSERT INTO scan_jobs (website_url, status, started_at) VALUES ($1, $2, $3) RETURNING id, website_url, status, started_at',
        [targetUrl, 'in_progress', new Date()]
      );
    } catch (dbError) {
      console.error('Database error creating scan job:', dbError);
      console.error('Error code:', dbError.code);
      console.error('Error detail:', dbError.detail);
      console.error('Error message:', dbError.message);
      
      // Provide more helpful error message
      let errorMsg = `Database error: ${dbError.message}`;
      if (dbError.code === '42P01') {
        errorMsg = 'Table "scan_jobs" does not exist. Please run schema.sql to create the tables.';
      } else if (dbError.code === '23503') {
        errorMsg = 'Foreign key constraint violation. Check that referenced records exist.';
      } else if (dbError.code === '28P01') {
        errorMsg = 'Authentication failed. Check your database credentials in .env file.';
      } else if (dbError.code === '3D000') {
        errorMsg = 'Database "vulnerability_scanner" does not exist.';
      } else if (dbError.code === 'ECONNREFUSED' || dbError.code === 'ENOTFOUND') {
        errorMsg = 'Cannot connect to database server. Is PostgreSQL running?';
      }
      
      throw new Error(errorMsg);
    }
    
    if (!scanJobResult || !scanJobResult.rows || scanJobResult.rows.length === 0) {
      throw new Error('Failed to create scan job - no data returned from database');
    }
    
    const dbScanJob = scanJobResult.rows[0];
    const scanId = dbScanJob.id;
    
    const scanJob = {
      id: scanId,
      targetUrl: dbScanJob.website_url,
      status: dbScanJob.status === 'in_progress' ? 'running' : dbScanJob.status, // Map DB 'in_progress' to internal 'running'
      createdAt: new Date(dbScanJob.started_at)
    };
    scanResults.push(scanJob);
    
    // Emit notification for scan started
    io.emit('notification', {
      type: 'scan_started',
      message: `Scan started for ${targetUrl}`,
      targetUrl: targetUrl,
      scanId: scanId,
      timestamp: new Date()
    });
    
    const pythonProcess = spawn('python', [path.join(__dirname, 'scanner', 'vulnerability_scanner.py'), targetUrl]);
    
    let scanOutput = '';
    let scanError = '';

    pythonProcess.stdout.on('data', (data) => {
      scanOutput += data.toString();
    });

    pythonProcess.stderr.on('data', (data) => {
      scanError += data.toString();
    });

    pythonProcess.on('close', async (code) => {
      if (code !== 0) {
        console.error(`Python scanner exited with code ${code}`);
        console.error('Scanner error:', scanError);
        
        // Update scan job status in database
        await pool.query(
          'UPDATE scan_jobs SET status = $1, completed_at = $2 WHERE id = $3',
          ['failed', new Date(), scanId]
        );
        
        const scanIndex = scanResults.findIndex(s => s.id === scanId);
        if (scanIndex !== -1) {
          scanResults[scanIndex].status = 'failed';
          scanResults[scanIndex].completedAt = new Date();
        }
        
        io.emit('scan_results', {
          scanId,
          status: 'failed',
          error: scanError
        });
        
        emitDashboardStats();
        return;
      }

      try {
        console.log('--- Python scan output start ---');
        console.log(scanOutput);
        console.log('--- Python scan output end ---');
        const trimmedOutput = scanOutput.trim();
        const firstBrace = trimmedOutput.indexOf('{');
        const lastBrace = trimmedOutput.lastIndexOf('}');
        if (firstBrace === -1 || lastBrace === -1 || lastBrace <= firstBrace) throw new Error('No JSON output from scanner');
        const jsonString = trimmedOutput.substring(firstBrace, lastBrace + 1);
        const results = JSON.parse(jsonString);
        
        // Save vulnerabilities to database
        // Now that scan_id, description, and location columns exist, we can use them
        const vulnerabilityInserts = results.vulnerabilities.map(vuln => 
          pool.query(
            'INSERT INTO vulnerabilities (scan_id, url, type, severity, description, location, date_found) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, scan_id, url, type, severity, description, location, date_found',
            [
              scanId,
              targetUrl, // url column
              vuln.type,
              vuln.severity,
              vuln.description || getVulnerabilityDescription(vuln.type), // description column
              vuln.location || targetUrl, // location column
              new Date() // date_found column
            ]
          )
        );
        
        const savedVulns = await Promise.all(vulnerabilityInserts);
        const newVulnerabilities = savedVulns.map(result => {
          const row = result.rows[0];
          return {
            id: row.id,
            scanId: row.scan_id,
            type: row.type,
            severity: row.severity,
            description: row.description,
            location: row.location || row.url,
            createdAt: new Date(row.date_found)
          };
        });
        vulnerabilities.push(...newVulnerabilities);

        // Save scan results summary
        // Note: Your scan_results table has a different structure (stores individual vulnerabilities)
        // So we'll skip inserting summary data - the vulnerabilities are already saved above
        // If you want to store summary data, you'd need a different table or adapt this query
        try {
          // The scan_results table in your DB has: scan_id, vulnerability_name, severity, description, etc.
          // It's structured for individual vulnerability records, not summary stats
          // So we'll skip this insert - all important data is already in the vulnerabilities table
          console.log(`Scan completed: ${results.vulnerabilities.length} vulnerabilities saved to database`);
        } catch (scanResultsError) {
          // This shouldn't happen now, but just in case
          console.log('Note: Could not save to scan_results table (this is optional):', scanResultsError.message);
        }

        // Update scan job status in database
        await pool.query(
          'UPDATE scan_jobs SET status = $1, completed_at = $2 WHERE id = $3',
          ['completed', new Date(), scanId]
        );

        const scanIndex = scanResults.findIndex(s => s.id === scanId);
        if (scanIndex !== -1) {
          scanResults[scanIndex].status = 'completed';
          scanResults[scanIndex].completedAt = new Date();
          scanResults[scanIndex].totalVulnerabilities = results.vulnerabilities.length;
          scanResults[scanIndex].scanDuration = results.scan_duration;
        }

        io.emit('scan_results', {
          scanId,
          status: 'completed',
          results: {
            totalVulnerabilities: results.vulnerabilities.length,
            scanDuration: results.scan_duration,
            vulnerabilities: results.vulnerabilities
          }
        });
        
        // Emit notification for scan completed
        io.emit('notification', {
          type: 'scan_completed',
          message: `Scan completed for ${targetUrl}. Found ${results.vulnerabilities.length} vulnerability(ies).`,
          targetUrl: targetUrl,
          scanId: scanId,
          vulnerabilityCount: results.vulnerabilities.length,
          timestamp: new Date()
        });
        
        emitDashboardStats();

      } catch (error) {
        console.error('Error processing scan results:', error);
        
        // Update scan job status in database
        await pool.query(
          'UPDATE scan_jobs SET status = $1, completed_at = $2 WHERE id = $3',
          ['failed', new Date(), scanId]
        ).catch(err => console.error('Error updating scan job status:', err));

        const scanIndex = scanResults.findIndex(s => s.id === scanId);
        if (scanIndex !== -1) {
          scanResults[scanIndex].status = 'failed';
          scanResults[scanIndex].completedAt = new Date();
        }

        io.emit('scan_results', {
          scanId,
          status: 'failed',
          error: error.message
        });
        emitDashboardStats();
      }
    });

    res.json({ 
      message: 'Scan started successfully',
      scanId: scanId
    });

  } catch (error) {
    console.error('Error starting scan:', error);
    console.error('Error details:', error.message);
    if (error.stack) {
      console.error('Error stack:', error.stack);
    }
    res.status(500).json({ 
      error: 'Failed to start scan',
      message: error.message || 'Unknown error occurred',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Get dashboard stats
app.get('/api/dashboard-stats', async (req, res) => {
  try {
    // Get count from database
    const scanCountResult = await pool.query('SELECT COUNT(*) as count FROM scan_jobs');
    const totalScans = parseInt(scanCountResult.rows[0].count);
    
    // Update in-memory cache
    scanResults = (await pool.query(
      'SELECT id, website_url as "targetUrl", status, started_at as "createdAt", completed_at as "completedAt" FROM scan_jobs ORDER BY started_at DESC'
    )).rows.map(row => ({
      id: row.id,
      targetUrl: row.targetUrl,
      status: row.status,
      createdAt: new Date(row.createdAt),
      completedAt: row.completedAt ? new Date(row.completedAt) : null
    }));

    res.json({
      success: true,
      totalScans: totalScans,
      scanRequests: totalScans
    });
  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    // Fallback to in-memory data
    res.json({
      success: true,
      totalScans: scanResults.length,
      scanRequests: scanResults.length
    });
  }
});

// Get vulnerabilities
app.get('/api/vulnerabilities', async (req, res) => {
  try {
    // Get from database to ensure we have the latest data
    const result = await pool.query(
      'SELECT type, severity, description, date_found FROM vulnerabilities ORDER BY date_found DESC'
    );
    
    const dbVulnerabilities = result.rows.map(row => ({
      type: row.type,
      severity: row.severity,
      description: row.description || getVulnerabilityDescription(row.type),
      detectedAt: new Date(row.date_found)
    }));

    // Also update in-memory cache (reload full data)
    const fullVulnsResult = await pool.query(
      'SELECT id, scan_id, url, type, severity, description, location, date_found FROM vulnerabilities ORDER BY date_found DESC'
    );
    vulnerabilities = fullVulnsResult.rows.map(row => ({
      id: row.id,
      scanId: row.scan_id,
      type: row.type,
      severity: row.severity,
      description: row.description || getVulnerabilityDescription(row.type),
      location: row.location || row.url,
      createdAt: new Date(row.date_found)
    }));

    res.json({
      success: true,
      vulnerabilities: dbVulnerabilities
    });
  } catch (error) {
    console.error('Error fetching vulnerabilities:', error);
    // Fallback to in-memory data
    res.json({
      success: true,
      vulnerabilities: vulnerabilities.map(v => ({
        type: v.type,
        severity: v.severity,
        description: v.description || getVulnerabilityDescription(v.type),
        detectedAt: v.createdAt
      }))
    });
  }
});

// Helper function to get vulnerability descriptions
function getVulnerabilityDescription(type) {
  const descriptions = {
    'SSL/TLS': 'SSL/TLS configuration issues detected. This may include outdated TLS versions (SSLv2, SSLv3, TLSv1.0, TLSv1.1), invalid certificates, or weak encryption protocols that could expose data to interception and man-in-the-middle attacks.',
    'Security Headers': 'Missing or improperly configured security headers detected. These headers (X-Frame-Options, X-Content-Type-Options, Content-Security-Policy, X-XSS-Protection, Strict-Transport-Security) protect against various attacks like clickjacking, XSS, MIME-sniffing, and enforce secure connections.',
    'Open Port': 'Potentially vulnerable ports are open on the server. These ports (such as FTP on 21, Telnet on 23, or RDP on 3389) may expose services that are not properly secured or should not be publicly accessible, increasing the attack surface.',
    'XSS': 'Cross-Site Scripting (XSS) vulnerability detected. This allows attackers to inject malicious scripts into web pages viewed by other users, potentially stealing sensitive information (cookies, session tokens), performing actions on behalf of users, or defacing websites.',
    'SQL Injection': 'SQL Injection vulnerability detected. This allows attackers to manipulate database queries by injecting malicious SQL code, potentially accessing, modifying, or deleting sensitive data, bypassing authentication, or taking control of the database server.',
    'CSRF': 'Cross-Site Request Forgery (CSRF) vulnerability detected. Forms without CSRF protection can be exploited to perform unauthorized actions on behalf of authenticated users, such as changing passwords, making purchases, or modifying account settings.',
    'DNS Security': 'DNS security issues detected. Missing SPF (Sender Policy Framework), DMARC (Domain-based Message Authentication), or other DNS security records can allow email spoofing, phishing attacks, and domain impersonation.',
    'Information Disclosure': 'Server information disclosure detected. Exposed server versions, software details, error messages, stack traces, or configuration information can help attackers identify and exploit known vulnerabilities, reducing the time needed for reconnaissance.',
    'HSTS': 'HTTP Strict Transport Security (HSTS) issues detected. Missing or improperly configured HSTS headers can allow downgrade attacks and man-in-the-middle attacks by forcing browsers to use insecure HTTP connections instead of HTTPS.',
    'SPF': 'SPF (Sender Policy Framework) record issues detected. Missing, incorrect, or weak SPF records can allow email spoofing, making it easier for attackers to send phishing emails that appear to come from your domain, potentially damaging your reputation and tricking users.',
    'Server Version': 'Outdated server software detected. Older versions of web servers (Apache, nginx, IIS), application servers, or frameworks often contain known security vulnerabilities that can be exploited by attackers. Regular updates and patches are essential for security.'
  };
  
  return descriptions[type] || `Security vulnerability of type ${type} detected. This may pose a risk to the application's security and should be addressed promptly.`;
}

// Get chart data
app.get('/api/charts', async (req, res) => {
  try {
    // Get scan jobs from database
    const scanJobsResult = await pool.query(
      'SELECT started_at as created_at FROM scan_jobs ORDER BY started_at'
    );
    
    // Get vulnerabilities from database
    const vulnsResult = await pool.query(
      'SELECT type, severity, date_found as created_at FROM vulnerabilities ORDER BY date_found'
    );

    const scanActivity = {};
    scanJobsResult.rows.forEach(row => {
      const month = new Date(row.created_at).toLocaleString('default', { month: 'short', year: 'numeric' });
      scanActivity[month] = (scanActivity[month] || 0) + 1;
    });

    const vulnerabilityTypes = {};
    vulnsResult.rows.forEach(row => {
      vulnerabilityTypes[row.type] = (vulnerabilityTypes[row.type] || 0) + 1;
    });

    const trends = {};
    vulnsResult.rows.forEach(row => {
      const month = new Date(row.created_at).toLocaleString('default', { month: 'short', year: 'numeric' });
      if (!trends[month]) trends[month] = { High: 0, Medium: 0, Low: 0, Critical: 0, Informational: 0 };
      trends[month][row.severity] = (trends[month][row.severity] || 0) + 1;
    });

    // Calculate severity distribution
    const severityDistribution = { High: 0, Medium: 0, Low: 0, Critical: 0, Informational: 0 };
    vulnsResult.rows.forEach(row => {
      const severity = row.severity || 'Low';
      severityDistribution[severity] = (severityDistribution[severity] || 0) + 1;
    });

    const riskBuckets = { '0-2': 0, '3-5': 0, '6-8': 0, '9-10': 0 };
    vulnsResult.rows.forEach(row => {
      let score = 0;
      if (row.severity === 'Critical') score = 10;
      else if (row.severity === 'High') score = 9;
      else if (row.severity === 'Medium') score = 5;
      else if (row.severity === 'Low') score = 2;
      else if (row.severity === 'Informational') score = 1;
      
      if (score <= 2) riskBuckets['0-2']++;
      else if (score <= 5) riskBuckets['3-5']++;
      else if (score <= 8) riskBuckets['6-8']++;
      else riskBuckets['9-10']++;
    });

    res.json({
      charts: {
        scanActivity: Object.entries(scanActivity).map(([date, scans]) => ({ date, scans })),
        vulnerabilityTypes,
        trends,
        riskBuckets,
        severityDistribution
      }
    });
  } catch (error) {
    console.error('Error fetching chart data:', error);
    // Fallback to in-memory data
    const scanActivity = {};
    scanResults.forEach(scan => {
      const month = new Date(scan.createdAt).toLocaleString('default', { month: 'short', year: 'numeric' });
      scanActivity[month] = (scanActivity[month] || 0) + 1;
    });

    const vulnerabilityTypes = {};
    vulnerabilities.forEach(vuln => {
      vulnerabilityTypes[vuln.type] = (vulnerabilityTypes[vuln.type] || 0) + 1;
    });

    res.json({
      charts: {
        scanActivity: Object.entries(scanActivity).map(([date, scans]) => ({ date, scans })),
        vulnerabilityTypes,
        trends: {},
        riskBuckets: { '0-2': 0, '3-5': 0, '6-8': 0, '9-10': 0 }
      }
    });
  }
});

// Serve index.html for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'static', 'index.html'));
});

const PORT = process.env.PORT || 5500;

// Start server after loading data from database
loadDataFromDatabase().then(() => {
  httpServer.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Database connected. Loaded ${scanResults.length} scans and ${vulnerabilities.length} vulnerabilities.`);
  });
}).catch((error) => {
  console.error('Failed to load data from database:', error);
  // Start server anyway with empty data
  httpServer.listen(PORT, () => {
    console.log(`Server running on port ${PORT} (with empty data - database connection issue)`);
  });
});

function emitDashboardStats() {
  io.emit('dashboard_stats', {
    totalScans: scanResults.length,
    scanRequests: scanResults.length
  });
}
