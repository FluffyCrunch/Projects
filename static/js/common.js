// Initialize Socket.IO connection
const socket = io('http://localhost:5500', {
    transports: ['websocket', 'polling'],
    reconnection: true,
    reconnectionAttempts: 5,
    reconnectionDelay: 1000
});

// Connection event handlers
socket.on('connect', () => {
    console.log('Connected to WebSocket server');
});

socket.on('connect_error', (error) => {
    console.error('WebSocket connection error:', error);
});

socket.on('disconnect', () => {
    console.log('Disconnected from WebSocket server');
});

socket.on('reconnect_attempt', (attemptNumber) => {
    console.log('Attempting to reconnect:', attemptNumber);
    showNotification('Attempting to reconnect...', 'info');
});

socket.on('reconnect', (attemptNumber) => {
    console.log('Reconnected after', attemptNumber, 'attempts');
    showNotification('Reconnected to server', 'success');
});

socket.on('reconnect_error', (error) => {
    console.error('Reconnection error:', error);
    showNotification('Reconnection failed: ' + error.message, 'error');
});

socket.on('reconnect_failed', () => {
    console.error('Failed to reconnect');
    showNotification('Failed to reconnect to server', 'error');
});

socket.on('connection_response', (data) => {
    console.log('Connection response:', data);
});

// Scan event handlers
socket.on('scan_started', (data) => {
    console.log('Scan started:', data);
    showNotification('Scan started for ' + data.target_url);
});

socket.on('scan_results', (data) => {
    console.log('Scan results received:', data);
    showNotification('Scan completed for ' + data.target_url);
    
    // Display vulnerabilities
    if (data.vulnerabilities && data.vulnerabilities.length > 0) {
        data.vulnerabilities.forEach(vuln => {
            showVulnerabilityNotification(vuln);
        });
    } else {
        showNotification('No vulnerabilities found');
    }
});

socket.on('scan_error', (data) => {
    console.error('Scan error:', data);
    showNotification('Scan error: ' + data.error, 'error');
});

// Helper function to show notifications
function showNotification(message, type = 'info') {
    console.log(`[${type.toUpperCase()}] ${message}`);
    // You can add UI notification here if needed
}

// Helper function to show vulnerability notifications
function showVulnerabilityNotification(vulnerability) {
    const message = `[${vulnerability.severity}] ${vulnerability.type}: ${vulnerability.details}`;
    console.log(message);
    // You can add UI notification here if needed
}

// Function to start a scan
function startScan(targetUrl) {
    if (!targetUrl) {
        showNotification('Please enter a target URL', 'error');
        return;
    }
    
    console.log('Starting scan for:', targetUrl);
    socket.emit('start_scan', { url: targetUrl });
}

// Function to get scan status
function getScanStatus(scanId) {
    if (!scanId) {
        showNotification('No scan ID provided', 'error');
        return;
    }
    
    console.log('Getting status for scan:', scanId);
    socket.emit('get_scan_status', { scan_id: scanId });
}

// Make socket available globally
window.socket = socket;

// Export socket for use in other modules
export { socket }; 