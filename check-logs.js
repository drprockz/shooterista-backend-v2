#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// Function to search for logs containing our request ID
function searchLogs(requestId) {
  console.log(`🔍 Searching for logs with requestId: ${requestId}`);
  
  // Common log file locations
  const logFiles = [
    'app.log',
    'server.log',
    'logs/app.log',
    'logs/server.log',
    'dist/logs/app.log'
  ];
  
  let foundLogs = false;
  
  logFiles.forEach(logFile => {
    if (fs.existsSync(logFile)) {
      console.log(`📄 Checking log file: ${logFile}`);
      const content = fs.readFileSync(logFile, 'utf8');
      const lines = content.split('\n');
      
      const matchingLines = lines.filter(line => 
        line.includes(requestId) || 
        line.includes('register.start') ||
        line.includes('register.error') ||
        line.includes('guard.check.url') ||
        line.includes('guard.block.url_access') ||
        line.includes('url_access_error')
      );
      
      if (matchingLines.length > 0) {
        foundLogs = true;
        console.log(`\n📋 Found ${matchingLines.length} relevant log entries in ${logFile}:`);
        matchingLines.forEach(line => {
          console.log(`  ${line}`);
        });
      }
    }
  });
  
  if (!foundLogs) {
    console.log('❌ No log files found or no matching entries.');
    console.log('💡 Try checking the console output where you started the server.');
  }
}

// Get the request ID from command line argument or use the one from our test
const requestId = process.argv[2] || 'test-1759141084134-f9m20152j';

searchLogs(requestId);
