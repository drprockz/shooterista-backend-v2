const { spawn } = require('child_process');
const path = require('path');

console.log('🚀 Starting server with bypassed initialization...');

// Set environment variable to skip problematic initialization
process.env.SKIP_INITIALIZATION = 'true';

const server = spawn('npm', ['run', 'dev'], {
  cwd: path.resolve(__dirname),
  stdio: 'inherit',
  env: {
    ...process.env,
    SKIP_INITIALIZATION: 'true'
  }
});

server.on('close', (code) => {
  console.log(`Server process exited with code ${code}`);
});

server.on('error', (err) => {
  console.error('Failed to start server:', err);
});

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down server...');
  server.kill('SIGINT');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Shutting down server...');
  server.kill('SIGTERM');
  process.exit(0);
});
