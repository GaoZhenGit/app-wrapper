// Minimal loader - only provide what's missing
// The bundle needs 'require' to be available

// Make bun's require available globally for eval
global.require = require;

// Read and execute unwrapped bundle
const code = require('fs').readFileSync(__dirname + '/claude_unwrapped.js', 'utf-8');
eval(code);
