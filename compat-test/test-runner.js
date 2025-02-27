#!/usr/bin/env node

/**
 * Test runner for Unsane compatibility with DOMPurify
 */

import path from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';
import fs from 'fs';

// Get current directory in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Define test filenames
const compatTest = path.join(__dirname, 'compatibility-test.js');
const xssTest = path.join(__dirname, 'xss-test.js');

// Run the tests
try {
  console.log('Running compatibility tests...');
  console.log('-------------------------------------------------------------');
  
  // Run basic compatibility tests
  execSync(`node --test ${compatTest}`, { stdio: 'inherit' });
  
  // Run XSS tests if they exist
  try {
    if (fs.existsSync(xssTest)) {
      console.log('\nRunning XSS prevention tests...');
      console.log('-------------------------------------------------------------');
      execSync(`node --test ${xssTest}`, { stdio: 'inherit' });
    }
  } catch (e) {
    console.error('Error running XSS tests:', e.message);
  }
  
  console.log('\nAll tests completed!');
} catch (error) {
  console.error('Error running tests:', error.message);
  process.exit(1);
}