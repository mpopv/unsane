/**
 * Text security utilities - handling dangerous content in text nodes
 */

import { encode } from './htmlEntities';

// Patterns that should be neutralized in text content 
const DANGEROUS_TEXT_PATTERNS = [
  /javascript/i,
  /script/i,
  /alert\s*\(/i,
  /confirm\s*\(/i,
  /prompt\s*\(/i,
  /eval\s*\(/i,
  /function\s*\(/i,
  /setTimeout\s*\(/i,
  /setInterval\s*\(/i,
  /new\s+Function/i,
  /document\./i,
  /window\./i,
  /onerror\s*=/i,
  /onclick\s*=/i,
  /on\w+\s*=/i
];

/**
 * Sanitize text content by encoding known dangerous patterns
 * 
 * @param text Text content to sanitize
 * @returns Sanitized text where dangerous patterns are HTML encoded
 */
export function sanitizeTextContent(text: string): string {
  if (!text) return '';
  
  let result = text;
  
  // Encode dangerous patterns
  for (const pattern of DANGEROUS_TEXT_PATTERNS) {
    result = result.replace(pattern, (match) => {
      return encode(match, { useNamedReferences: true });
    });
  }
  
  return result;
}

/**
 * More aggressive sanitization that also breaks up function calls and parentheses
 * to prevent execution of code patterns
 * 
 * @param text Text to sanitize
 * @returns Sanitized text
 */
export function sanitizeAggressively(text: string): string {
  if (!text) return '';
  
  // First encode all dangerous patterns
  let result = sanitizeTextContent(text);
  
  // Also encode parentheses and other execution-related chars
  result = result.replace(/[\(\)\[\]\{\}=:;]/g, (match) => {
    return encode(match, { useNamedReferences: true });
  });
  
  return result;
}

export default {
  sanitizeTextContent,
  sanitizeAggressively
};