/**
 * Security utilities for HTML sanitization
 */

// Interface for encoder options
export interface EncodeOptions {
  useNamedReferences?: boolean;
  encodeEverything?: boolean;
  decimal?: boolean;
  escapeOnly?: boolean;
}

// Only these protocols are allowed (allowlist approach)
export const ALLOWED_PROTOCOLS = new Set([
  "http:",
  "https:", 
  "mailto:",
  "tel:",
  "ftp:", 
  "sms:"
]);

// List of dangerous content patterns
export const DANGEROUS_CONTENT = [
  // Code execution
  "javascript",
  "eval(",
  "new Function",
  "setTimeout(",
  "setInterval(",

  // XSS common vectors
  "alert(",
  "confirm(",
  "prompt(",
  "document.",
  "window.",

  // Event handlers
  "onerror=",
  "onclick=",
  "onload=",
  "onmouseover=",
];

// Set of dangerous attribute names that should be blocked
export const DANGEROUS_ATTRIBUTES = new Set([
  // Event handlers (all on* attributes)
  "onabort", "onblur", "oncanplay", "oncanplaythrough", "onchange",
  "onclick", "oncontextmenu", "oncopy", "oncut", "ondblclick", 
  "ondrag", "ondragend", "ondragenter", "ondragleave", "ondragover",
  "ondragstart", "ondrop", "ondurationchange", "onemptied", "onended",
  "onerror", "onfocus", "onformdata", "oninput", "oninvalid", "onkeydown",
  "onkeypress", "onkeyup", "onload", "onloadeddata", "onloadedmetadata",
  "onloadstart", "onmousedown", "onmouseenter", "onmouseleave", "onmousemove",
  "onmouseout", "onmouseover", "onmouseup", "onpaste", "onpause", "onplay",
  "onplaying", "onprogress", "onratechange", "onreset", "onresize", "onscroll",
  "onsecuritypolicyviolation", "onseeked", "onseeking", "onselect", "onslotchange",
  "onstalled", "onsubmit", "onsuspend", "ontimeupdate", "ontoggle", "onvolumechange",
  "onwaiting", "onwheel",
  
  // Style can contain expressions in some browsers
  "style",
  
  // Form actions that can execute JavaScript
  "formaction",
  "action",
  
  // SVG-specific dangerous attributes
  "xlink:href"
]);

/**
 * Check if an attribute name is considered dangerous (centralized logic)
 * 
 * @param name The attribute name to check
 * @returns True if the attribute is dangerous and should be removed
 */
export function isDangerousAttribute(name: string): boolean {
  if (!name) return false;
  
  const lowerName = name.toLowerCase();
  
  // Block all on* event handlers
  if (lowerName.startsWith('on')) {
    return true;
  }
  
  // Check against our set of known dangerous attributes
  return DANGEROUS_ATTRIBUTES.has(lowerName);
}

/**
 * Check if a URL is safe (non-JavaScript and allowed protocol)
 * 
 * @param url The URL to check
 * @returns True if the URL is safe
 */
export function isSafeUrl(url: string): boolean {
  if (!url) return true;
  
  // Normalize for comparison
  const normalized = url.toLowerCase().replace(/\s+/g, "");
  
  // Check for URL protocols and only allow from our explicit allowlist
  const protocolMatch = normalized.match(/^([a-z0-9.+-]+):/i);
  if (protocolMatch) {
    const protocol = protocolMatch[1].toLowerCase() + ':';
    // If a protocol is found but it's not in our allowlist, reject it
    if (!ALLOWED_PROTOCOLS.has(protocol)) {
      return false;
    }
  }
  
  return true;
}

/**
 * Check if a value contains dangerous content like script, JavaScript,
 * event handlers or other potentially harmful patterns
 *
 * @param value The string to check
 * @returns True if the value contains dangerous content
 */
export function containsDangerousContent(value: string): boolean {
  if (!value) return false;

  // Normalize for comparison
  const normalized = value.toLowerCase().replace(/\s+/g, "");
  
  // First check if it's a URL - rely on our URL security function
  const protocolMatch = normalized.match(/^([a-z0-9.+-]+):/i);
  if (protocolMatch) {
    return !isSafeUrl(normalized);
  }

  // Check for dangerous content patterns
  for (const pattern of DANGEROUS_CONTENT) {
    if (normalized.includes(pattern.toLowerCase())) {
      return true;
    }
  }

  // Check for control characters and Unicode obfuscation
  if (
    normalized.includes("\\u0000") ||
    normalized.includes("\u0000") || // Actual null character
    // Control characters
    normalized.split("").some((char) => {
      const code = char.charCodeAt(0);
      return code <= 0x1f || (code >= 0x7f && code <= 0x9f);
    }) ||
    // Check for zero-width characters used for obfuscation
    normalized.includes("\u200c") || // Zero-width non-joiner
    normalized.includes("\u200d") || // Zero-width joiner
    normalized.includes("\u2028") || // Line separator 
    normalized.includes("\u2029") || // Paragraph separator
    normalized.includes("\ufeff")    // Zero-width no-break space
  ) {
    return true;
  }

  return false;
}

/**
 * Check attribute safety in a comprehensive way
 * 
 * @param name Attribute name
 * @param value Attribute value
 * @returns Object indicating if safe and reason if not
 */
export function checkAttributeSafety(name: string, value: string): { safe: boolean; reason?: string } {
  if (!name) return { safe: false, reason: "empty-name" };
  
  const lowerName = name.toLowerCase();
  
  // Check if the attribute name itself is dangerous
  if (isDangerousAttribute(lowerName)) {
    return { safe: false, reason: "dangerous-attr-name" };
  }
  
  // No value is safe (boolean attribute)
  if (!value) return { safe: true };
  
  // URL attributes need special checking
  const urlAttributes = new Set(["href", "src", "action", "formaction", "xlink:href"]);
  if (urlAttributes.has(lowerName)) {
    if (!isSafeUrl(value)) {
      return { safe: false, reason: "unsafe-url" };
    }
  }
  
  // Check for dangerous content in all attributes
  if (containsDangerousContent(value)) {
    return { safe: false, reason: "dangerous-content" };
  }
  
  return { safe: true };
}

/**
 * Sanitize text content by removing or encoding potentially dangerous patterns
 *
 * @param text Text to sanitize
 * @param encode Function to encode unsafe content
 * @returns Sanitized text
 */
export function sanitizeTextContent(
  text: string,
  encodeFunc?: (s: string, o?: EncodeOptions) => string
): string {
  if (!text) return "";

  // Simple regex pattern for common dangerous strings
  const dangerousPattern =
    /javascript|script|alert|eval|onerror|onclick|on\w+\s*=|\(\s*\)|function/gi;

  // Use the provided encode function or default to a basic encoder
  const encoder = encodeFunc || ((s: string) => s);

  return text.replace(dangerousPattern, (match) =>
    encoder(match, { useNamedReferences: true })
  );
}

// No default export
