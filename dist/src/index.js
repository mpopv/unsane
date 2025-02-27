"use strict";
/**
 * unsane - A lightweight, zero-dependency HTML sanitization library
 *
 * This library provides HTML sanitization with:
 * - Small footprint (minimal bundle size)
 * - No dependencies (works in any JavaScript environment)
 * - Protection against XSS vectors
 * - Simple, streamlined API
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.decode = exports.encode = exports.escape = exports.sanitize = void 0;
const htmlSanitizer_1 = require("./sanitizer/htmlSanitizer");
Object.defineProperty(exports, "sanitize", { enumerable: true, get: function () { return htmlSanitizer_1.sanitize; } });
const htmlEntities_1 = require("./utils/htmlEntities");
Object.defineProperty(exports, "escape", { enumerable: true, get: function () { return htmlEntities_1.escape; } });
Object.defineProperty(exports, "encode", { enumerable: true, get: function () { return htmlEntities_1.encode; } });
Object.defineProperty(exports, "decode", { enumerable: true, get: function () { return htmlEntities_1.decode; } });
// Create default sanitizer
const sanitizer = { sanitize: htmlSanitizer_1.sanitize };
// Default export for convenience
exports.default = sanitizer;
