/**
 * unsane.ts
 * A lightweight, zero-dependency HTML sanitization library.
 * No DOM or Node required.
 */
export interface SanitizerOptions {
    /**
     * Array of allowed HTML tag names
     */
    allowedTags?: string[];
    /**
     * Object mapping tag names to arrays of allowed attribute names
     */
    allowedAttributes?: Record<string, string[]>;
    /**
     * If true, self-closing tags will have a trailing slash
     */
    selfClosing?: boolean;
    /**
     * Function to transform text content before encoding
     */
    transformText?: (text: string) => string;
}
/**
 * Decode all HTML entities in a string
 */
export declare function decode(text: string): string;
/**
 * Escape special characters to prevent XSS
 */
export declare function escape(text: string): string;
/**
 * Options for entity encoding
 */
interface EncodeOptions {
    useNamedReferences?: boolean;
    encodeEverything?: boolean;
    decimal?: boolean;
}
/**
 * Encode characters to HTML entities
 */
export declare function encode(text: string, options?: EncodeOptions): string;
/**
 * Main sanitizer function
 */
export declare function sanitize(html: string, options?: SanitizerOptions): string;
declare const _default: {
    sanitize: typeof sanitize;
    decode: typeof decode;
    encode: typeof encode;
    escape: typeof escape;
};
export default _default;
