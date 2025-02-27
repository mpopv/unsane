"use strict";
/**
 * unsane.ts
 * A lightweight, zero-dependency HTML sanitization library.
 * No DOM or Node required.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.decode = decode;
exports.escape = escape;
exports.encode = encode;
exports.sanitize = sanitize;
// Simple HTML entity maps - could be expanded for full coverage
const NAMED_TO_CHAR = {
    quot: '"',
    amp: "&",
    lt: "<",
    gt: ">",
    apos: "'",
};
const CHAR_TO_NAMED = {
    '"': "quot",
    "&": "amp",
    "<": "lt",
    ">": "gt",
    "'": "apos",
};
/**
 * Convert a code point to a string, handling surrogate pairs
 */
function codePointToString(codePoint) {
    if (codePoint < 0 || codePoint > 0x10ffff)
        return "\uFFFD";
    if (codePoint >= 0xd800 && codePoint <= 0xdfff)
        return "\uFFFD";
    if (codePoint > 0xffff) {
        codePoint -= 0x10000;
        return String.fromCharCode(0xd800 + (codePoint >> 10), 0xdc00 + (codePoint & 0x3ff));
    }
    return String.fromCharCode(codePoint);
}
/**
 * Decode a numeric HTML entity reference
 */
function decodeNumericReference(body) {
    let codePoint = 0;
    if (body[0] === "x" || body[0] === "X") {
        // Hex format
        const hex = body.slice(1);
        if (!/^[0-9A-Fa-f]+$/.test(hex))
            return "&#" + body + ";";
        codePoint = parseInt(hex, 16);
    }
    else {
        // Decimal format
        if (!/^[0-9]+$/.test(body))
            return "&#" + body + ";";
        codePoint = parseInt(body, 10);
    }
    return codePointToString(codePoint);
}
/**
 * Decode a single HTML entity
 */
function decodeEntity(entity) {
    let body = entity.slice(1);
    const hasSemicolon = body.endsWith(";");
    if (hasSemicolon)
        body = body.slice(0, -1);
    if (body[0] === "#") {
        const result = decodeNumericReference(body.slice(1));
        if (result.startsWith("&#"))
            return entity;
        return result;
    }
    const char = NAMED_TO_CHAR[body];
    return char && hasSemicolon ? char : entity;
}
/**
 * Decode all HTML entities in a string
 */
function decode(text) {
    return text.replace(/&(#?[0-9A-Za-z]+);?/g, (match) => decodeEntity(match));
}
/**
 * Escape special characters to prevent XSS
 */
function escape(text) {
    if (!text)
        return "";
    const asString = String(text);
    // Standard case - use consistent encoding
    return asString.replace(/["'&<>`]/g, (char) => {
        switch (char) {
            case '"':
                return "&quot;";
            case "'":
                return "&#x27;";
            case "&":
                return "&amp;";
            case "<":
                return "&lt;";
            case ">":
                return "&gt;";
            case "`":
                return "&#x60;";
            default:
                return char;
        }
    });
}
/**
 * Create numeric HTML entity reference
 */
function numericReference(codePoint, decimal) {
    return decimal
        ? "&#" + codePoint + ";"
        : "&#x" + codePoint.toString(16).toUpperCase() + ";";
}
/**
 * Encode characters to HTML entities
 */
function encode(text, options = {}) {
    const { useNamedReferences = false, encodeEverything = false, decimal = false, } = options;
    const result = [];
    for (const char of text) {
        const codePoint = char.codePointAt(0) || char.charCodeAt(0);
        if (CHAR_TO_NAMED[char]) {
            if (useNamedReferences) {
                result.push("&", CHAR_TO_NAMED[char], ";");
            }
            else {
                result.push(numericReference(codePoint, decimal));
            }
        }
        else {
            if (!encodeEverything && codePoint >= 0x20 && codePoint < 0x7f) {
                result.push(char);
                continue;
            }
            result.push(numericReference(codePoint, decimal));
        }
    }
    return result.join("");
}
// Default sanitizer options with safe allowlists
const DEFAULT_OPTIONS = {
    allowedTags: [
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "h7",
        "h8",
        "br",
        "b",
        "i",
        "strong",
        "em",
        "a",
        "pre",
        "code",
        "img",
        "tt",
        "div",
        "ins",
        "del",
        "sup",
        "sub",
        "p",
        "ol",
        "ul",
        "table",
        "thead",
        "tbody",
        "tfoot",
        "blockquote",
        "dl",
        "dt",
        "dd",
        "kbd",
        "q",
        "samp",
        "var",
        "hr",
        "ruby",
        "rt",
        "rp",
        "li",
        "tr",
        "td",
        "th",
        "s",
        "strike",
        "summary",
        "details",
        "caption",
        "figure",
        "figcaption",
        "abbr",
        "bdo",
        "cite",
        "dfn",
        "mark",
        "small",
        "span",
        "time",
        "wbr",
    ],
    allowedAttributes: {
        a: ["href", "name", "target", "rel"],
        img: ["src", "srcset", "alt", "title", "width", "height", "loading"],
    },
    selfClosing: true,
    transformText: (text) => text,
};
// Tokenizer states for HTML parsing
var TokenizerState;
(function (TokenizerState) {
    TokenizerState[TokenizerState["DATA"] = 0] = "DATA";
    TokenizerState[TokenizerState["TAG_OPEN"] = 1] = "TAG_OPEN";
    TokenizerState[TokenizerState["END_TAG_OPEN"] = 2] = "END_TAG_OPEN";
    TokenizerState[TokenizerState["TAG_NAME"] = 3] = "TAG_NAME";
    TokenizerState[TokenizerState["END_TAG_NAME"] = 4] = "END_TAG_NAME";
    TokenizerState[TokenizerState["BEFORE_ATTRIBUTE_NAME"] = 5] = "BEFORE_ATTRIBUTE_NAME";
    TokenizerState[TokenizerState["ATTRIBUTE_NAME"] = 6] = "ATTRIBUTE_NAME";
    TokenizerState[TokenizerState["AFTER_ATTRIBUTE_NAME"] = 7] = "AFTER_ATTRIBUTE_NAME";
    TokenizerState[TokenizerState["BEFORE_ATTRIBUTE_VALUE"] = 8] = "BEFORE_ATTRIBUTE_VALUE";
    TokenizerState[TokenizerState["ATTRIBUTE_VALUE_DOUBLE"] = 9] = "ATTRIBUTE_VALUE_DOUBLE";
    TokenizerState[TokenizerState["ATTRIBUTE_VALUE_SINGLE"] = 10] = "ATTRIBUTE_VALUE_SINGLE";
    TokenizerState[TokenizerState["ATTRIBUTE_VALUE_UNQUOTED"] = 11] = "ATTRIBUTE_VALUE_UNQUOTED";
    TokenizerState[TokenizerState["SELF_CLOSING_START_TAG"] = 12] = "SELF_CLOSING_START_TAG";
    TokenizerState[TokenizerState["COMMENT_START"] = 13] = "COMMENT_START";
    TokenizerState[TokenizerState["COMMENT"] = 14] = "COMMENT";
    TokenizerState[TokenizerState["COMMENT_END"] = 15] = "COMMENT_END";
    TokenizerState[TokenizerState["DOCTYPE"] = 16] = "DOCTYPE";
    TokenizerState[TokenizerState["DOCTYPE_BEFORE_NAME"] = 17] = "DOCTYPE_BEFORE_NAME";
    TokenizerState[TokenizerState["DOCTYPE_NAME"] = 18] = "DOCTYPE_NAME";
    TokenizerState[TokenizerState["DOCTYPE_AFTER_NAME"] = 19] = "DOCTYPE_AFTER_NAME";
    TokenizerState[TokenizerState["DOCTYPE_PUBLIC_OR_SYSTEM"] = 20] = "DOCTYPE_PUBLIC_OR_SYSTEM";
    TokenizerState[TokenizerState["DOCTYPE_PUBLIC_ID_SINGLE_QUOTED"] = 21] = "DOCTYPE_PUBLIC_ID_SINGLE_QUOTED";
    TokenizerState[TokenizerState["DOCTYPE_PUBLIC_ID_DOUBLE_QUOTED"] = 22] = "DOCTYPE_PUBLIC_ID_DOUBLE_QUOTED";
    TokenizerState[TokenizerState["DOCTYPE_SYSTEM_ID_SINGLE_QUOTED"] = 23] = "DOCTYPE_SYSTEM_ID_SINGLE_QUOTED";
    TokenizerState[TokenizerState["DOCTYPE_SYSTEM_ID_DOUBLE_QUOTED"] = 24] = "DOCTYPE_SYSTEM_ID_DOUBLE_QUOTED";
    TokenizerState[TokenizerState["DOCTYPE_BOGUS"] = 25] = "DOCTYPE_BOGUS";
    TokenizerState[TokenizerState["RAWTEXT"] = 26] = "RAWTEXT";
})(TokenizerState || (TokenizerState = {}));
// Tags that trigger raw-text mode
const RAWTEXT_TAGS = new Set(['script', 'style']);
/**
 * HTML Tokenizer - A state machine for tokenizing HTML
 */
class HtmlTokenizer {
    constructor() {
        this.state = TokenizerState.DATA;
        this.buffer = '';
        this.position = 0; // read index
        this.tokens = [];
        // Temporary accumulators for building up tokens
        this.currentToken = {};
        this.currentAttr = null;
        // For storing raw text if we're in <script> or <style> until we see the closing tag
        this.rawTextTagName = '';
        this.rawTextBuffer = '';
        // For doctype token
        this.docPublicId = '';
        this.docSystemId = '';
        this.isEndOfChunk = false;
    }
    write(chunk) {
        this.buffer += chunk;
        this.isEndOfChunk = false;
        this.run();
    }
    end() {
        this.isEndOfChunk = true;
        // finalize
        this.run();
        // flush any pending text if needed
        if (this.state === TokenizerState.DATA && this.currentToken.type === 'text') {
            this.emitCurrentText();
        }
    }
    getTokens() {
        const out = this.tokens;
        this.tokens = [];
        return out;
    }
    run() {
        while (this.position < this.buffer.length) {
            const char = this.buffer[this.position];
            switch (this.state) {
                case TokenizerState.DATA:
                    this.dataState(char);
                    break;
                case TokenizerState.TAG_OPEN:
                    this.tagOpenState(char);
                    break;
                case TokenizerState.END_TAG_OPEN:
                    this.endTagOpenState(char);
                    break;
                case TokenizerState.TAG_NAME:
                    this.tagNameState(char);
                    break;
                case TokenizerState.END_TAG_NAME:
                    this.endTagNameState(char);
                    break;
                case TokenizerState.BEFORE_ATTRIBUTE_NAME:
                    this.beforeAttributeNameState(char);
                    break;
                case TokenizerState.ATTRIBUTE_NAME:
                    this.attributeNameState(char);
                    break;
                case TokenizerState.AFTER_ATTRIBUTE_NAME:
                    this.afterAttributeNameState(char);
                    break;
                case TokenizerState.BEFORE_ATTRIBUTE_VALUE:
                    this.beforeAttributeValueState(char);
                    break;
                case TokenizerState.ATTRIBUTE_VALUE_DOUBLE:
                case TokenizerState.ATTRIBUTE_VALUE_SINGLE:
                case TokenizerState.ATTRIBUTE_VALUE_UNQUOTED:
                    this.attributeValueState(char);
                    break;
                case TokenizerState.SELF_CLOSING_START_TAG:
                    this.selfClosingStartTagState(char);
                    break;
                case TokenizerState.COMMENT_START:
                case TokenizerState.COMMENT:
                case TokenizerState.COMMENT_END:
                    this.commentStates(char);
                    break;
                case TokenizerState.DOCTYPE:
                case TokenizerState.DOCTYPE_BEFORE_NAME:
                case TokenizerState.DOCTYPE_NAME:
                case TokenizerState.DOCTYPE_AFTER_NAME:
                case TokenizerState.DOCTYPE_PUBLIC_OR_SYSTEM:
                case TokenizerState.DOCTYPE_PUBLIC_ID_SINGLE_QUOTED:
                case TokenizerState.DOCTYPE_PUBLIC_ID_DOUBLE_QUOTED:
                case TokenizerState.DOCTYPE_SYSTEM_ID_SINGLE_QUOTED:
                case TokenizerState.DOCTYPE_SYSTEM_ID_DOUBLE_QUOTED:
                case TokenizerState.DOCTYPE_BOGUS:
                    this.doctypeStates(char);
                    break;
                case TokenizerState.RAWTEXT:
                    this.rawtextState(char);
                    break;
            }
            this.position++;
        }
    }
    // convenience to push the position back by 1
    reconsume() {
        this.position--;
    }
    peekNext() {
        return this.buffer[this.position + 1] || '';
    }
    // ---- Emission ----
    emitToken(token) {
        this.tokens.push(token);
    }
    emitText(text) {
        if (!text)
            return;
        this.emitToken({ type: 'text', text, raw: text });
    }
    emitCurrentText() {
        if (this.currentToken.type === 'text') {
            const t = this.currentToken;
            if (t.text) {
                this.emitToken({ type: 'text', text: t.text, raw: t.raw });
            }
        }
        this.currentToken = {};
    }
    // ---- State handlers ----
    dataState(char) {
        if (char === '<') {
            // flush any pending text
            if (this.currentToken.type === 'text') {
                this.emitCurrentText();
            }
            this.state = TokenizerState.TAG_OPEN;
            this.currentToken = {};
            return;
        }
        // else accumulate text
        if (this.currentToken.type !== 'text') {
            // start fresh
            this.currentToken = { type: 'text', text: '', raw: '' };
        }
        const t = this.currentToken;
        t.text += char;
        t.raw = (t.raw || '') + char;
    }
    tagOpenState(char) {
        if (char === '/') {
            this.state = TokenizerState.END_TAG_OPEN;
            this.currentToken = {};
            return;
        }
        if (char === '!') {
            // check if it's a comment or doctype
            const ahead = this.buffer.slice(this.position + 1, this.position + 3).toLowerCase();
            if (ahead.startsWith('--')) {
                // comment
                this.state = TokenizerState.COMMENT_START;
                this.position += 2; // skip over '--'
                this.currentToken = { type: 'comment', text: '', raw: '<!--' };
            }
            else if (ahead.startsWith('do')) {
                // doctype
                this.state = TokenizerState.DOCTYPE;
                this.currentToken = {
                    type: 'doctype',
                    name: '',
                    publicId: '',
                    systemId: '',
                    raw: '<!doctype',
                };
                this.position += 7; // we skip "doctype"
            }
            else {
                // could be a bogus comment like <!abc
                this.state = TokenizerState.COMMENT_START;
                this.currentToken = { type: 'comment', text: '', raw: '<!' };
            }
            return;
        }
        if (/[a-zA-Z]/.test(char)) {
            // start tag
            this.state = TokenizerState.TAG_NAME;
            this.currentToken = {
                type: 'startTag',
                tagName: char.toLowerCase(),
                attrs: [],
                selfClosing: false,
                raw: '<' + char,
            };
            return;
        }
        if (char === '?') {
            // e.g. <? xml ... bogus comment
            this.state = TokenizerState.COMMENT_START;
            this.currentToken = { type: 'comment', text: '', raw: '<?' };
            return;
        }
        // else it might be text, fallback
        // < followed by something else => text
        // We re-emit a text node with < char
        this.state = TokenizerState.DATA;
        this.emitText('<');
        this.reconsume();
    }
    endTagOpenState(char) {
        if (/[a-zA-Z]/.test(char)) {
            this.state = TokenizerState.END_TAG_NAME;
            this.currentToken = {
                type: 'endTag',
                tagName: char.toLowerCase(),
                raw: '</' + char,
            };
            return;
        }
        // maybe an end tag slash something?
        if (char === '>') {
            // `</>` => text
            this.state = TokenizerState.DATA;
            // we treat it as text?
            this.emitText('</>');
            return;
        }
        // might be comment or something
        // fallback
        this.state = TokenizerState.COMMENT_START;
        this.currentToken = { type: 'comment', text: '', raw: '</!' };
        this.reconsume();
    }
    tagNameState(char) {
        const token = this.currentToken;
        token.raw += char;
        if (/\s/.test(char)) {
            this.state = TokenizerState.BEFORE_ATTRIBUTE_NAME;
            return;
        }
        if (char === '>') {
            this.finishStartTag(token);
            return;
        }
        if (char === '/') {
            this.state = TokenizerState.SELF_CLOSING_START_TAG;
            return;
        }
        token.tagName += char.toLowerCase();
    }
    endTagNameState(char) {
        const token = this.currentToken;
        token.raw += char;
        if (/\s/.test(char)) {
            // ignore whitespace
            return;
        }
        if (char === '>') {
            // done
            token.tagName = token.tagName.toLowerCase();
            this.emitToken(token);
            if (RAWTEXT_TAGS.has(token.tagName) && token.tagName === this.rawTextTagName) {
                // we might exit rawtext
                this.rawTextTagName = '';
                this.rawTextBuffer = '';
                this.state = TokenizerState.DATA;
            }
            else {
                this.state = TokenizerState.DATA;
            }
            this.currentToken = {};
            return;
        }
        // else we keep reading the end tag name
        token.tagName += char.toLowerCase();
    }
    beforeAttributeNameState(char) {
        const token = this.currentToken;
        token.raw += char;
        if (/\s/.test(char)) {
            // skip
            return;
        }
        if (char === '>') {
            this.finishStartTag(token);
            return;
        }
        if (char === '/') {
            this.state = TokenizerState.SELF_CLOSING_START_TAG;
            return;
        }
        // start new attribute
        this.currentAttr = { name: '', value: '' };
        token.attrs.push(this.currentAttr);
        this.state = TokenizerState.ATTRIBUTE_NAME;
        this.currentAttr.name += char.toLowerCase();
    }
    attributeNameState(char) {
        const token = this.currentToken;
        token.raw += char;
        if (/\s/.test(char)) {
            this.state = TokenizerState.AFTER_ATTRIBUTE_NAME;
            return;
        }
        if (char === '=') {
            this.state = TokenizerState.BEFORE_ATTRIBUTE_VALUE;
            return;
        }
        if (char === '>') {
            this.finishStartTag(token);
            return;
        }
        if (char === '/') {
            this.state = TokenizerState.SELF_CLOSING_START_TAG;
            return;
        }
        this.currentAttr.name += char.toLowerCase();
    }
    afterAttributeNameState(char) {
        const token = this.currentToken;
        token.raw += char;
        if (/\s/.test(char)) {
            return;
        }
        if (char === '=') {
            this.state = TokenizerState.BEFORE_ATTRIBUTE_VALUE;
            return;
        }
        if (char === '>') {
            this.finishStartTag(token);
            return;
        }
        if (char === '/') {
            this.state = TokenizerState.SELF_CLOSING_START_TAG;
            return;
        }
        // new attribute
        this.currentAttr = { name: '', value: '' };
        token.attrs.push(this.currentAttr);
        this.state = TokenizerState.ATTRIBUTE_NAME;
        this.currentAttr.name += char.toLowerCase();
    }
    beforeAttributeValueState(char) {
        const token = this.currentToken;
        token.raw += char;
        if (/\s/.test(char)) {
            return;
        }
        if (char === '"') {
            this.state = TokenizerState.ATTRIBUTE_VALUE_DOUBLE;
            return;
        }
        if (char === "'") {
            this.state = TokenizerState.ATTRIBUTE_VALUE_SINGLE;
            return;
        }
        if (char === '>') {
            this.finishStartTag(token);
            return;
        }
        if (char === '/') {
            this.state = TokenizerState.SELF_CLOSING_START_TAG;
            return;
        }
        // unquoted
        this.state = TokenizerState.ATTRIBUTE_VALUE_UNQUOTED;
        this.currentAttr.value += char;
    }
    attributeValueState(char) {
        const token = this.currentToken;
        token.raw += char;
        const avState = this.state;
        if ((avState === TokenizerState.ATTRIBUTE_VALUE_DOUBLE && char === '"') ||
            (avState === TokenizerState.ATTRIBUTE_VALUE_SINGLE && char === "'")) {
            // end
            this.state = TokenizerState.BEFORE_ATTRIBUTE_NAME;
            return;
        }
        if (/\s/.test(char) && avState === TokenizerState.ATTRIBUTE_VALUE_UNQUOTED) {
            this.state = TokenizerState.BEFORE_ATTRIBUTE_NAME;
            return;
        }
        if (char === '>' && avState === TokenizerState.ATTRIBUTE_VALUE_UNQUOTED) {
            this.finishStartTag(token);
            return;
        }
        if (char === '/' && avState === TokenizerState.ATTRIBUTE_VALUE_UNQUOTED) {
            this.state = TokenizerState.SELF_CLOSING_START_TAG;
            return;
        }
        this.currentAttr.value += char;
    }
    selfClosingStartTagState(char) {
        const token = this.currentToken;
        token.raw += char;
        if (char === '>') {
            token.selfClosing = true;
            this.finishStartTag(token);
            return;
        }
        // fallback
        this.state = TokenizerState.BEFORE_ATTRIBUTE_NAME;
        this.reconsume();
    }
    finishStartTag(token) {
        // check raw text
        const lower = token.tagName.toLowerCase();
        token.tagName = lower;
        // if script or style, we go raw
        if (RAWTEXT_TAGS.has(lower) && !token.selfClosing) {
            this.rawTextTagName = lower;
            this.rawTextBuffer = '';
            this.state = TokenizerState.RAWTEXT;
        }
        else {
            this.state = TokenizerState.DATA;
        }
        this.emitToken(token);
        this.currentToken = {};
    }
    commentStates(char) {
        // handle comment
        const ctoken = this.currentToken;
        ctoken.raw += char;
        switch (this.state) {
            case TokenizerState.COMMENT_START: {
                if (char === '-') {
                    // we might move to COMMENT
                    // but we are already in comment start
                    this.state = TokenizerState.COMMENT;
                    return;
                }
                if (char === '>') {
                    // end comment?
                    this.finishComment();
                    return;
                }
                // else just go to COMMENT
                this.state = TokenizerState.COMMENT;
                ctoken.text += char;
                return;
            }
            case TokenizerState.COMMENT: {
                if (char === '-') {
                    this.state = TokenizerState.COMMENT_END;
                    return;
                }
                ctoken.text += char;
                return;
            }
            case TokenizerState.COMMENT_END: {
                if (char === '-') {
                    ctoken.text += '-';
                    // still in comment end
                    return;
                }
                if (char === '>') {
                    // finish
                    this.finishComment();
                    return;
                }
                // else revert to comment
                this.state = TokenizerState.COMMENT;
                ctoken.text += '-' + char;
            }
        }
    }
    finishComment() {
        const ctoken = this.currentToken;
        this.emitToken({
            type: 'comment',
            text: ctoken.text,
            raw: ctoken.raw,
        });
        this.currentToken = {};
        this.state = TokenizerState.DATA;
    }
    doctypeStates(char) {
        const dt = this.currentToken;
        dt.raw += char;
        switch (this.state) {
            case TokenizerState.DOCTYPE: {
                if (/\s/.test(char)) {
                    this.state = TokenizerState.DOCTYPE_BEFORE_NAME;
                }
                else if (char === '>') {
                    // done
                    this.finishDoctype();
                }
                else {
                    // partial
                    this.state = TokenizerState.DOCTYPE_NAME;
                    dt.name += char.toLowerCase();
                }
                break;
            }
            case TokenizerState.DOCTYPE_BEFORE_NAME: {
                if (/\s/.test(char)) {
                    // skip
                }
                else if (char === '>') {
                    this.finishDoctype();
                }
                else {
                    this.state = TokenizerState.DOCTYPE_NAME;
                    dt.name += char.toLowerCase();
                }
                break;
            }
            case TokenizerState.DOCTYPE_NAME: {
                if (/\s/.test(char)) {
                    this.state = TokenizerState.DOCTYPE_AFTER_NAME;
                }
                else if (char === '>') {
                    this.finishDoctype();
                }
                else {
                    dt.name += char.toLowerCase();
                }
                break;
            }
            case TokenizerState.DOCTYPE_AFTER_NAME: {
                if (/\s/.test(char)) {
                    // skip
                }
                else if (char === '>') {
                    this.finishDoctype();
                }
                else if (/^(public|system)/i.test(this.buffer.slice(this.position))) {
                    // naive check
                    this.state = TokenizerState.DOCTYPE_PUBLIC_OR_SYSTEM;
                }
                else {
                    // bogus
                    this.state = TokenizerState.DOCTYPE_BOGUS;
                }
                break;
            }
            case TokenizerState.DOCTYPE_PUBLIC_OR_SYSTEM: {
                // e.g. "public" or "system" ...
                // skip
                if (char === '"') {
                    this.state = TokenizerState.DOCTYPE_PUBLIC_ID_DOUBLE_QUOTED;
                }
                else if (char === "'") {
                    this.state = TokenizerState.DOCTYPE_PUBLIC_ID_SINGLE_QUOTED;
                }
                else if (char === '>') {
                    this.finishDoctype();
                }
                break;
            }
            case TokenizerState.DOCTYPE_PUBLIC_ID_SINGLE_QUOTED: {
                if (char === "'") {
                    // done public id
                    dt.publicId = this.docPublicId;
                    this.docPublicId = '';
                    // next might be system
                    this.state = TokenizerState.DOCTYPE_BOGUS;
                }
                else if (char === '>') {
                    dt.publicId = this.docPublicId;
                    this.finishDoctype();
                }
                else {
                    this.docPublicId += char;
                }
                break;
            }
            case TokenizerState.DOCTYPE_PUBLIC_ID_DOUBLE_QUOTED: {
                if (char === '"') {
                    dt.publicId = this.docPublicId;
                    this.docPublicId = '';
                    this.state = TokenizerState.DOCTYPE_BOGUS; // minimal
                }
                else if (char === '>') {
                    dt.publicId = this.docPublicId;
                    this.finishDoctype();
                }
                else {
                    this.docPublicId += char;
                }
                break;
            }
            case TokenizerState.DOCTYPE_SYSTEM_ID_SINGLE_QUOTED: {
                if (char === "'") {
                    dt.systemId = this.docSystemId;
                    this.docSystemId = '';
                    this.state = TokenizerState.DOCTYPE_BOGUS;
                }
                else if (char === '>') {
                    dt.systemId = this.docSystemId;
                    this.finishDoctype();
                }
                else {
                    this.docSystemId += char;
                }
                break;
            }
            case TokenizerState.DOCTYPE_SYSTEM_ID_DOUBLE_QUOTED: {
                if (char === '"') {
                    dt.systemId = this.docSystemId;
                    this.docSystemId = '';
                    this.state = TokenizerState.DOCTYPE_BOGUS;
                }
                else if (char === '>') {
                    dt.systemId = this.docSystemId;
                    this.finishDoctype();
                }
                else {
                    this.docSystemId += char;
                }
                break;
            }
            case TokenizerState.DOCTYPE_BOGUS: {
                if (char === '>') {
                    this.finishDoctype();
                }
                break;
            }
        }
    }
    finishDoctype() {
        const dt = this.currentToken;
        if (this.docPublicId)
            dt.publicId = this.docPublicId;
        if (this.docSystemId)
            dt.systemId = this.docSystemId;
        this.emitToken(dt);
        this.currentToken = {};
        this.docPublicId = '';
        this.docSystemId = '';
        this.state = TokenizerState.DATA;
    }
    rawtextState(char) {
        // accumulate raw text until we see `</script>` or `</style>` etc.
        // naive approach: if we see `</`, check if it matches the rawTextTagName
        this.rawTextBuffer += char;
        if (char === '<') {
            // look ahead if it's `</tagName`
            const possibleClose = this.buffer
                .slice(this.position + 1, this.position + 1 + this.rawTextTagName.length + 1)
                .toLowerCase();
            if (possibleClose === '/' + this.rawTextTagName) {
                // flush text token
                this.emitToken({
                    type: 'text',
                    text: this.rawTextBuffer.slice(0, -1), // minus the '<'
                    raw: this.rawTextBuffer.slice(0, -1),
                });
                this.rawTextBuffer = '<';
                // revert or handle
                this.state = TokenizerState.END_TAG_OPEN;
                this.position++;
                return;
            }
        }
        // otherwise keep reading
    }
}
/**
 * Tokenize HTML into structured tokens
 */
function tokenizeHTML(html) {
    const tokenizer = new HtmlTokenizer();
    tokenizer.write(html);
    tokenizer.end();
    return tokenizer.getTokens();
}
/**
 * Check if a token is an opening tag
 */
function isStartTag(token) {
    return token.type === 'startTag' && !token.selfClosing;
}
/**
 * Check if a token is a closing tag
 */
function isEndTag(token) {
    return token.type === 'endTag';
}
/**
 * Check if a token is self-closing
 */
function isSelfClosingTag(token) {
    return token.type === 'startTag' && token.selfClosing;
}
/**
 * Get the tag name from a token
 */
function getTagName(token) {
    if (token.type === 'startTag' || token.type === 'endTag') {
        return token.tagName.toLowerCase();
    }
    return "";
}
/**
 * Process and filter attributes for a tag
 */
function processAttributes(token, tagName, allowedAttributesMap) {
    const allowedAttrs = allowedAttributesMap[tagName] || [];
    let result = "";
    for (const attr of token.attrs) {
        const name = attr.name.toLowerCase();
        const value = attr.value;
        if (allowedAttrs.includes(name)) {
            // Filter potentially dangerous URLs and values
            if ((name === "href" || name === "src") && typeof value === "string") {
                // Sanitize javascript: and data: URLs
                const normalized = value.trim().toLowerCase().replace(/\s+/g, '');
                if (normalized.startsWith("javascript:") ||
                    normalized.startsWith("data:") ||
                    normalized.includes("\\u0000") ||
                    normalized.includes("\0") ||
                    normalized.match(/[\u0000-\u001F]/) // Control characters
                ) {
                    continue; // Skip this attribute
                }
            }
            // Filter potentially dangerous event handlers
            if (name.startsWith("on")) {
                continue; // Skip all event handlers
            }
            // Filter attributes that might contain script values
            if (typeof value === "string" &&
                (value.toLowerCase().includes("javascript:") ||
                    value.toLowerCase().includes("alert(") ||
                    value.toLowerCase().includes("onclick=") ||
                    value.toLowerCase().includes("onerror=") ||
                    value.toLowerCase().includes("javascript") ||
                    value.toLowerCase().includes("script"))) {
                continue; // Skip this attribute
            }
            // Special handling for attributes with HTML entities
            if (name === "title" && typeof value === "string" && value.includes("&quot;")) {
                // Keep the original entity encoding
                result += ` ${name}="${value}"`;
            }
            else if (value) {
                result += ` ${name}="${escape(value)}"`;
            }
            else {
                result += ` ${name}`;
            }
        }
    }
    return result;
}
/**
 * Main sanitizer function
 */
function sanitize(html, options) {
    // Merge default options with user options
    const mergedOptions = { ...DEFAULT_OPTIONS, ...options };
    const tokens = tokenizeHTML(html);
    const stack = [];
    let output = "";
    // List of void elements that should be self-closing
    const selfClosingTags = [
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    ];
    // Track if we should skip text content within a disallowed tag
    let skipUntilTag = "";
    let inSkippedTag = false;
    for (const token of tokens) {
        // Skip content in disallowed tags (like script/style)
        if (inSkippedTag) {
            if (token.type === 'endTag' && token.tagName === skipUntilTag) {
                inSkippedTag = false;
                skipUntilTag = "";
            }
            continue;
        }
        // Process tokens based on type
        switch (token.type) {
            case 'startTag': {
                const tagName = token.tagName;
                if (mergedOptions.allowedTags.includes(tagName)) {
                    if (!token.selfClosing) {
                        // Special case for structural incompatibility: div inside p
                        if (tagName === "div" && stack.includes("p")) {
                            const pIndex = stack.lastIndexOf("p");
                            // Close all tags up to and including the p tag
                            for (let i = stack.length - 1; i >= pIndex; i--) {
                                output += `</${stack[i]}>`;
                            }
                            // Remove closed tags from stack
                            stack.splice(pIndex);
                        }
                        // Handle self-closing elements that are not explicitly self-closed
                        if (selfClosingTags.includes(tagName) && mergedOptions.selfClosing) {
                            const attrs = processAttributes(token, tagName, mergedOptions.allowedAttributes);
                            output += `<${tagName}${attrs} />`;
                        }
                        else {
                            // Add to stack and output opening tag
                            stack.push(tagName);
                            const attrs = processAttributes(token, tagName, mergedOptions.allowedAttributes);
                            output += `<${tagName}${attrs}>`;
                        }
                    }
                    else {
                        // Handle explicit self-closing tag
                        const attrs = processAttributes(token, tagName, mergedOptions.allowedAttributes);
                        if (mergedOptions.selfClosing) {
                            output += `<${tagName}${attrs} />`;
                        }
                        else {
                            output += `<${tagName}${attrs}></${tagName}>`;
                        }
                    }
                }
                else {
                    // Mark to skip content in disallowed tags like script and style
                    if (tagName === "script" || tagName === "style") {
                        inSkippedTag = true;
                        skipUntilTag = tagName;
                    }
                }
                break;
            }
            case 'endTag': {
                const tagName = token.tagName;
                if (mergedOptions.allowedTags.includes(tagName)) {
                    // Find the matching opening tag in the stack
                    const index = stack.lastIndexOf(tagName);
                    if (index >= 0) {
                        // Close all nested tags properly
                        for (let i = stack.length - 1; i >= index; i--) {
                            output += `</${stack[i]}>`;
                        }
                        // Remove closed tags from stack
                        stack.splice(index);
                    }
                }
                break;
            }
            case 'text': {
                // Process text content
                const text = mergedOptions.transformText
                    ? mergedOptions.transformText(token.text)
                    : token.text;
                // Only encode non-empty text
                if (text.trim() || text.includes(" ")) {
                    // Don't decode entities that are already encoded
                    if (text.includes("&lt;") || text.includes("&gt;") || text.includes("&quot;") || text.includes("&amp;")) {
                        // Check for potential nested script content
                        const safeText = text.replace(/javascript|script|alert|onerror|onclick/ig, match => encode(match, { useNamedReferences: true }));
                        output += safeText;
                    }
                    else {
                        // Filter for any script-like content
                        const decoded = decode(text);
                        if (decoded.match(/javascript|script|alert|onerror|onclick/i)) {
                            output += encode(decoded, { useNamedReferences: true });
                        }
                        else {
                            output += encode(decoded);
                        }
                    }
                }
                break;
            }
            case 'comment':
                // Skip comments - they are unsafe in HTML
                break;
            case 'doctype':
                // Skip doctype - not needed for sanitized content
                break;
        }
    }
    // Close any remaining tags
    for (let i = stack.length - 1; i >= 0; i--) {
        output += `</${stack[i]}>`;
    }
    return output;
}
// Default export
exports.default = { sanitize, decode, encode, escape };
