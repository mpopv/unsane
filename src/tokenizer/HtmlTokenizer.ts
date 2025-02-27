/**
 * HTML Tokenizer - A state machine for tokenizing HTML
 * 
 * This tokenizer is designed to parse HTML by character and classify into tokens:
 * - Start tags
 * - End tags
 * - Text content
 * - Comments
 * - Doctype declarations
 */

import {
  TokenizerState,
  HtmlToken,
  StartTagToken,
  EndTagToken,
  CommentToken,
  TextToken,
  DoctypeToken,
  RAWTEXT_TAGS
} from "./types";

export class HtmlTokenizer {
  private state = TokenizerState.DATA;
  private buffer = "";
  private position = 0; // read index
  private tokens: HtmlToken[] = [];

  // Temporary accumulators for building up tokens
  private currentToken: Partial<
    StartTagToken | EndTagToken | CommentToken | DoctypeToken | TextToken
  > = {};
  private currentAttr: { name: string; value: string } | null = null;

  // For storing raw text if we're in <script> or <style> until we see the closing tag
  private rawTextTagName = "";
  private rawTextBuffer = "";

  // For doctype token
  private docPublicId = "";
  private docSystemId = "";

  private isEndOfChunk = false;

  /**
   * Write a chunk of HTML to the tokenizer
   */
  public write(chunk: string): void {
    this.buffer += chunk;
    this.isEndOfChunk = false;
    this.run();
  }

  /**
   * End processing and flush any pending tokens
   */
  public end(): void {
    this.isEndOfChunk = true;
    // finalize
    this.run();
    // flush any pending text if needed
    if (
      this.state === TokenizerState.DATA &&
      this.currentToken.type === "text"
    ) {
      this.emitCurrentText();
    }
  }

  /**
   * Get all parsed tokens and reset the token buffer
   */
  public getTokens(): HtmlToken[] {
    const out = this.tokens;
    this.tokens = [];
    return out;
  }

  /**
   * Main processing loop - runs the state machine
   */
  private run(): void {
    while (this.position < this.buffer.length) {
      const char = this.buffer[this.position];

      // Handle the current state
      this.handleState(char);

      this.position++;
    }
  }

  /**
   * Dispatch to the appropriate state handler
   */
  private handleState(char: string): void {
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
  }

  // -------------- Utility Methods --------------

  /**
   * Move position back by 1 to reprocess the current character in a different state
   */
  private reconsume(): void {
    this.position--;
  }

  /**
   * Look ahead to the next character without advancing
   */
  private peekNext(): string {
    return this.buffer[this.position + 1] || "";
  }

  /**
   * Add a token to the output buffer
   */
  private emitToken(token: HtmlToken): void {
    this.tokens.push(token);
  }

  /**
   * Create and emit a text token
   */
  private emitText(text: string): void {
    if (!text) return;
    this.emitToken({ type: "text", text, raw: text });
  }

  /**
   * Emit the current text token if it exists
   */
  private emitCurrentText(): void {
    if (this.currentToken.type === "text") {
      const t = this.currentToken as TextToken;
      if (t.text) {
        this.emitToken({ type: "text", text: t.text, raw: t.raw! });
      }
    }
    this.currentToken = {};
  }

  // -------------- State Handlers --------------

  /**
   * Processing normal text content
   */
  private dataState(char: string): void {
    if (char === "<") {
      // flush any pending text
      if (this.currentToken.type === "text") {
        this.emitCurrentText();
      }
      this.state = TokenizerState.TAG_OPEN;
      this.currentToken = {};
      return;
    }
    // else accumulate text
    if (this.currentToken.type !== "text") {
      // start fresh
      this.currentToken = { type: "text", text: "", raw: "" };
    }
    const t = this.currentToken as TextToken;
    t.text += char;
    t.raw = (t.raw || "") + char;
  }

  /**
   * Handling "<" - could be start tag, end tag, comment, etc.
   */
  private tagOpenState(char: string): void {
    if (char === "/") {
      this.state = TokenizerState.END_TAG_OPEN;
      this.currentToken = {};
      return;
    }
    if (char === "!") {
      // check if it's a comment or doctype
      const ahead = this.buffer
        .slice(this.position + 1, this.position + 3)
        .toLowerCase();
      if (ahead.startsWith("--")) {
        // comment
        this.state = TokenizerState.COMMENT_START;
        this.position += 2; // skip over '--'
        this.currentToken = { type: "comment", text: "", raw: "<!--" };
      } else if (ahead.startsWith("do")) {
        // doctype
        this.state = TokenizerState.DOCTYPE;
        this.currentToken = {
          type: "doctype",
          name: "",
          publicId: "",
          systemId: "",
          raw: "<!doctype",
        };
        this.position += 7; // we skip "doctype"
      } else {
        // could be a bogus comment like <!abc
        this.state = TokenizerState.COMMENT_START;
        this.currentToken = { type: "comment", text: "", raw: "<!" };
      }
      return;
    }
    if (/[a-zA-Z\u200C\u200D\u200E\u200F]/.test(char)) {
      // start tag - also handle zero-width characters that might be used for obfuscation
      this.state = TokenizerState.TAG_NAME;
      this.currentToken = {
        type: "startTag",
        tagName: char.toLowerCase(),
        attrs: [],
        selfClosing: false,
        raw: "<" + char,
      };
      return;
    }
    if (char === "?") {
      // e.g. <? xml ... bogus comment
      this.state = TokenizerState.COMMENT_START;
      this.currentToken = { type: "comment", text: "", raw: "<?" };
      return;
    }
    // else it might be text, fallback
    // < followed by something else => text
    // We re-emit a text node with < char
    this.state = TokenizerState.DATA;
    this.emitText("<");
    this.reconsume();
  }

  /**
   * Processing "</..." - looking for end tag name
   */
  private endTagOpenState(char: string): void {
    if (/[a-zA-Z]/.test(char)) {
      this.state = TokenizerState.END_TAG_NAME;
      this.currentToken = {
        type: "endTag",
        tagName: char.toLowerCase(),
        raw: "</" + char,
      };
      return;
    }
    // maybe an end tag slash something?
    if (char === ">") {
      // `</>` => text
      this.state = TokenizerState.DATA;
      // we treat it as text?
      this.emitText("</>");
      return;
    }
    // might be comment or something
    // fallback
    this.state = TokenizerState.COMMENT_START;
    this.currentToken = { type: "comment", text: "", raw: "</!" };
    this.reconsume();
  }

  /**
   * Processing a start tag name
   */
  private tagNameState(char: string): void {
    const token = this.currentToken as StartTagToken;
    token.raw += char;
    if (/\s/.test(char)) {
      this.state = TokenizerState.BEFORE_ATTRIBUTE_NAME;
      return;
    }
    if (char === ">") {
      this.finishStartTag(token);
      return;
    }
    if (char === "/") {
      this.state = TokenizerState.SELF_CLOSING_START_TAG;
      return;
    }
    token.tagName += char.toLowerCase();
  }

  /**
   * Processing an end tag name
   */
  private endTagNameState(char: string): void {
    const token = this.currentToken as EndTagToken;
    token.raw += char;
    if (/\s/.test(char)) {
      // ignore whitespace
      return;
    }
    if (char === ">") {
      // done
      token.tagName = token.tagName.toLowerCase();
      this.emitToken(token as EndTagToken);
      if (
        RAWTEXT_TAGS.has(token.tagName) &&
        token.tagName === this.rawTextTagName
      ) {
        // we might exit rawtext
        this.rawTextTagName = "";
        this.rawTextBuffer = "";
        this.state = TokenizerState.DATA;
      } else {
        this.state = TokenizerState.DATA;
      }
      this.currentToken = {};
      return;
    }
    // else we keep reading the end tag name
    token.tagName += char.toLowerCase();
  }

  /**
   * Process the space before an attribute name
   */
  private beforeAttributeNameState(char: string): void {
    const token = this.currentToken as StartTagToken;
    token.raw += char;
    if (/\s/.test(char)) {
      // skip
      return;
    }
    if (char === ">") {
      this.finishStartTag(token);
      return;
    }
    if (char === "/") {
      this.state = TokenizerState.SELF_CLOSING_START_TAG;
      return;
    }
    // start new attribute
    this.currentAttr = { name: "", value: "" };
    token.attrs.push(this.currentAttr);
    this.state = TokenizerState.ATTRIBUTE_NAME;
    this.currentAttr!.name += char.toLowerCase();
  }

  /**
   * Process an attribute name
   */
  private attributeNameState(char: string): void {
    const token = this.currentToken as StartTagToken;
    token.raw += char;
    if (/\s/.test(char)) {
      this.state = TokenizerState.AFTER_ATTRIBUTE_NAME;
      return;
    }
    if (char === "=") {
      this.state = TokenizerState.BEFORE_ATTRIBUTE_VALUE;
      return;
    }
    if (char === ">") {
      this.finishStartTag(token);
      return;
    }
    if (char === "/") {
      this.state = TokenizerState.SELF_CLOSING_START_TAG;
      return;
    }
    this.currentAttr!.name += char.toLowerCase();
  }

  /**
   * Process the space after an attribute name (waiting for = or new attribute)
   */
  private afterAttributeNameState(char: string): void {
    const token = this.currentToken as StartTagToken;
    token.raw += char;
    if (/\s/.test(char)) {
      return;
    }
    if (char === "=") {
      this.state = TokenizerState.BEFORE_ATTRIBUTE_VALUE;
      return;
    }
    if (char === ">") {
      this.finishStartTag(token);
      return;
    }
    if (char === "/") {
      this.state = TokenizerState.SELF_CLOSING_START_TAG;
      return;
    }
    // new attribute
    this.currentAttr = { name: "", value: "" };
    token.attrs.push(this.currentAttr);
    this.state = TokenizerState.ATTRIBUTE_NAME;
    this.currentAttr!.name += char.toLowerCase();
  }

  /**
   * Process the space after = before the attribute value
   */
  private beforeAttributeValueState(char: string): void {
    const token = this.currentToken as StartTagToken;
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
    if (char === ">") {
      this.finishStartTag(token);
      return;
    }
    if (char === "/") {
      this.state = TokenizerState.SELF_CLOSING_START_TAG;
      return;
    }
    // unquoted
    this.state = TokenizerState.ATTRIBUTE_VALUE_UNQUOTED;
    this.currentAttr!.value += char;
  }

  /**
   * Process attribute values (all quote types handled here)
   */
  private attributeValueState(char: string): void {
    const token = this.currentToken as StartTagToken;
    token.raw += char;
    const avState = this.state;
    if (
      (avState === TokenizerState.ATTRIBUTE_VALUE_DOUBLE && char === '"') ||
      (avState === TokenizerState.ATTRIBUTE_VALUE_SINGLE && char === "'")
    ) {
      // end
      this.state = TokenizerState.BEFORE_ATTRIBUTE_NAME;
      return;
    }
    if (
      /\s/.test(char) &&
      avState === TokenizerState.ATTRIBUTE_VALUE_UNQUOTED
    ) {
      this.state = TokenizerState.BEFORE_ATTRIBUTE_NAME;
      return;
    }
    if (char === ">" && avState === TokenizerState.ATTRIBUTE_VALUE_UNQUOTED) {
      this.finishStartTag(token);
      return;
    }
    if (char === "/" && avState === TokenizerState.ATTRIBUTE_VALUE_UNQUOTED) {
      this.state = TokenizerState.SELF_CLOSING_START_TAG;
      return;
    }

    this.currentAttr!.value += char;
  }

  /**
   * Process the / in a self-closing tag
   */
  private selfClosingStartTagState(char: string): void {
    const token = this.currentToken as StartTagToken;
    token.raw += char;
    if (char === ">") {
      token.selfClosing = true;
      this.finishStartTag(token);
      return;
    }
    // fallback
    this.state = TokenizerState.BEFORE_ATTRIBUTE_NAME;
    this.reconsume();
  }

  /**
   * Emit the start tag token and transition to the correct state
   */
  private finishStartTag(token: StartTagToken): void {
    // check raw text
    const lower = token.tagName.toLowerCase();
    token.tagName = lower;
    // if script or style, we go raw
    if (RAWTEXT_TAGS.has(lower) && !token.selfClosing) {
      this.rawTextTagName = lower;
      this.rawTextBuffer = "";
      this.state = TokenizerState.RAWTEXT;
    } else {
      this.state = TokenizerState.DATA;
    }
    this.emitToken(token);
    this.currentToken = {};
  }

  /**
   * Handle HTML comments - all comment states combined
   */
  private commentStates(char: string): void {
    // handle comment
    const ctoken = this.currentToken as CommentToken;
    ctoken.raw += char;
    switch (this.state) {
      case TokenizerState.COMMENT_START: {
        if (char === "-") {
          // we might move to COMMENT
          // but we are already in comment start
          this.state = TokenizerState.COMMENT;
          return;
        }
        if (char === ">") {
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
        if (char === "-") {
          this.state = TokenizerState.COMMENT_END;
          return;
        }
        ctoken.text += char;
        return;
      }
      case TokenizerState.COMMENT_END: {
        if (char === "-") {
          ctoken.text += "-";
          // still in comment end
          return;
        }
        if (char === ">") {
          // finish
          this.finishComment();
          return;
        }
        // else revert to comment
        this.state = TokenizerState.COMMENT;
        ctoken.text += "-" + char;
      }
    }
  }

  /**
   * Emit the completed comment token
   */
  private finishComment(): void {
    const ctoken = this.currentToken as CommentToken;
    this.emitToken({
      type: "comment",
      text: ctoken.text,
      raw: ctoken.raw,
    });
    this.currentToken = {};
    this.state = TokenizerState.DATA;
  }

  /**
   * Handle doctype declarations - all doctype states combined
   */
  private doctypeStates(char: string): void {
    const dt = this.currentToken as DoctypeToken;
    dt.raw += char;
    switch (this.state) {
      case TokenizerState.DOCTYPE: {
        if (/\s/.test(char)) {
          this.state = TokenizerState.DOCTYPE_BEFORE_NAME;
        } else if (char === ">") {
          // done
          this.finishDoctype();
        } else {
          // partial
          this.state = TokenizerState.DOCTYPE_NAME;
          dt.name += char.toLowerCase();
        }
        break;
      }
      case TokenizerState.DOCTYPE_BEFORE_NAME: {
        if (/\s/.test(char)) {
          // skip
        } else if (char === ">") {
          this.finishDoctype();
        } else {
          this.state = TokenizerState.DOCTYPE_NAME;
          dt.name += char.toLowerCase();
        }
        break;
      }
      case TokenizerState.DOCTYPE_NAME: {
        if (/\s/.test(char)) {
          this.state = TokenizerState.DOCTYPE_AFTER_NAME;
        } else if (char === ">") {
          this.finishDoctype();
        } else {
          dt.name += char.toLowerCase();
        }
        break;
      }
      case TokenizerState.DOCTYPE_AFTER_NAME: {
        if (/\s/.test(char)) {
          // skip
        } else if (char === ">") {
          this.finishDoctype();
        } else if (/^(public|system)/i.test(this.buffer.slice(this.position))) {
          // naive check
          this.state = TokenizerState.DOCTYPE_PUBLIC_OR_SYSTEM;
        } else {
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
        } else if (char === "'") {
          this.state = TokenizerState.DOCTYPE_PUBLIC_ID_SINGLE_QUOTED;
        } else if (char === ">") {
          this.finishDoctype();
        }
        break;
      }
      case TokenizerState.DOCTYPE_PUBLIC_ID_SINGLE_QUOTED: {
        if (char === "'") {
          // done public id
          dt.publicId = this.docPublicId;
          this.docPublicId = "";
          // next might be system
          this.state = TokenizerState.DOCTYPE_BOGUS;
        } else if (char === ">") {
          dt.publicId = this.docPublicId;
          this.finishDoctype();
        } else {
          this.docPublicId += char;
        }
        break;
      }
      case TokenizerState.DOCTYPE_PUBLIC_ID_DOUBLE_QUOTED: {
        if (char === '"') {
          dt.publicId = this.docPublicId;
          this.docPublicId = "";
          this.state = TokenizerState.DOCTYPE_BOGUS; // minimal
        } else if (char === ">") {
          dt.publicId = this.docPublicId;
          this.finishDoctype();
        } else {
          this.docPublicId += char;
        }
        break;
      }
      case TokenizerState.DOCTYPE_SYSTEM_ID_SINGLE_QUOTED: {
        if (char === "'") {
          dt.systemId = this.docSystemId;
          this.docSystemId = "";
          this.state = TokenizerState.DOCTYPE_BOGUS;
        } else if (char === ">") {
          dt.systemId = this.docSystemId;
          this.finishDoctype();
        } else {
          this.docSystemId += char;
        }
        break;
      }
      case TokenizerState.DOCTYPE_SYSTEM_ID_DOUBLE_QUOTED: {
        if (char === '"') {
          dt.systemId = this.docSystemId;
          this.docSystemId = "";
          this.state = TokenizerState.DOCTYPE_BOGUS;
        } else if (char === ">") {
          dt.systemId = this.docSystemId;
          this.finishDoctype();
        } else {
          this.docSystemId += char;
        }
        break;
      }
      case TokenizerState.DOCTYPE_BOGUS: {
        if (char === ">") {
          this.finishDoctype();
        }
        break;
      }
    }
  }

  /**
   * Emit the completed doctype token
   */
  private finishDoctype(): void {
    const dt = this.currentToken as DoctypeToken;
    if (this.docPublicId) dt.publicId = this.docPublicId;
    if (this.docSystemId) dt.systemId = this.docSystemId;
    this.emitToken(dt as DoctypeToken);
    this.currentToken = {};
    this.docPublicId = "";
    this.docSystemId = "";
    this.state = TokenizerState.DATA;
  }

  /**
   * Handle raw text content inside script, style tags
   */
  private rawtextState(char: string): void {
    // accumulate raw text until we see `</script>` or `</style>` etc.
    // naive approach: if we see `</`, check if it matches the rawTextTagName
    this.rawTextBuffer += char;

    if (char === "<") {
      // look ahead if it's `</tagName`
      const possibleClose = this.buffer
        .slice(
          this.position + 1,
          this.position + 1 + this.rawTextTagName.length + 1
        )
        .toLowerCase();
      if (possibleClose === "/" + this.rawTextTagName) {
        // flush text token
        this.emitToken({
          type: "text",
          text: this.rawTextBuffer.slice(0, -1), // minus the '<'
          raw: this.rawTextBuffer.slice(0, -1),
        });
        this.rawTextBuffer = "<";
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
 * @param html HTML string to tokenize
 * @returns Array of HTML tokens
 */
export function tokenizeHTML(html: string): HtmlToken[] {
  const tokenizer = new HtmlTokenizer();
  tokenizer.write(html);
  tokenizer.end();
  return tokenizer.getTokens();
}

export default {
  HtmlTokenizer,
  tokenizeHTML
};