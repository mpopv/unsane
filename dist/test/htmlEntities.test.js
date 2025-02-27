"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const vitest_1 = require("vitest");
const htmlEntities_1 = require("../src/utils/htmlEntities");
(0, vitest_1.describe)("htmlEntities", () => {
    (0, vitest_1.describe)("decode", () => {
        (0, vitest_1.it)("should decode named entities", () => {
            (0, vitest_1.expect)((0, htmlEntities_1.decode)("&lt;div&gt;")).toBe("<div>");
            (0, vitest_1.expect)((0, htmlEntities_1.decode)("&amp;")).toBe("&");
            (0, vitest_1.expect)((0, htmlEntities_1.decode)("&quot;")).toBe('"');
            (0, vitest_1.expect)((0, htmlEntities_1.decode)("&apos;")).toBe("'");
        });
        (0, vitest_1.it)("should decode decimal numeric entities", () => {
            (0, vitest_1.expect)((0, htmlEntities_1.decode)("&#60;")).toBe("<");
            (0, vitest_1.expect)((0, htmlEntities_1.decode)("&#38;")).toBe("&");
            (0, vitest_1.expect)((0, htmlEntities_1.decode)("&#34;")).toBe('"');
        });
        (0, vitest_1.it)("should decode hexadecimal numeric entities", () => {
            (0, vitest_1.expect)((0, htmlEntities_1.decode)("&#x3C;")).toBe("<");
            (0, vitest_1.expect)((0, htmlEntities_1.decode)("&#x26;")).toBe("&");
            (0, vitest_1.expect)((0, htmlEntities_1.decode)("&#x22;")).toBe('"');
            (0, vitest_1.expect)((0, htmlEntities_1.decode)("&#X3C;")).toBe("<"); // Capital X also works
        });
        (0, vitest_1.it)("should handle malformed entities", () => {
            (0, vitest_1.expect)((0, htmlEntities_1.decode)("&lt")).toBe("&lt"); // No semicolon
            (0, vitest_1.expect)((0, htmlEntities_1.decode)("&unknown;")).toBe("&unknown;"); // Unknown entity
            (0, vitest_1.expect)((0, htmlEntities_1.decode)("&#xGHI;")).toBe("&#xGHI;"); // Invalid hex
            (0, vitest_1.expect)((0, htmlEntities_1.decode)("&#abc;")).toBe("&#abc;"); // Invalid decimal
        });
        (0, vitest_1.it)("should decode multiple entities in a string", () => {
            (0, vitest_1.expect)((0, htmlEntities_1.decode)("&lt;div&gt;Hello &amp; world!&lt;/div&gt;")).toBe("<div>Hello & world!</div>");
        });
    });
    (0, vitest_1.describe)("encode", () => {
        (0, vitest_1.it)("should encode special characters with numeric references by default", () => {
            const result = (0, htmlEntities_1.encode)("<div>");
            (0, vitest_1.expect)(result).toContain("&#x3C;"); // <
            (0, vitest_1.expect)(result).toContain("&#x3E;"); // >
        });
        (0, vitest_1.it)("should use named references when requested", () => {
            const result = (0, htmlEntities_1.encode)("<div>", { useNamedReferences: true });
            (0, vitest_1.expect)(result).toBe("&lt;div&gt;");
        });
        (0, vitest_1.it)("should use decimal references when requested", () => {
            const result = (0, htmlEntities_1.encode)("<div>", { decimal: true });
            (0, vitest_1.expect)(result).toBe("&#60;div&#62;");
        });
        (0, vitest_1.it)("should only encode special chars by default", () => {
            const result = (0, htmlEntities_1.encode)("Hi <there>");
            (0, vitest_1.expect)(result).toBe("Hi &#x3C;there&#x3E;");
        });
        (0, vitest_1.it)("should encode everything when requested", () => {
            const result = (0, htmlEntities_1.encode)("Hi", { encodeEverything: true });
            (0, vitest_1.expect)(result).toBe("&#x48;&#x69;");
        });
    });
    (0, vitest_1.describe)("escape", () => {
        (0, vitest_1.it)("should escape only essential characters", () => {
            const input = '<img src="x" onerror="alert(\'XSS\')">';
            const result = (0, htmlEntities_1.escape)(input);
            (0, vitest_1.expect)(result).toBe("&lt;img src=&quot;x&quot; onerror=&quot;alert(&#x27;XSS&#x27;)&quot;&gt;");
        });
        (0, vitest_1.it)("should leave normal text untouched", () => {
            (0, vitest_1.expect)((0, htmlEntities_1.escape)("Hello world")).toBe("Hello world");
        });
        (0, vitest_1.it)("should handle all escapable characters", () => {
            const input = "&<>\"'`";
            const result = (0, htmlEntities_1.escape)(input);
            (0, vitest_1.expect)(result).toBe("&amp;&lt;&gt;&quot;&#x27;&#x60;");
        });
    });
});
