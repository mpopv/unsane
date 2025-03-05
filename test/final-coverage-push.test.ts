import { describe, it, expect } from "vitest";
import { sanitize } from "../src/sanitizer/htmlSanitizer";
import { encode, decode } from "../src/utils/htmlEntities";

// Final push to get 100% coverage
describe("Final Coverage Push", () => {
  // Target lines 65-66 in htmlSanitizer.ts
  it("should handle dangerous attribute values with extreme edge cases", () => {
    // Create a test case that will specifically hit lines 65-66
    // We need to create an attribute with a dangerous value that isn't a URL attribute

    // First, let's create a custom sanitizer config that allows data-* attributes
    const input =
      '<div data-test="javascript:alert(1)" data-other="eval(alert(2))">Test</div>';

    // This should trigger the containsDangerousContent check but not be a URL attribute
    const output = sanitize(input, {
      allowedTags: ["div"],
      allowedAttributes: { div: ["data-test", "data-other"] },
    });

    // The dangerous attributes should be removed
    expect(output).not.toContain("data-test");
    expect(output).not.toContain("data-other");
    expect(output).toContain("<div");
    expect(output).toContain("Test");
    expect(output).toContain("</div>");

    // Try another variation
    const input2 = '<span title="javascript:void(0)">Click</span>';
    const output2 = sanitize(input2, {
      allowedTags: ["span"],
      allowedAttributes: { span: ["title"] },
    });

    expect(output2).not.toContain("title");
    expect(output2).toContain("<span");
    expect(output2).toContain("Click");
  });

  // Target line 396 in htmlSanitizer.ts
  it("should handle empty attribute values with extreme edge cases", () => {
    // Create a test case that will specifically hit line 396
    // We need an attribute with an empty value followed by >

    // Try with multiple empty attributes
    const input = '<div data-test="" data-other="">Content</div>';
    const output = sanitize(input, {
      allowedTags: ["div"],
      allowedAttributes: { div: ["data-test", "data-other"] },
    });

    expect(output).toContain("<div");
    expect(output).toContain("data-test");
    expect(output).toContain("data-other");
    expect(output).toContain("Content");

    // Try with a self-closing tag
    const input2 = '<br data-empty="" />';
    const output2 = sanitize(input2, {
      allowedTags: ["br"],
      allowedAttributes: { br: ["data-empty"] },
    });

    expect(output2).toContain("<br");
    expect(output2).toContain("data-empty");
  });

  // Target line 429 in htmlSanitizer.ts
  it("should handle unquoted attribute values with extreme edge cases", () => {
    // Create a test case that will specifically hit line 429
    // We need an unquoted attribute value followed by >

    // Try with multiple unquoted attributes
    const input = "<div data-test=value data-other=123>Content</div>";
    const output = sanitize(input, {
      allowedTags: ["div"],
      allowedAttributes: { div: ["data-test", "data-other"] },
    });

    expect(output).toContain("<div");
    expect(output).toContain("data-test");
    expect(output).toContain("value");
    expect(output).toContain("data-other");
    expect(output).toContain("123");
    expect(output).toContain("Content");

    // Try with a self-closing tag
    const input2 = "<br data-test=value/>";
    const output2 = sanitize(input2, {
      allowedTags: ["br"],
      allowedAttributes: { br: ["data-test"] },
    });

    expect(output2).toContain("<br");
    expect(output2).toContain("data-test");
    expect(output2).toContain("value");
  });

  // Target line 450 in htmlSanitizer.ts
  it("should handle tag end state with extreme edge cases", () => {
    // Create a test case that will specifically hit line 450
    // We need a tag in TAG_END state followed by >

    // Try with a closing tag that has extra characters
    const input = "<div></div////>";
    const output = sanitize(input);

    expect(output).toBe("<div></div>");

    // Try with a self-closing tag that has extra characters
    const input2 = "<br//////>";
    const output2 = sanitize(input2, {
      allowedTags: ["br"],
    });

    expect(output2).toContain("<br");
  });

  // Target line 87 in htmlEntities.ts
  it("should handle non-target characters in htmlEntities with extreme edge cases", () => {
    // Create a test case that will specifically hit line 87
    // We need a character that doesn't match the pattern with !escapeOnly && !encodeEverything

    const result = encode("abcdefghijklmnopqrstuvwxyz0123456789", {
      escapeOnly: false,
      encodeEverything: false,
    });

    // None of these characters should be encoded
    expect(result).toBe("abcdefghijklmnopqrstuvwxyz0123456789");

    // Try with a mix of special and non-special characters
    const result2 = encode("abc&def<ghi>jkl\"mno'pqr", {
      escapeOnly: false,
      encodeEverything: false,
    });

    // Special characters should be encoded, others should not
    expect(result2).toContain("abc");
    expect(result2).toContain("def");
    expect(result2).toContain("ghi");
    expect(result2).toContain("jkl");
    expect(result2).toContain("mno");
    expect(result2).toContain("pqr");
    expect(result2).toContain("&#x26;"); // &
    expect(result2).toContain("&#x3C;"); // <
    expect(result2).toContain("&#x3E;"); // >
    expect(result2).toContain("&#x22;"); // "
    expect(result2).toContain("&#x27;"); // '
  });

  // Target line 139 in htmlEntities.ts
  it("should handle extremely broken HTML entity formats with edge cases", () => {
    // Create a test case that will specifically hit line 139
    // We need to create entities that will cause errors in the parseInt functions

    // Try with an entity that has an extremely large hex value
    const result = decode("&#x" + "F".repeat(100) + ";");
    expect(result).toBe("\uFFFD"); // Should be the replacement character

    // Try with an entity that has invalid characters
    const result2 = decode("&#xGHIJKL;");
    expect(result2).toBe("&#xGHIJKL;"); // Should be unchanged

    // Try with an entity that has a negative value
    const result3 = decode("&#-123;");
    expect(result3).toBe("&#-123;"); // Should be unchanged

    // Try with an entity that has a decimal value that's too large
    const result4 = decode("&#" + "9".repeat(100) + ";");
    expect(result4).toBe("\uFFFD"); // Should be the replacement character
  });
});
