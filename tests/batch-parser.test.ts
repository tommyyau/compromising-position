import { describe, it, expect } from "vitest";
import {
  parseEnvString,
  parseJsonString,
  disposeBatch,
} from "../src/input/batch-parser.js";

describe("parseEnvString", () => {
  it("should parse simple KEY=VALUE pairs", () => {
    const entries = parseEnvString("API_KEY=sk-test-123\nDB_PASSWORD=hunter2");

    expect(entries).toHaveLength(2);
    expect(entries[0]!.name).toBe("API_KEY");
    expect(entries[0]!.secret.unsafeGetString()).toBe("sk-test-123");
    expect(entries[1]!.name).toBe("DB_PASSWORD");
    expect(entries[1]!.secret.unsafeGetString()).toBe("hunter2");

    disposeBatch(entries);
  });

  it("should handle quoted values", () => {
    const entries = parseEnvString('SECRET="my secret value"\nTOKEN=\'single quoted\'');

    expect(entries).toHaveLength(2);
    expect(entries[0]!.secret.unsafeGetString()).toBe("my secret value");
    expect(entries[1]!.secret.unsafeGetString()).toBe("single quoted");

    disposeBatch(entries);
  });

  it("should skip comments and empty lines", () => {
    const entries = parseEnvString(
      "# This is a comment\n\nAPI_KEY=value\n# Another comment\n",
    );

    expect(entries).toHaveLength(1);
    expect(entries[0]!.name).toBe("API_KEY");

    disposeBatch(entries);
  });

  it("should skip lines without = sign", () => {
    const entries = parseEnvString("NOEQUALS\nAPI_KEY=value");

    expect(entries).toHaveLength(1);
    expect(entries[0]!.name).toBe("API_KEY");

    disposeBatch(entries);
  });

  it("should handle values with = in them", () => {
    const entries = parseEnvString("KEY=base64value==");

    expect(entries).toHaveLength(1);
    expect(entries[0]!.secret.unsafeGetString()).toBe("base64value==");

    disposeBatch(entries);
  });

  it("should skip entries with empty values", () => {
    const entries = parseEnvString("EMPTY=\nVALID=test");

    expect(entries).toHaveLength(1);
    expect(entries[0]!.name).toBe("VALID");

    disposeBatch(entries);
  });
});

describe("parseJsonString", () => {
  it("should parse simple JSON objects", () => {
    const entries = parseJsonString(
      '{"API_KEY": "sk-test-123", "DB_PASSWORD": "hunter2"}',
    );

    expect(entries).toHaveLength(2);
    expect(entries[0]!.name).toBe("API_KEY");
    expect(entries[0]!.secret.unsafeGetString()).toBe("sk-test-123");

    disposeBatch(entries);
  });

  it("should skip non-string values", () => {
    const entries = parseJsonString(
      '{"KEY": "value", "NUM": 42, "BOOL": true, "NULL": null}',
    );

    expect(entries).toHaveLength(1);
    expect(entries[0]!.name).toBe("KEY");

    disposeBatch(entries);
  });

  it("should skip empty string values", () => {
    const entries = parseJsonString('{"EMPTY": "", "VALID": "test"}');

    expect(entries).toHaveLength(1);
    expect(entries[0]!.name).toBe("VALID");

    disposeBatch(entries);
  });
});

describe("disposeBatch", () => {
  it("should dispose all SecureBuffers", () => {
    const entries = parseEnvString("A=val1\nB=val2");

    disposeBatch(entries);

    expect(entries[0]!.secret.isDisposed).toBe(true);
    expect(entries[1]!.secret.isDisposed).toBe(true);
  });
});
