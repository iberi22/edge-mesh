import { describe, it, expect } from "vitest";
import { generarNonce, generarId, bytesAHex, hexABytes } from "../../src/protocol/utils.js";

describe("protocol utils", () => {
  describe("generarNonce", () => {
    it("should generate a string of length 32", () => {
      const nonce = generarNonce();
      expect(typeof nonce).toBe("string");
      expect(nonce.length).toBe(32);
    });

    it("should generate unique nonces", () => {
      const nonce1 = generarNonce();
      const nonce2 = generarNonce();
      expect(nonce1).not.toBe(nonce2);
    });
  });

  describe("generarId", () => {
    it("should generate a string containing a hyphen", () => {
      const id = generarId();
      expect(typeof id).toBe("string");
      expect(id).toContain("-");
    });

    it("should generate unique IDs", () => {
      const id1 = generarId();
      const id2 = generarId();
      expect(id1).not.toBe(id2);
    });
  });

  describe("bytesAHex", () => {
    it("should convert bytes to hex string", () => {
      const bytes = new Uint8Array([0, 1, 15, 16, 255]);
      expect(bytesAHex(bytes)).toBe("00010f10ff");
    });

    it("should return empty string for empty array", () => {
      expect(bytesAHex(new Uint8Array())).toBe("");
    });
  });

  describe("hexABytes", () => {
    it("should convert hex string to bytes", () => {
      const hex = "00010f10ff";
      const expected = new Uint8Array([0, 1, 15, 16, 255]);
      expect(hexABytes(hex)).toEqual(expected);
    });

    it("should handle uppercase hex", () => {
      const hex = "00010F10FF";
      const expected = new Uint8Array([0, 1, 15, 16, 255]);
      expect(hexABytes(hex)).toEqual(expected);
    });

    it("should ignore non-hex characters", () => {
      const hex = "00-01-0F:10 FF";
      const expected = new Uint8Array([0, 1, 15, 16, 255]);
      expect(hexABytes(hex)).toEqual(expected);
    });

    it("should return empty array for empty string", () => {
      expect(hexABytes("")).toEqual(new Uint8Array());
    });
  });

  describe("hex roundtrip", () => {
    it("should maintain integrity through conversion", () => {
      const original = new Uint8Array([1, 2, 3, 4, 5, 250, 251, 252, 253, 254, 255]);
      const hex = bytesAHex(original);
      const back = hexABytes(hex);
      expect(back).toEqual(original);
    });
  });
});
