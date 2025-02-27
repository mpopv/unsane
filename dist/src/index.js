"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = exports.encode = exports.decode = exports.sanitize = void 0;
var unsane_1 = require("./unsane");
Object.defineProperty(exports, "sanitize", { enumerable: true, get: function () { return unsane_1.sanitize; } });
Object.defineProperty(exports, "decode", { enumerable: true, get: function () { return unsane_1.decode; } });
Object.defineProperty(exports, "encode", { enumerable: true, get: function () { return unsane_1.encode; } });
Object.defineProperty(exports, "escape", { enumerable: true, get: function () { return unsane_1.escape; } });
var unsane_2 = require("./unsane");
Object.defineProperty(exports, "default", { enumerable: true, get: function () { return __importDefault(unsane_2).default; } });
