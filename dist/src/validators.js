"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.loginInputValidator = exports.registerInputValidator = void 0;
const checkeasy_1 = require("checkeasy");
exports.registerInputValidator = (0, checkeasy_1.object)({
    email: (0, checkeasy_1.email)(),
    password: (0, checkeasy_1.string)({ min: 8, max: 64 }),
    username: (0, checkeasy_1.string)({ min: 3, max: 32 }),
});
exports.loginInputValidator = (0, checkeasy_1.object)({
    email: (0, checkeasy_1.email)(),
    password: (0, checkeasy_1.string)(),
});
