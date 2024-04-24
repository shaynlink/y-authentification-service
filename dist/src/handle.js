"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.setUpHandle = void 0;
const codebase_1 = require("codebase");
const validators_1 = require("./validators");
const package_json_1 = __importDefault(require("../package.json"));
const axios_1 = __importDefault(require("axios"));
const bcrypt_1 = __importDefault(require("bcrypt"));
function setUpHandle(handle) {
    handle.initiateHealthCheckRoute(package_json_1.default.version);
    const User = handle.app.locals.schema.User;
    handle.createRoute('/', (route) => {
        route.mapper.post('/register', async (req, res, next) => {
            try {
                (0, validators_1.registerInputValidator)(req.body, 'register');
                next();
            }
            catch (error) {
                return handle.createResponse(req, res, null, new codebase_1.ErrorResponse(error.message, 400));
            }
        }, async (req, res) => {
            var _a;
            try {
                const encryptedPassword = await bcrypt_1.default.hash(req.body.password, 10);
                const user = new User({ ...req.body, password: encryptedPassword, role: 'user' });
                await user.save();
                const response = await axios_1.default.post('https://authorization-service-2fqcvdzp6q-ew.a.run.app', {
                    type: 'sign',
                    userId: user._id.toHexString()
                });
                if (response.status !== 200) {
                    throw new Error('Unable to create user');
                }
                if (response.data.error) {
                    return new Error(response.data.error.message);
                }
                return handle.createResponse(req, res, {
                    token: (_a = response.data.result) === null || _a === void 0 ? void 0 : _a.token
                }, null);
            }
            catch (error) {
                if ((error === null || error === void 0 ? void 0 : error.code) === 11000) {
                    return handle.createResponse(req, res, null, new codebase_1.ErrorResponse(`${Object.keys(error.keyPattern).join(', ')} : already used`, 400, {
                        code: 11000,
                        keyPattern: error.keyPattern
                    }));
                }
                console.error(error);
                return handle.createResponse(req, res, null, new codebase_1.ErrorResponse('Unable to create user', 500));
            }
        });
        route.mapper.post('/login', async (req, res, next) => {
            try {
                (0, validators_1.loginInputValidator)(req.body, 'login');
                next();
            }
            catch (error) {
                return handle.createResponse(req, res, null, new codebase_1.ErrorResponse(error.message, 400));
            }
        }, async (req, res) => {
            var _a;
            try {
                const user = await User
                    .findOne({ email: req.body.email })
                    .select({ password: 1, _id: 1 })
                    .exec();
                if (!user) {
                    return handle.createResponse(req, res, null, new codebase_1.ErrorResponse('Invalid credential', 404));
                }
                if (!(await bcrypt_1.default.compare(req.body.password, user.password))) {
                    return handle.createResponse(req, res, null, new codebase_1.ErrorResponse('Invalid credential', 400));
                }
                const response = await axios_1.default.post('https://authorization-service-2fqcvdzp6q-ew.a.run.app', {
                    type: 'sign',
                    userId: user._id.toHexString()
                });
                if (response.status !== 200) {
                    throw new Error('Unable to create user');
                }
                if (response.data.error) {
                    return new Error(response.data.error.message);
                }
                return handle.createResponse(req, res, {
                    token: (_a = response.data.result) === null || _a === void 0 ? void 0 : _a.token
                }, null);
            }
            catch (error) {
                console.error(error);
                return handle.createResponse(req, res, null, new codebase_1.ErrorResponse('Unable to login', 500));
            }
        });
    });
    handle.initiateNotFoundRoute();
}
exports.setUpHandle = setUpHandle;
