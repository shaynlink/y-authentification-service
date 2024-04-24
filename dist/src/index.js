"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
require("dotenv/config");
const codebase_1 = __importDefault(require("codebase"));
const handle_1 = require("./handle");
const shemas_1 = require("./shemas");
const CERTIFICATE_KEY = 'DB_CERTIFICATE';
const CERTIFICATE_DATABASE_NAME = process.env.CERTIFICATE_DATABASE_NAME;
const core = codebase_1.default.instanciateFromEnv();
async function bootstrap() {
    if (!CERTIFICATE_DATABASE_NAME) {
        throw new Error('Missing certificate database name in env');
    }
    await core.KMService.fetchSecret(CERTIFICATE_DATABASE_NAME, CERTIFICATE_KEY);
    core.DBService.getSecretFromKMS(CERTIFICATE_KEY);
    const client = await core.DBService.createClient();
    const User = client.model('users', shemas_1.UserSchema);
    const handle = core.HTTPService.handle;
    handle.app.locals.schema = {
        User: User
    };
    (0, handle_1.setUpHandle)(handle);
    const server = core.HTTPService.createServer();
    server.on('connection', (socket) => {
        console.log('New connection from %s', socket.remoteAddress);
    });
}
bootstrap();
