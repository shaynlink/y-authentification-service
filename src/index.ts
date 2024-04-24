import 'dotenv/config'
import Core from 'codebase'
import { setUpHandle } from './handle';
import { IUser, UserModel, UserSchema } from './shemas';

const CERTIFICATE_KEY = 'DB_CERTIFICATE';
const CERTIFICATE_DATABASE_NAME = process.env.CERTIFICATE_DATABASE_NAME;

const core = Core.instanciateFromEnv();

async function bootstrap() {
  if (!CERTIFICATE_DATABASE_NAME) {
    throw new Error('Missing certificate database name in env');
  }

  await core.KMService.fetchSecret(
    CERTIFICATE_DATABASE_NAME,
    CERTIFICATE_KEY
  );
  
  core.DBService.getSecretFromKMS(CERTIFICATE_KEY);

  const client = await core.DBService.createClient();

  const User = client.model<IUser, UserModel>('users', UserSchema);

  const handle = core.HTTPService.handle;
  handle.app.locals.schema = {
    User: User
  }

  setUpHandle(handle);

  const server = core.HTTPService.createServer();

  server.on('connection', (socket) => {
    console.log('New connection from %s', socket.remoteAddress);
  })
}

bootstrap();