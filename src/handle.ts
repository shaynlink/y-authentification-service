import { ErrorResponse, HTTPHandle, Route } from 'codebase'
import { registerInputValidator, loginInputValidator } from './validators'
import type { Model } from 'mongoose'
import type { UserSchema } from './shemas'
import pkg from '../package.json'
import axios from 'axios'
import { AuthorizationSignResponse } from 'y-types/service'
import bcrypt from 'bcrypt'
import { Types } from 'mongoose'

export function setUpHandle(handle: HTTPHandle) {
  handle.initiateHealthCheckRoute(pkg.version);

  const User: Model<typeof UserSchema> = handle.app.locals.schema.User;

  handle.createRoute('/',(route: Route) => {
    route.mapper.post('/register',
      async (req, res, next) => {
        try {
          registerInputValidator(req.body, 'register');
          next();
        } catch (error: unknown) {
          return handle.createResponse(req, res, null, new ErrorResponse((<any>error).message, 400));
        }
      },
      async (req, res) => {
        try {
          const encryptedPassword = await bcrypt.hash(req.body.password, 10);
          
          const user = new User({...req.body, password: encryptedPassword, role: 'user'});
          await user.save();

          const response = await axios.post<AuthorizationSignResponse>('https://authorization-service-2fqcvdzp6q-ew.a.run.app', {
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
            token: response.data.result?.token
          }, null)
        } catch (error: any) {
          if (error?.code === 11000) {
            return handle.createResponse(req, res, null,
              new ErrorResponse(
                `${Object.keys(error.keyPattern).join(', ')} : already used`,
                400,
                {
                  code: 11000,
                  keyPattern: error.keyPattern
                }
              ));
          }

          console.error(error);
          return handle.createResponse(req, res, null, new ErrorResponse('Unable to create user', 500));
        }
      })

    route.mapper.post('/login',
      async (req, res, next) => {
        try {
          loginInputValidator(req.body, 'login');
          next();
        } catch (error: unknown) {
          return handle.createResponse(req, res, null, new ErrorResponse((<any>error).message, 400));
        }
      },
      async (req, res) => {
        try {
          const user = await User
            .findOne({ email: req.body.email })
            .select({ password: 1, _id: 1 })
            .exec() as unknown as { _id: Types.ObjectId, password: string };

          if (!user) {
            return handle.createResponse(req, res, null, new ErrorResponse('Invalid credential', 404));
          }

          if (!(await bcrypt.compare(req.body.password, user.password))) {
            return handle.createResponse(req, res, null, new ErrorResponse('Invalid credential', 400));
          }

          const response = await axios.post<AuthorizationSignResponse>('https://authorization-service-2fqcvdzp6q-ew.a.run.app', {
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
            token: response.data.result?.token
          }, null);
        } catch (error) {
          console.error(error);
          return handle.createResponse(req, res, null, new ErrorResponse('Unable to login', 500));
        }
      }
    )
  })

  handle.initiateNotFoundRoute();
}