import { email, object, string } from 'checkeasy';

export const registerInputValidator = object({
  email: email(),
  password: string({ min: 8, max: 64 }),
  username: string({ min: 3, max: 32 }),
})

export const loginInputValidator = object({
  email: email(),
  password: string(),
})