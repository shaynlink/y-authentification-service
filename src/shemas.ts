import { Schema, Model } from 'mongoose'

export interface IUser {
  username: string;
  email: string;
  picture?: string;
  password: string;
  role: 'user' | 'admin';
}

export type UserModel = Model<IUser, {}, {}>;

export const UserSchema = new Schema<IUser>({
  username: {
    type: String,
    required: true,
    unique: true,
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    validator: {
      validate: (email: string) => {
        return /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/.test(email)
      },
      message: (props: any) => `${props.value} is not a valid email`
    }
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    validator: {
      validate: (password: string) => {
        return password.length >= 8 && password.length <= 64
      },
      message: () => `Is not a valid password`
    }
  },
  picture: {
    type: String,
    required: false,
  },
  role: {
    type: String,
    required: true,
    default: 'user',
    enum: ['user', 'admin'],
  }
})