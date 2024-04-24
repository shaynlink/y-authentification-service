"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserSchema = void 0;
const mongoose_1 = require("mongoose");
exports.UserSchema = new mongoose_1.Schema({
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
            validate: (email) => {
                return /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/.test(email);
            },
            message: (props) => `${props.value} is not a valid email`
        }
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        validator: {
            validate: (password) => {
                return password.length >= 8 && password.length <= 64;
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
});
