const mongoose = require('mongoose');
const Joi = require('joi');
const jwt = require('jsonwebtoken');

const tokenSchema = new mongoose.Schema({
    token: { type: String, required: false },
    createdDate: { type: String, default: Date }
});

const userSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true, minlength: 5 },
    createdDate: { type: Date, default: Date },
    isAdmin: { type: Boolean, default: false },
    avitar: { type: String, default: 'default.jpg' },
    address: { type: String },
    city: { type: String },
    zipCode: { type: String },
    state: { type: String },
    resetPasswordToken: { type: [tokenSchema], default: {} },
    confirmedRegisted: { type: Boolean, default: false }
});

userSchema.methods.generateAuthToken = function () {
    return jwt.sign({ id: this.id }, process.env.JWT_SECRET);
};

const User = mongoose.model('user', userSchema);

function validateUser(user) {
    const schema = Joi.object({
        firstName: Joi.string().required(),
        lastName: Joi.string().required(),
        email: Joi.string().required(),
        password: Joi.string().required().min(5),
        createdDate: Joi.date(),
        isAdmin: Joi.boolean(),
        avitar: Joi.string()
    });
    return schema.validate(user);
}

//things to check when updating
function validateUpdateUser(user){
    const schema = Joi.object({
        firstName: Joi.string().required(),
        lastName: Joi.string().required(),
        isAdmin: Joi.boolean(),
        avitar: Joi.string()
    });
    return schema.validate(user);
}

function validateLogin(user){
    const schema = Joi.object({
        email: Joi.string().required(),
        password: Joi.string().required()
    });
    return schema.validate(user);
}

function generateToken(length) {
    let result = '';
    let characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

exports.User = User;
exports.validateUser = validateUser;
exports.validateUpdateUser = validateUpdateUser;
exports.validateLogin = validateLogin;
exports.generateToken = generateToken;