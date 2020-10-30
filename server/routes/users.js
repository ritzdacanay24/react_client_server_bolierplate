const { User, validateUser, validateLogin, generateToken } = require('../models/user');
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { auth } = require('../middleware/auth');
const { sendEmail } = require('./sendEmail');

//create user
router.post('/', async (req, res) => {
    try {
        const { error } = validateUser(req.body);
        if (error) return res.status(400).send(error.details[0].message);

        let user = await User.findOne({ email: req.body.email });
        if (user) return res.status(400).send("User already registered")

        const salt = await bcrypt.genSalt(10);

        user = new User({
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            email: req.body.email,
            password: await bcrypt.hash(req.body.password, salt)
        })

        await user.save();

        return res.send("User created");
    }

    catch (ex) {
        return res.status(500).send(`Internal Server Error: ${ex}`)
    }
})

//update user
router.put('/:userId', auth, async (req, res) => {
    try {

        let userId = req.params.userId;

        let user = await User.findOne({ _id: userId });
        if (!user) return res.status(400).send("User not found.")

        User.findOneAndUpdate({ _id: userId }, { $set: req.body }, { upsert: true, new: true }, function (err, doc) {
            if (err) return res.status(500).send(`Internal Server Error: ${err}`)
            return res.send(doc);
        });
    }

    catch (ex) {
        return res.status(500).send(`Internal Server Error: ${ex}`)
    }
})

//delete user by Id
router.delete('/:userId', auth, async (req, res) => {
    try {

        User.findOneAndRemove({ _id: req.params.userId }, function (err, doc) {
            if (err) return res.status(500).send(`Internal Server Error: ${err}`)
            return res.send(doc);
        });
    }

    catch (ex) {
        return res.status(500).send(`Internal Server Error: ${ex}`)
    }
})

//Get all Users
router.get('/', async (req, res) => {
    try {
        let user = await User.find();
        return res.send(user);
    }
    catch (ex) {
        return res.status(500).send(`Internal Server Error: ${ex}`)
    }
})

//Get all Users
router.get('/:userId', auth, async (req, res) => {
    try {
        let userId = req.params.userId;
        let user = await User.findOne({ _id: userId });
        if (!user) return res.send(false);
        return res.send(user);
    }

    catch (ex) {
        return res.status(500).send(`Internal Server Error: ${ex}`)
    }
})

//Login User
router.post('/login', async (req, res) => {
    try {
        const { error } = validateLogin(req.body);
        if (error) return res.status(400).send(error.details[0].message);

        let user = await User.findOne({ email: req.body.email });
        
        if (!user) return res.status(400).send('Invalid email or password.');
        if (!user.confirmedRegisted) return res.status(400).send('Please check email to confirm account.');

        const validPassword = await bcrypt.compare(req.body.password, user.password);
        if (!validPassword) return res.status(400).send('Invalid email or password.')

        const token = user.generateAuthToken();

        return res
            .header('x-auth-token', token)
            .header('access-control-expose-headers', 'x-auth-token')
            .send({ appToken: token, userId: user._id });
    }
    catch (ex) {
        return res.status(500).send(`Internal Server Error: ${ex}`);
    }
})

//Forgot password email check
router.post('/forgotPassword', async (req, res) => {
    try {

        let user = await User.findOne({ email: req.body.email });
        if (!user) return res.status(400).send('Email not found');

        let randomToken = generateToken(25);

        user.resetPasswordToken = {
            token: randomToken
        }

        await user.save();

        //TODO:Send Email

        return res.send('Email sent. Please check email/spam folder. Thank you');
    }
    catch (ex) {
        return res.status(500).send(`Internal Server Error: ${ex}`);
    }
})

//Verify password token
router.get('/verifyPasswordToken/:token', async (req, res) => {
    try {

        let token = await User.findOne({ "resetPasswordToken.token": req.params.token });
        if (!token) return res.status(400).send('Token not found');

        return res.send({ message: true })

    }
    catch (ex) {
        return res.status(500).send(`Internal Server Error: ${ex}`);
    }
})

//Reset Password and delete token
router.post('/resetPassword', async (req, res) => {
    try {

        let user = await User.findOne({ "resetPasswordToken.token": req.body.token });
        if (!user) return res.status(400).send('Token not found');

        const salt = await bcrypt.genSalt(10)
        let saltPassword = await bcrypt.hash(req.body.password, salt);

        await User.findOneAndUpdate({ _id: user._id }, {
            $set: {
                password: saltPassword, resetPasswordToken
                    : []
            }
        }, { new: true }, (err, doc) => {
            if (err) {
                return res.status(500).send(`Internal Server Error`);
            }
            return res.send(doc);
        });
    }

    catch (ex) {
        return res.status(500).send(`Internal Server Error: ${ex}`)
    }
})

//User request change password
router.put('/:userId/passwordChange', async (req, res) => {
    try {

        //get user info
        let user = await User.findOne({ _id: req.params.userId });
        if (!user) return res.status(400).send('Invalid User');

        //check if current password matches in db.
        const validPassword = await bcrypt.compare(req.body.currentPassword, user.password);
        if (!validPassword) return res.status(400).send('Invalid email or password.')

        //change password using salt
        const salt = await bcrypt.genSalt(10)
        let saltPassword = await bcrypt.hash(req.body.newPassword, salt);

        await User.findOneAndUpdate({ _id: user._id }, {
            $set: {
                password: saltPassword
            }
        }, { new: true }, (err, doc) => {
            if (err) {
                return res.status(500).send(`Internal Server Error`);
            }
            return res.send(doc);
        });
    }

    catch (ex) {
        return res.status(500).send(`Internal Server Error: ${ex}`)
    }
})

module.exports = router
