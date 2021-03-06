const connectDB = require('./server/startup/db');
const express = require('express');
const app = express();
const cookieParser = require('cookie-parser');
const path = require('path');
const cors = require('cors');

if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config({ path: `./.env.${process.env.NODE_ENV}` });
    console.log(`enviroment running on ./.env.${process.env.NODE_ENV}`);
}

//app api examples
const user = require('./server/routes/users');
const port = process.env.PORT || 8080;

app.use(cookieParser());
app.use(cors({ origin: '*' }));

connectDB();
app.use(express.json());

/** Example */
app.use("/api/users", user);

const server = app.listen(port, () => {
    console.log(`Server started on port: ${port}`);
});

if (process.env.NODE_ENV === 'production') {
    app.use(express.static('client/build'));

    app.get('*', (req, res) => {
        res.sendFile(path.join(__dirname, 'client', 'build', 'index.html')); // relative path
    });
}

