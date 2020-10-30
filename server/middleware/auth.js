const jwt = require('jsonwebtoken');

function auth(req, res, next) {
   return next();
}

exports.auth = auth;
