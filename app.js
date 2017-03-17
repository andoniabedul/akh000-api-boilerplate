// DEPENDENCIES
const express = require('express');
const path = require('path');
const favicon = require('serve-favicon');
const logger = require('morgan');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');

// MIDDLEWAR VALIDATOR
const expressValidator = require('express-validator');
// DATABASE
const mongoose = require('mongoose');

// AUTHENTICATION
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

// ROUTES
const API = "/api/v1";
var home = require('.'+ API + '/home');
var users = require('.' + API + '/users');

// MODELS
var User = require('./model/user');

// CONFIG
var config = require('./config/env.json')[process.env.NODE_ENV || 'development'];

const app = express();
const router = express.Router();

// VALIDATOR
app.use(expressValidator());

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());


app.use(require('express-session')({
    secret: 'M4LD1T0-G0RD0-C0MUN1ST4',
    resave: false,
    saveUninitialized: false
}));

// PASSPORT
app.use(passport.initialize());
app.use(passport.session());

// PUBLIC DIRECTORY
app.use(express.static(path.join(__dirname, 'public')));

// FLASH MESSAGES
app.use(function(req, res, next){
  res.locals.success_msg = ''; // SUCCESSFULLY MESSAGES
  res.locals.error_msg = ''; // SINGLE ERROR
  res.locals.errors = ''; // MULTIPLE ERRORS
  res.locals.user = '';
  next();
})

// ROUTES

app.use(API + '/', home);
app.use(API + '/users', users);

// passport config
//passport.use(new //LocalStrategy(User.authenticate()));
//passport.serializeUser(User.serializeUser());
//passport.deserializeUser(User.deserializeUser());

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

console.log("######################################");
console.log("Launching environment on: ");
console.log(config.server);
console.log("######################################");
console.log(" ******* LAUNCHING EXAMPLE APP ******* ");
console.log("######################################");
console.log("Connecting database on: ");
console.log(config.mongo_uri + config.database);
console.log("######################################");
console.log("\n");

// LAUNCH CONNECTION WITH DATABASE
mongoose.connect(config.mongo_uri + config.database);

// LAUNCH THE APP ON THE LISTENING PORT
app.listen(config.port);

module.exports = app;
