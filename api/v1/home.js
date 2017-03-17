const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const expressValidator = require('express-validator');
const router = express.Router();
const User = require('../../model/user');

router.get('/',function (req, res) {
    if(req.user){
      res.render('home/index', { user : req.user });
    } else {
      res.render('home/index');
    }

});

router.get('/about', function(req, res){
  if(req.user){
    res.render('home/about', { user : req.user });
  } else {
    res.render('home/about');
  }
});
function ensureAuthenticated(req, res, next){
  if(req.isAuthenticated()){
    console.log("auth");
    return next();
  } else {
    res.render('users/login', {username:'', error_msg: 'Debes estar logueado'});
  }
}

module.exports = router;
