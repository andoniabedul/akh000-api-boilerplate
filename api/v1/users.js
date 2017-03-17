const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const expressValidator = require('express-validator');
const router = express.Router();
const User = require('../../model/user');
const jwt = require('jsonwebtoken');
var mailHelper = require('../../helpers/mail');
var userHelper = require('../../helpers/users');

// CONFIG
var config = require('../../config/env.json')[process.env.NODE_ENV || 'development'];

// CHECK IF IS AUTHENTICATED
function ensureAuthenticated(req, res, next){
  if(req.isAuthenticated()){
    if(req.is('application/json')){
      var token = req.body.token || req.query.token || req.headers['x-access-token'];
      if (token) {
        // verifies secret and checks exp
        jwt.verify(token, config.session.secret, function(err, decoded) {
          if (err) {
            return res.json({ success: false, message: 'Failed to authenticate token.' });
          } else {
            // if everything is good, save to request for use in other routes
            req.decoded = decoded;
            return next();
          }
        });
      } else {
        return res.status(403).send({
            success: false,
            message: 'No token provided.'
        });
      }
    } else {
      req.referer = req.body.referer;
      return next();
    }
  } else {
    res.format({
      html:  function(){
        res.render('users/login', {username:'', error_msg: 'Debes estar logueado'});
      },
      json: function(){
        return res.status(403).send({
            success: false,
            message: 'No token provided.'
        });
      }
    });
  }
}

// REGISTER USERS BY USERNAME
router.get('/register', function(req, res) {
    res.render('users/register');
});

router.post('/register', function(req, res) {
    var username = req.body.username;
    var email = req.body.email;
    var name = req.body.name;
    var lastname = req.body.lastname;
    var password1 = req.body.password1;
    var password2 = req.body.password2;

    req.checkBody('username','Username is required').notEmpty();
    req.checkBody('email','Email not valid').isEmail();
    req.checkBody('email','Email cant be empty').notEmpty();
    req.checkBody('password1', 'Password cant be empty').notEmpty();
    req.checkBody('password2','Passwords do not match').equals(req.body.password1);
    req.checkBody('name', 'Name cant be empty').notEmpty();
    req.checkBody('lastname', 'Lastname cant be empty').notEmpty();

    // OPTIONAL TO-DO: RENDER ALL FIELDS WHERE DONT EXIST ERRORS TO THE FORM
    var errors = req.validationErrors();
    if (errors) {
      res.format({
        json: function(){
          res.send({
            success: false,
            message: "There are errors with the parameters" + errors
          });
        }
      });
    } else {
      User.getUserByUsername(username, function(err,checkUser){
        if(err){
          console.log("err " + err);
        } else {
          if(!checkUser){
            User.getUserByEmail(email, function(err, checkUser){
              if(!checkUser){
                var token = userHelper.generateToken();
                var verificationLink = userHelper.generateVerificationLink(username,token);
                mailHelper.sendVerificationEmail(email,verificationLink, name, function(response){
                  console.log('***** Sended email of verification *****');
                  console.log('***** Link ' + verificationLink + '*****');
                  console.log('***** Response: '+ JSON.stringify(response) + '*****');
                });
                var newUser = new User({
                  username: username,
                  password: password1,
                  email: email,
                  estatus: {verified: false, token:token},
                  name: name,
                  lastname: lastname
                });
                //return done(null, false, { success_msg: 'Username available!' });
                User.create(newUser, function(err,user){
                  if(err){
                    console.log("Error creating user: " + err);
                  }
                  res.format({
                    json: function(){
                      res.send({
                        success: true,
                        message:"Successfully registered user: " + username,
                        username: username,
                      });
                    }
                  });
                });
              } else {
                res.format({
                  json: function(){
                    res.send({
                      success: false,
                      message: "Already exist a user with that email",
                      error: errors
                    });
                  }
                });
              }
            });
          } else {
            res.format({
              json: function(){
                res.send({
                  success: false,
                  message: "Somebody already have that username",
                  error: errors
                });
              }
            });
          }
        }
      });
    }
});
//VERIFY USER EMAIL
router.get('/verify', function(req,res){
  var username = req.query.username;
  var token = req.query.token;
  User.getUserByUsername(username,function(err, user){
    if (err) return err;
    if(user.estatus.token === token){
      User.changeStatus(user, function(user){
        if(user.estatus.verified === true){
          //mailHelper.sendWelcomeEmail();
          res.format({
            html:function(){
              res.render('users/login', {success_msg: 'Awesome! Your email was verified correctly!' , user: user});
            },
            json: function(){
              res.send({success: true, message:"The email was verified correctly"});
            }
          });

        } else {
          res.format({
            html:function(){
              res.render('users/login', {error: 'Oops, error!'});
            },
            json: function(){
              res.send({
                success: false,
                message: "Error on the proccess of verify user. Try again."
              });
            }
          });

        }
      });

    }
  });
});
// LOGIN USERS BY USERNAME
router.get('/login', function(req, res) {
    var message = "";
    var username = '';
    if(req.headers.referer === config.server+'users/register' && req.query.username !== undefined){
      message = "Successfulyy create user";
      username = decodeURIComponent(req.query.username);
      res.format({
        html:function(){
          res.render('users/login', {success_msg: message, username: username});
        },
        json: function(){
          res.send({
            success: true,
            message: "Nothing to do here. Use the method POST for log in"
          });
        }
      });

    } else {
      res.format({
        html:function(){
          res.render('users/login', {username : ''});
        },
        json: function(){
          res.send({
            success: true,
            message: "Nothing to do here. Use the method POST for log in"
          });
        }
      });
    }
});

router.post('/login', function(req,res,next){
  passport.authenticate('local', function(err, user, info) {
    if (err) { return next(err); }
    if (user) {
      req.logIn(user, function(err) {
        if (err) { return next(err); }
        if(req.is('application/json')){
          res.format({
            // WHEN THE REQUEST ITS FROM API CALL
            json: function(){
              var token = jwt.sign(user, config.session.secret, {
                  expiresIn: "1 day" // expires in 24 hours
              });
              return res.json({
                success: true,
                message: 'Correctly logged. This token expires in 24 hours',
                token: token
              });
            }
          });
        } else {
          res.format({
            // WHEN THE REQUEST ITS FROM WEBPAGE
            html: function(){
              if(req.headers.referer.search('users') > 0){
                return res.redirect('/quotes');
              } else {
                return res.redirect(req.headers.referer);
              }
            }
          });
        }
      });
    } else {
      return res.format({
        json: function(){
          return res.json({success: false, message: info.error_msg});
        }
      });
    }
  })(req, res, next);
});

// PASSPORT LOCAL STRATEGY
passport.use(new LocalStrategy(
  function(username, password, done) {
    User.getUserByUsername(username, function(err, user) {
      if (err) { return done(err); }
      if (!user) {
        return done(null, false, { error_msg: 'That user doesnt exist.' });
      } User.comparePasswords(password, user.password,function(err, isMatch){
          if(err){
            console.log(err);
          } else {
            if(isMatch){
              return done(null, user);
            } else {
              return done(null,false, {error_msg: 'El password no coincide'});
            }
          }
        });
    });
  }
));

passport.use(new FacebookStrategy({
          clientID: '449778045413106',
          clientSecret: '85440fc38f0ebffba2800e5d61c0cde5',
          callbackURL: "http://localhost:3000/users/auth/facebook/callback",
          profileFields: ['id','email', 'displayName', 'name']
      },function(accessToken, refreshToken, profile, done) {
        process.nextTick(function () {
          var email = profile.emails[0].value;
          User.getUserByEmail(email, function(err, user){
            if(err) return console.log('Error searching user with that email');
            if(user){
              var userInfo = {user: user};
              var params = new Object();
              params.params = new Object();
              params.params.username = user.username;
              params.params.name = user.name;
              params.params.lastname = user.lastname;
              params.params.email = user.email;
              params.params.facebook = new Object();
              params.params.facebook.fbid = profile.id;
              params.params.facebook.token = accessToken;
              params.params.facebook.displayName = profile.displayName;
              params.params.facebook.email = profile.emails[0].value;
              User.updateInfo(userInfo,params, function(err, user){
                if(err) {
                  return done(err, null);
                } else {
                  console.log(JSON.stringify(user));
                  done(null,user);
                }

              });
            } else {
              var user = new User();

              user.username = profile.emails[0].value;

              user.email = profile.emails[0].value;

              user.password = "";

              user.name = (typeof profile.name.givenName === "undefined")? profile.displayName: profile.name.givenName;

              user.lastname = (typeof profile.name.familyName === "undefined")? "": profile.name.familyName;

              user.facebook.token = accessToken;

              user.facebookprofileUrl = profile.profileUrl;

              user.facebook.email = profile.emails[0].value;

              user.facebook.fbid = profile.id;

              user.facebook.displayName = profile.displayName;

              User.create(user, function(err,user){
                if(err) {
                  console.log("Error creating user: " + err);
                  return done(err, null);
                } else {
                  return done(null, user);
                }
              });
            }
          });
      });
    }
));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    done(err, user);
  });
});

router.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
      res.redirect('/quotes/all');
});

router.get('/auth/facebook', passport.authenticate('facebook', {scope:'email'}));

// PROFILE OF A USER
router.get('/profile', ensureAuthenticated, function(req, res){
  res.format({
    json: function(){
      res.send({success: true, message: "Profile info retrivied correctly", user: req.user});
    }
  });

});

router.post('/profile', ensureAuthenticated, function(req,res){
    if(Object.hasOwnProperty.call(req.body, "info")){
      var username = req.body.username;
      var name = req.body.name;
      var lastname = req.body.lastname;
      var email = req.body.email;
      params = {
        username: username,
        name: name,
        lastname: lastname,
        email: email
      };
      User.updateInfo({user: req.user},{params}, function(user){
        res.format({
          json: function(){
            res.send({success: true, message: "Info updated correctly", user: user});
          }
        });

      });
    } else if (Object.hasOwnProperty.call(req.body, "password")) {
      var oldPassword = req.body.oldPassword;
      var newPassword = req.body.newPassword1;
      var repeatNewPassword = req.body.newPassword2;
      req.checkBody('oldPassword', 'Password cant be empty').notEmpty();
      req.checkBody('newPassword1','Passwords do not match').equals(req.body.newPassword2);
      var errors = req.validationErrors();
      if (errors) {
        res.format({
          html:function(){
            res.render('users/profile', {
              user: req.user,
              errors: errors
            });
          },
          json: function(){
            res.send({
              success: false,
              message: "There are errors with the parameters"
            });
          }
        });

      } else {
        User.comparePasswords(oldPassword,req.user.password, function(err,isMatch){
          if(err){
            console.log("Error: " + err);
          } else {
            if(isMatch){
              console.log("El password coincide");
              User.updatePassword(req.user, newPassword, function(err, updated){
                if(err){
                  console.log("Error updating password: " + JSON.stringify(err));
                  res.format({
                    json: function(){
                      res.send({success: false, message:"Error updating password: " + err});
                    }
                  });

                } else {
                  res.format({
                    json: function(){
                      res.send({
                        success: true,
                        message: "Password updated correctly"
                      });
                    }
                  });
                }
              });
            } else {
              res.format({
                json: function(){
                  res.send({
                    success: false,
                    message: "Error: the password doesn't match"
                  });
                }
              });
            }
          }
        });
      }
    }
});

// LOGOUT
router.get('/logout', function(req, res) {
    req.logout();
    res.format({
      html:function(){
        res.redirect('/users/login');
      },
      json: function(){
        res.send({
          success: true,
          message: "Logout successfully"
        });
      }
    });

});

router.get('/forgotpassword', function(req,res){
  res.format({
    html:function(){
      res.render('users/forgotpassword');
    },
    json: function(){
      res.send({success: true, message: "Nothing to do here. Use method POST for forgot password"});
    }
  });
});

router.post('/forgotpassword', function(req,res){
  var username = req.body.username;
  var email = req.body.email;
  var newPassword = Math.random().toString(16).slice(2);
  var recoverPasswordLink;
  req.checkBody('username','Username is required').notEmpty();
  req.checkBody('email','Email not valid').isEmail();
  req.checkBody('email','Email cant be empty').notEmpty();

  var errors = req.validationErrors();
  if (errors) {
    res.format({
      html:function(){
        res.render('users/forgotpassword', {
          errors: errors
        });
      },
      json: function(){
        res.send({
          success: false,
          message: "There are errors with the parameters"
        });
      }
    });

  } else {
    User.getUserByEmail(email, function(err,user){
      if (err) return err;
      console.log(JSON.stringify(user));
      if(user){
        if(user.username === username){
          if(err){
            console.log("Error updating password: " + err);
            res.format({
              html:function(){
                res.render('users/login', {
                  error_msg: 'Error actualizando password'
                });
              },
              json: function(){
                res.send({
                  success: false,
                  message: "Error updating password: " + err
                });
              }
            });

          } else {
            User.createPasswordToken(user, function(user){
              userHelper.generateRememberPasswordLink(user.email, user.resetPasswordToken).then((link) => {
                console.log(link);
                mailHelper.sendRecoverPasswordEmail(user, link).then((response) => {
                  console.log('***** Sended email of recover password *****');
                  console.log('***** Link ' + link + '*****');
                  console.log('***** Response: '+ JSON.stringify(response) + '*****');
                  res.format({
                    html:function(){
                      res.render('users/login', {
                        success_msg: 'We send you a email for recover your password'
                      });
                    },
                    json: function(){
                      res.send({
                        success: true,
                        message: "Forgot password successfully. We send you a email for recover your password"
                      });
                    }
                  });
                });
              });
            });
          }
        } else {
          res.format({
            html:function(){
              res.render('users/forgotpassword', {error_msg: 'The email and password doesnt match'});
            },
            json: function(){
              res.send({
                success: false,
                message: "Theare are errors, the email and password doesn't match"
              });
            }
          });
        }
      } else {
        res.format({
          html:function(){
            res.render('users/forgotpassword', {error_msg: "Doesn't exist a user with that email"});
          },
          json: function(){
            res.send({
              success: false,
              message: "Doesnt exist a user with that email"
            });
          }
        });

      }
    });
  }
});

router.get('/recoverpassword', function(req, res, next){
  if(req.query.hasOwnProperty('email') && req.query.hasOwnProperty('token')){
    var email = req.query.email;
    var token = req.query.token;
    console.log("email-token: " + email + '-' + token);
    User.getUserByEmail(email, function(err, user){
      if (err) return err;
      console.log("getUserByEmail: " + user);
      if(user){
        User.verifyPasswordToken(token, function(err, user){
          if(err){
            console.log(err);
            res.format({
              html:function(){
                res.render('users/forgotpassword', {error_msg: 'Error recovering password.'});
              },
              json: function(){
                res.send({
                  success: false,
                  message: "Error recovering password: " + err
                });
              }
            });
          } else {
            res.format({
              html:function(){
                res.render('users/recoverpassword', {user: user});
              },
              json: function(){
                res.send({
                  success: true,
                  message: "Token for recover password was verified correctly"
                });
              }
            });

          }
        });
      } else {
        res.format({
          html:function(){
            res.render('users/forgotpassword', {error_msg: "Doesn't exist any user with that email"});
          },
          json: function(){
            res.send({
              success: false,
              message: "There are errors. Doesn't exist a user with that email"
            });
          }
        });

      }
    });
  } else {
    res.format({
      html:function(){
        res.render('users/forgotpassword', {error: 'Error recovering password'});
      },
      json: function(){
        res.send({
          success: false,
          message: "You must provide a email and a token associated with it"
        });
      }
    });
  }
});

router.post('/recoveringpassword', function(req, res){
  var token = req.body.resetPasswordToken;
  console.log("User: " + JSON.stringify(req.user));
  var newPassword = req.body.newPassword;
  var newPassword2 = req.body.newPassword2;
  req.checkBody('newPassword', 'Password cant be empty').notEmpty();
  req.checkBody('newPassword2','Passwords do not match').equals(newPassword);
  var errors = req.validationErrors();
  if (errors) {
    res.format({
      html:function(){
        res.render('users/forgotpassword', {
          errors: errors
        });
      },
      json: function(){
        res.send({
          success: false,
          message: "There are errors recovering password: " + errors
        });
      }
    });
  } else {
    User.verifyPasswordToken(token, function(err, user){
      if(err){
        res.format({
          html:function(){
            res.render('users/forgotpassword', {error_msg: 'Error recovering password.'});
          },
          json: function(){
            res.send({
              success: false,
              message: "There are errors. " + err
            });
          }
        });
      } if (user) {
        User.updatePassword(user, newPassword, function(err, user){
          if(user){
            res.format({
              html:function(){
                res.render('users/login', {success_msg: 'Congratulations, log in with your new password'});
              },
              json: function(){
                res.send({
                  success: true,
                  message: "The password was reseted correctly. Login with the new password"
                });
              }
            });
          } else {
            res.format({
              html:function(){
                res.render('users/forgotpassword', {error_msg: 'Error updating password'});
              },
              json: function(){
                res.send({
                  success: false,
                  message:"There are errors updating password"
                });
              }
            });
          }
        });
      }
    });
  }
});

module.exports = router;
