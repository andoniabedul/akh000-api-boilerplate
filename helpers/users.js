const bcrypt = require('bcrypt-nodejs');
// CONFIG
var config = require('../config/env.json')[process.env.NODE_ENV || 'development'];
// Generates hash using bCrypt
// ENCRYPT -> GENERATE HASH
module.exports.createHash = function(string){
 return bcrypt.hashSync(string, bcrypt.genSaltSync(8), null);
}

// DESENCRYPT -> COMPARE HASH
module.exports.isValidPassword = function(user, password){
  return bcrypt.compareSync(password, user.password);
}

module.exports.isValidHash= function(token, compareToken){
  return bcrypt.compareSync(token, compareToken);
}

module.exports.generateToken = function(){
  function partToken(){
    return Math.random().toString(36).substr(2);
  }
  return partToken() + partToken();
}

module.exports.generateVerificationLink = function(username,token){
  var server = config.server;
  var link = server + 'users/verify?username='+username+'&'+'token='+token;
  return link;
}

module.exports.generateRememberPasswordLink = function(email,token){
  var server = config.server;
  var link = server + 'users/recoverpassword?email='+email+'&'+'token='+token;
  return new Promise((resolve, reject) => {
    return resolve(encodeURIComponent(link));
  });
}
