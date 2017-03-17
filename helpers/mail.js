var nodemailer = require('nodemailer');
var transporter = nodemailer.createTransport('smtps://akh000developerservices%40gmail.com:s3rv3rg0d@smtp.gmail.com');
// CONFIG
var config = require('../config/env.json')[process.env.NODE_ENV || 'development'];

module.exports.sendVerificationEmail = function(toEmail,verificationLink, name, callback){
  // setup e-mail data with unicode symbols
  var mailOptionsVerification = {
      from: '"AKH000 Developer Services" <AKH000DeveloperServices@gmail.com>', // sender address
      to: toEmail, // list of receivers
      subject: 'Verify your email on ' + config.titles.app, // Subject line
      text: 'Hi there! From StudentHUB. Please verify your email on this link: ' + verificationLink + 'Thank you!', // plaintext body
      html:
      ['<h2>Hi '+ name +'!</h2><br>',
        '<h3>Its from StudentHUB</h3>',
        '<p>Please verify your email on this link: </p>',
        '<a href='+verificationLink+'><b>LINK TO VERIFY HERE</b></a>',
        '<h4>Thank you!<h4>'
      ].join('\r\n') // html body
  };

  // send mail with defined transport object
  transporter.sendMail(mailOptionsVerification, function(error, info){
      if(error){
          callback(error);
          return console.log(error);
      } else {
        console.log('Message to verify account sent: ' + info.response);
        callback(info.response);
      }
  });
}

module.exports.sendWelcomeEmail = function(user, callback){

}

module.exports.sendRecoverPasswordEmail = function(user, recoverPasswordLink){
  var mailOptionsRecoverPassword = {
      from: '"AKH000 Developer Services" <AKH000DeveloperServices@gmail.com>', // sender address
      to: user.email, // list of receivers
      subject: 'Recovering your password ' + config.titles.app, // Subject line
      text: 'Hi '+ user.name + 'there! From StudentHUB. Please recover your password on this link: ' + decodeURIComponent(recoverPasswordLink) + 'Thank you!', // plaintext body
      html:
      ['<h2>Hi '+ user.name +'!</h2><br>',
        '<h3>Its from StudentHUB</h3>',
        '<p>We received a petition for reset your password: </p>',
        '<p>Please, click the link below to reset your password: </p>',
        '<a href='+ decodeURIComponent(recoverPasswordLink) +'><b>LINK TO RECOVER PASSWORD HERE</b></a>',
        '<p>If you dont make this action, please ignore this email. </p>',
        '<h4>Thank you!<h4>'
      ].join('\r\n') // html body
  };

  // send mail with defined transport object
  return new Promise((resolve,reject)=>{
    transporter.sendMail(mailOptionsRecoverPassword, function(error, info){
        if(error){
            return reject(error);
        } else {
          return resolve(info.response);
        }
    });
  });
}

module.exports.sendRecoveredPasswordEmail = function(user, callback){
  var mailOptionsRecoverPassword = {
      from: '"AKH000 Developer Services" <' +config.email.main+ '>', // sender address
      to: user.email, // list of receivers
      subject: 'Your password has been changed |' + config.titles.app, // Subject line
      text: 'Hi '+ user.name + 'there! \r\n Its From StudentHUB. \r\n This is a confirmation that the password for your account ' + user.email + 'has just been changed. \r\n If exist any problem, please contact us ' + nconf.get('email:support'), // plaintext body
      html:
      ['<h2>Hi '+ user.name +'!</h2><br>',
        '<h3>Its from StudentHUB</h3>',
        '<p>This is a confirmation that the password for your account  </p>',
        '<p>' + user.email + ' has just been changed. </p>',
        '<p>If exist any problem, please contact us </p>',
        '<p>' + config.email.support + ' </p>',
        '<h4>Thank you!<h4>'
      ].join('\r\n') // html body
  };

  // send mail with defined transport object
  transporter.sendMail(mailOptionsRecoverPassword, function(error, info){
      if(error){
          callback(error);
          return console.log(error);
      } else {
        console.log('Message recovering password sent: ' + info.response);
        callback(info.response);
      }
  });
}
