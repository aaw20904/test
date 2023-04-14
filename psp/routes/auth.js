var express = require('express');
var passport = require('passport');
var LocalStrategy = require('passport-local');
var crypto = require('crypto');
var db = require('../db');
//create a router instance
var router = express.Router();

passport.use(new LocalStrategy(verify));

async function verify(username, password, cb) {

  let usrinfo, hashedPasswFromReq;
  try{ //read user info from the DB
        usrinfo = await new Promise((resolve, reject) => {
            
            db.get('SELECT * FROM users WHERE username = ?', [ username ], function(err, row) {
                if (err) {
                    reject(err);
                    return; 
                } else {
                    resolve(row);
                }
            });

         });
  } catch(e){
    //when DB error occured
     return cb(e);
  }
  //checking - is a user exists:
  if (!usrinfo) {
    return cb(null, false, { message: 'Incorrect username or password.' });
  }
  //create a hash from a given http request`s password:
  try{
hashedPasswFromReq = await   new Promise((resolve, reject) => {
                //making hash
                crypto.pbkdf2(password, usrinfo.salt, 310000, 32, 'sha256', function(err, hashedPassword) {
                    if (err) { 
                        reject(err);
                        return; 
                    } else{
                        resolve(hashedPassword);
                    }
                                        
                 });
            });
} catch(e) {
    return cb(e);
}
    //comparing a hash from the DB and a hash from the request (generated previously):
    if (!crypto.timingSafeEqual(usrinfo.hashed_password, hashedPasswFromReq)) {
        return cb(null, false, { message: 'Incorrect username or password.' });
    }
    //when a passwort has been matched successfully:
    return cb(null, usrinfo);

}

router.get('/login', function(req, res, next) {
  res.render('login',{time: new Date().toLocaleTimeString()});
});

router.get('/signup', function(req, res, next) {
  res.render('signup');
});

router.post('/logout', function(req, res, next) {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});


router.post('/login/password', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login'
}));
/*** */

router.post('/signup', async function(req, res, next) {
     let hashedUsrPassw , salt, user;
    //generate salt:
     salt = crypto.randomBytes(16);
    //create a hash of the password
   
try {
        hashedUsrPassw =await new Promise((resolve, reject) => {
                crypto.pbkdf2(req.body.password, salt, 310000, 32, 'sha256', function(err, hashedPassword) {
                    if (err) {
                        reject(err);
                    }
                    resolve(hashedPassword);
                })
        });
 
/*insert into the DB: */

  user = await new Promise((resolve, reject) => {
            db.run('INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)', [
                req.body.username,
                hashedUsrPassw,
                salt
                ], function(err) {
                    if (err) { 
                        reject(err); 
                    }
                    var user = {
                        id: this.lastID,
                        username: req.body.username
                    };
                    resolve(user);
                })
    });


//login a new user

    await  new Promise((resolve, reject) => {
            req.login(user, function(err) {
            if (err) { 
                    reject(err); 
                }
            res.redirect('/');
            resolve()
        });
        });
} catch (error) {
    return next(error);
}


})


passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

module.exports = router;