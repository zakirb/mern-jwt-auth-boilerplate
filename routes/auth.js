require('dotenv').config();
var express = require('express');
var router = express.Router();
var mongoose = require('mongoose');
var User = require('../models/user');
var bcrypt = require('bcrypt');

var expressJWT = require('express-jwt');
var jwt = require('jsonwebtoken');

router.post('/login', (req, res, next) => {
  let hashedPass = ''
  let passwordMatch = false

  //Look up the user
  User.findOne( {email: req.body.email}, function (err, user) {
    hashedPass = user.password
    //compare hashedPass to submitted password
    passwordMatch = bcrypt.compareSync(req.body.password, hashedPass)
    if (passwordMatch) {
      //the passwords match...
      var token = jwt.sign(user.toObject(), process.env.JWT_SECRET, {
        expiresIn: 60 * 60 * 24 //expires in 24 hr
      })
      res.json({user, token})
    } else {
      console.log("Passwords don't match")
      res.status(401).json({
        error: true,
        message: 'Email or password is incorrect'
      })
    }
  })
})

router.post('/signup', function (req, res, next) {
  User.findOne({ email: req.body.email }, function (err, user) {
    if (user) {
      res.redirect('/auth/signup')
      console.log('ALREADY SIGNED UP!!!!!')
    } else {
      User.create({
        name:req.body.name,
        email:req.body.email,
        password:req.body.password
      }, function(err, user) {
        if (err) {
          res.send(err)
        } else {
          var token = jwt.sign(user.toObject(), process.env.JWT_SECRET, {
            expiresIn: 60 * 60 * 24
          })
          res.json({user, token})
        }
      })
    }
  })
})

router.post('/me/from/token', (req, res, next) => {
  // Check for presence of token
  var token = req.body.token
  if (!token) {
    res.status(401).json({message: "Must pass the token"})
  } else {
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        res.status(401).send(err)
      } else {
        User.findById({
          '_id': user._id
        }).then( (err, user) => {
          if (err) {
            res.status(401).send(err)
          } else {
            res.json({user, token})
          }
        })
      }
    })
  }
})

module.exports = router
