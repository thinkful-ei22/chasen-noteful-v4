'use strict';

const express = require('express');

const User = require('../models/user');

const router = express.Router();

router.post('/users', (req, res, next) =>{
  const requiredFields = ['username', 'password'];
  const missingField = requiredFields.find(field => !(field in req.body));
  const {username, password, fullname} = req.body;
  
  if (missingField){
    const err = new Error(`Missing '${missingField}' in request body`);
    err.status = 422;
    return next(err);
  }

  const stringFields = ['username', 'password', 'fullname'];
  const nonStringFields = stringFields.find(
    field => field in req.body && typeof req.body[field] !== 'string'  ////?
  );

  if (nonStringFields){
    const err = new Error(`Incorrect field type: ${nonStringFields} must be string`);
    err.status = 422;
    return next(err);
  }
 
  // If the username and password aren't trimmed we give an error.  Users might
  // expect that these will work without trimming (i.e. they want the password
  // "foobar ", including the space at the end).  We need to reject such values
  // explicitly so the users know what's happening, rather than silently
  // trimming them and expecting the user to understand.
  // We'll silently trim the other fields, because they aren't credentials used
  // to log in, so it's less of a problem.
  if (fullname){
    fullname.trim();
  }
  
  const explicitlyTrimmedFields = ['username', 'password'];
  const nonTrimmedFields = explicitlyTrimmedFields.find(
    field => req.body[field].trim() !== req.body[field]
  );

  if (nonTrimmedFields){
    const err = new Error(`Need to remove whitespace in ${nonTrimmedFields}`);
    err.status = 422;
    return next(err);
  }

  // bcrypt truncates after 72 characters, so let's not give the illusion
  // of security by storing extra **unused** info
  const sizedFields = {
    username: { min: 1 },
    password: { min: 8, max: 72 }
  };

  const tooSmallFields = Object.keys(sizedFields).find(
    field => 'min' in sizedFields[field] && req.body[field].trim().length < sizedFields[field].min
  );

  const tooLargeFields = Object.keys(sizedFields).find(
    field => 'max' in sizedFields[field] && req.body[field].trim().length < sizedFields[field].max
  );

  if (tooSmallFields || tooLargeFields){
    const err = tooSmallFields ? `Must be at least ${sizedFields[tooSmallFields].min} characters long`: `Must be at most ${sizedFields[tooLargeFields].min} characters long`;
  }

  User.find({username})       /////????????????
    .count()
    .then(count => {
      if(count > 0){
        return Promise.reject({
          code: 422,
          reason: 'ValidationError',
          message: `Username ${username} already exist, please pick a new one`,
          location: 'username'
        });
      }
      return User.hashPassword(password);
    })
    .then(digest => {
      const newUser = {
        username, 
        password: digest, 
        fullname
      };
      return User.create(newUser);
    })
    .then(result => {
      res.status(201).location(`/api/users/${result.id}`).json(result); 
    })
    .catch(err =>{
      if (err.reason === 'ValidationError') {
        return res.status(err.code).json(err); 
      }
      next(err);
    });
    
});

module.exports = router;