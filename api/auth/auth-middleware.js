const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require('../users/users-model')
const jwt = require('jsonwebtoken');

const restricted = async (req, res, next) => {
  if(req.headers.authorization) {
    try {
      req.decodedJWT = await jwt.verify(req.headers.authorization, JWT_SECRET)
      next();
      // let user = await Users.findById(req.decodedJWT.sub)
      // console.log(user)
    } catch (error) {
      next({status:401, message: 'Token invalid'})
      return
    }
  }else{
    next({status:401, message: 'Token required'})
    return
  }
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
}

const only = role_name => (req, res, next) => {
  try {
    if(req.decodedJWT.role_name != role_name) {
      next({status: 403, message:'This is not for you'})
      return
    }
      next();
  } catch (error) {
      next({message: 'Internal server error'})
  }
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
}


const checkUsernameExists = async (req, res, next) => {
  try {
    const {username} = req.body
    let nameExists= await Users.findBy({username}).first()

    if(nameExists==null) {
      next({status: 401, message: 'Invalid credentials'})
    }else{
      req.user=nameExists
      next()
    }
  } catch (error) {
    next({message: 'Internal server error'})
  }


  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
}


const validateRoleName = (req, res, next) => {
  if (req.body.role_name != null && req.body.role_name!=='admin'){
    req.body.role_name = req.body.role_name.trim()
    next()
  }
  if(req.body.role_name==null|| req.body.role_name.trim() ==='') {
    req.body.role_name='student'
    next()
  }else if(req.body.role_name==='admin'){
    res.status(422).json({message:'Role name can not be admin'})
    return
  }else if(req.body.role_name.trim().length >32) {
    res.status(422).json({message:'Role name can not be longer than 32 chars'})
    return
  }
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
