/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , util = require('util')
  , jwt = require('jwt-simple');


/**
 * Creates an instance of `Strategy`.
 *
 * The JWT Simple authentication strategy authenticates requests based on
 * a bearer token contained in the `Authorization` header field, `access_token`
 * body parameter, or `access_token` query parameter.
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(token, done) { ... }
 *
 * `token` is the bearer token provided as a credential.  The verify callback
 * is responsible for finding the user who posesses the token, and invoking
 * `done` with the following arguments:
 *
 *     done(err, user, info);
 *
 * If the token is not valid, `user` should be set to `false` to indicate an
 * authentication failure.  Additional token `info` can optionally be passed as
 * a third argument, which will be set by Passport at `req.authInfo`, where it
 * can be used by later middleware for access control.  This is typically used
 * to pass any scope associated with the token.
 *
 *
 * Examples:
 *
 *     passport.use(new BearerStrategy(
 *       function(token, done) {
 *         User.findByToken({ token: token }, function (err, user) {
 *           if (err) { return done(err); }
 *           if (!user) { return done(null, false); }
 *           return done(null, user, { scope: 'read' });
 *         });
 *       }
 *     ));
 *
 *
 * @constructor
 * @param {Object} [options]
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {

  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) { throw new TypeError('JWT Strategy requires a verify callback'); }
  if (!options.secret) { throw new TypeError('Pass the JWT secret in options'); }
  
  passport.Strategy.call(this);
  this.name = 'jwt-strategy';
  this._verify = verify;
  this._secret = options.secret;
  this._passReqToCallback = options.passReqToCallback;  
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a JWT authorization
 * header, body parameter, or query parameter.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req) {

  var token = (req.body && req.body.access_token) || (req.query && req.query.access_token) || req.headers['x-access-token'];
  
  if (!token) { return this.fail(400); }
  
  try {  
    var payload = jwt.decode(token, this._secret);
    var userId = payload.id;
  }
  catch(err) {
    return this.fail(400);
  }
  
  var self = this; 
  
  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    
    var property = req._passport.instance._userProperty || 'user';
    req[property] = user;
    self.success(user, info);
  }
  
  if (self._passReqToCallback) {
    this._verify(req, userId, verified);
  } else {
    this._verify(userId, verified);
  }
  
 
};



/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
