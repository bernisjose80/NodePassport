const { Strategy } = require('passport-local');


//const AuthService = require('../../../services/auth.service');
const AuthService = require('../../../services/auth.service')
const service = new AuthService();

const LocalStrategy = new Strategy({
    usernameField: 'email',
    passwordField: 'password'
  },
  async (email, password, done) => {

    try {
      const user = await service.getUser(email, password); // llama a getUser en authservice
      done(null, user);

    } catch (error) {
      done(error, false);
    }

  }
  
);

module.exports = LocalStrategy;