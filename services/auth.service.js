const boom = require('@hapi/boom');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const { config } = require('./../config/config'); // se trae la variable de entorno secreto
const UserService = require('./user.service'); // importa el servicio de usuario para usar los metodos del usuario
const service = new UserService(); // se instancia la clase servicio

class AuthService {

  async getUser(email, password) {
    const user = await service.findByEmail(email);
    if (!user) {
      throw boom.unauthorized();
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      throw boom.unauthorized();;
    }
    delete user.dataValues.password;
    return user;
  }

  signToken(user) {
    const payload = {
      sub: user.id,
      role: user.role
    }
    const token = jwt.sign(payload, config.jwtSecret);
    return {
      user,
      token
    };
  }

  async sendRecovery(email) {
    const user = await service.findByEmail(email);
    if (!user) {
      throw boom.unauthorized();
    }

    const payload = { sub: user.id };
    const token = jwt.sign(payload, config.jwtSecret, {
      expiresIn: '15min',
    });
    const link = `https://myfrontend.com/recovery?token=${token}`;
    await service.update(user.id, { recoveryToken: token });
    const mail = {
      from: `"Foo Boo 👻" <${config.smtpEmail}>`,
      to: `${user.email}`,
      subject: 'Email para recuperar contraseña',
      html: `<b>Ingresa a este link para recuperar tu contraseña: ${link}</b>`,
    };

    const rta = await this.sendMail(mail);
    return rta;
  }

  async changePassword(token, newPassword) {
    try {
      const payload = jwt.verify(token, config.jwtSecret);
      const user = await service.findOne(payload.sub);
      if (user.recoveryToken !== token) {
        throw boom.unauthorized();
      }
      const hash = await bcrypt.hash(newPassword, 10);
      await service.update(user.id, {recoveryToken: null, password: hash});
      return { message: 'password changed' };
    } catch (error) {
      throw boom.unauthorized();
    }
  }

  async sendMail(infoMail) {
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      secure: true, // true for 465, false for other ports
      port: 465,
      auth: {
        user: config.smtpEmail,
        pass: config.smtpPassword,
      },
    });

    await transporter.sendMail(infoMail);
    return { message: 'Mail sent' };
  }
}

module.exports = AuthService;