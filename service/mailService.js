const nodeMailer = require('nodemailer')

class MailService {
  constructor() {
    this.transporter = nodeMailer.createTransport({
      service: process.env.SMTP_SERVICE, // указываем сервис, который будет отправлять письмо
      auth: {
        user: process.env.SMTP_USER, // адрес почты, с которой будет отправляться письмо
        pass: process.env.SMTP_PASSWORD, // сгенерированный пароль, после подключения 2-х этапной аутен-ции
      },
    })
  }
  // Метод для отправки письма с активацией:
  async sendActivationMail(email, link) {
    await this.transporter.sendMail({
      from: process.env.SMTP_USER, // кто отправляет письмо
      to: email, // кому отправить это письмо
      subject: `Активация аккаунта на ${process.env.API_URL}`, // тема письма
      text: '',
      // html разметка для тела письма:
      html: `
        <div>
          <h3>Для активации перейдите по ссылке:</h3>
          <a href="${link}">${link}</a>
        </div>`
    })
  }
}

module.exports = new MailService()