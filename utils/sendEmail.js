const transporter = require("../config/mailer");
const env = require("../config/env");
const sendEmail = async ({ to, subject, html }) => {
  await transporter.sendMail({
    from: env.EMAIL_USER,
    to,
    subject,
    html,
  });
};


module.exports = sendEmail;