const nodemailer = require("nodemailer");


const env = require("./env");
const transporter = nodemailer.createTransport({
  service: "gmail",

  auth: {
    user: env.EMAIL_USER,
    pass: env.EMAIL_APP_PASSWORD,
  },
});

transporter.verify((error, success) => {
  if (error) {
    console.log("Email connection error:", error);
  } else {
    console.log("Email server is ready");
  }
});
module.exports = transporter;