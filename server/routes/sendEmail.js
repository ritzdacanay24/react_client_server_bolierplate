const nodemailer = require('nodemailer');

const sendEmail = async (mailOptions) => {
  let smtpTransport = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE,
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  smtpTransport.sendMail(mailOptions, function (error, responsBe) {
    if (error) {

      console.log(error);
      return false;
    } else {
      console.log(response);
      return true;
    }
  });
};

exports.sendEmail = sendEmail;
