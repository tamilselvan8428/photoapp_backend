const nodemailer = require('nodemailer');

// Create a transporter object using the default SMTP transport
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

/**
 * Send an email with OTP
 * @param {string} to - Recipient email address
 * @param {string} otp - The OTP to send
 * @returns {Promise} - Promise that resolves when email is sent
 */
const sendOtpEmail = (to, otp) => {
  const mailOptions = {
    from: `"PhotoGallery" <${process.env.EMAIL_USER}>`,
    to,
    subject: 'Your OTP for PhotoGallery',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #4f46e5;">PhotoGallery - OTP Verification</h2>
        <p>Hello,</p>
        <p>Your OTP for logging in to PhotoGallery is:</p>
        <div style="background-color: #f3f4f6; padding: 15px; margin: 20px 0; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; color: #1f2937;">
          ${otp}
        </div>
        <p>This OTP is valid for 10 minutes.</p>
        <p>If you didn't request this, please ignore this email.</p>
        <p>Best regards,<br>The PhotoGallery Team</p>
      </div>
    `
  };

  return transporter.sendMail(mailOptions);
};

module.exports = { sendOtpEmail };
