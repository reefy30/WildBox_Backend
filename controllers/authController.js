const { Resend } = require('resend');

const User = require("../models/user");
const VerificationCode = require("../models/verificationCode");
const jwt = require("jsonwebtoken");

if (!process.env.RESEND_API) {
  throw new Error("RESEND_API environment variable is not defined");
}
const resend = new Resend(process.env.RESEND_API);

exports.sendCode = async (req, res) => {
  const { email } = req.body;
  console.log("sendCode called for:", email);

  if (!email || !email.includes("@")) {
    console.log("Invalid email address");
    return res.status(400).json({ message: "Invalid email address" });
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = new Date(Date.now() + 2 * 60 * 1000); // 2 minutes expiration

  try {
    await VerificationCode.deleteMany({ email });
    await VerificationCode.create({ email, code, expiresAt });

    const result = await resend.emails.send({
      from: 'WildBox <onboarding@resend.dev>',
      //from: 'noreply@wildbox-server.onrender.com',
      to: [email],
      subject: "Wildbox Verification",
      html: `Your verification code is: ${code}`
    })
    console.log(result)

    return res.json({ message: "Verification code sent" });

    /*
    const transporter = nodemailer.createTransport({
      service: 'hotmail',
      auth: {
        user: process.env.HOTMAIL_USER,
        pass: process.env.HOTMAIL_PASS
      }
    });

    const mailOptions = {
      from: 'Wildbox',
      to: email,
      subject: "Wildbox Verification",
      text: `Your verification code is: ${code}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Failed to send email:", error);
        return res.status(500).json({ message: "Failed to send email" });
      } else {
        console.log("Email sent:", info.response);
        return res.json({ message: "Verification code sent" });
      }
    });
    */
  } catch (err) {
    console.error("Error in sendCode:", err);
    return res.status(500).json({ message: "Server error" });
  }
};

exports.verifyCode = async (req, res) => {
  const { email, code } = req.body;

  const entry = await VerificationCode.findOne({ email, code });
  if (!entry || entry.expiresAt < new Date()) {
    return res.status(400).json({ message: "Invalid or expired code" });
  }

  let user = await User.findOne({ email });
  if (!user) {
    user = new User({ email });
    await user.save();
  }

  await VerificationCode.deleteMany({ email });

  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
    expiresIn: "1h"
  });

  res.json({ token, user: { id: user._id, email: user.email } });
};

exports.signIn = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h"
    });

    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};

exports.googleAppleSignIn = async (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ message: "Email is required" });

  try {
    let user = await User.findOne({ email });
    if (!user) {
      user = new User({ email });
      await user.save();
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h"
    });

    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};
