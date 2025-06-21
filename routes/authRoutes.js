const express = require("express");
const authController = require("../controllers/authController"); // Make sure this path is correct

const router = express.Router();

router.post("/send-code", authController.sendCode);
router.post("/sign-up", authController.sendCode);
router.post("/verify-code", authController.verifyCode);
router.post("/sign-in", authController.signIn);
router.post("/google-apple-signin", authController.googleAppleSignIn);

module.exports = router;