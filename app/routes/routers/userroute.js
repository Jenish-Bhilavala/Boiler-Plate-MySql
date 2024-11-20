const express = require("express");
const router = express.Router();
const upload = require("../../services/multer");
const {
  getUser,
  registerUser,
  loginUser,
  verifyEmail,
  resetPassword,
} = require("../../controller/usercontroller");

router.get("/registration", getUser);
router.post("/registration", upload.single("image"), registerUser);
router.post("/login", loginUser);
router.post("/verify-email", verifyEmail);
router.post("/verify-email", resetPassword);

module.exports = router;
