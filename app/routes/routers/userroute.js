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

router.get("/register", getUser);
router.post("/register", upload.single("image"), registerUser);
router.post("/login", loginUser);
router.post("/forgot-password", verifyEmail);
router.put("/reset-password", resetPassword);

module.exports = router;
