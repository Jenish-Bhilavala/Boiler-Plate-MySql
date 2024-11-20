const express = require("express");
const router = express();
const userRoute = require("./routers/userRoute");

router.use("/api/users", userRoute);

module.exports = router;
