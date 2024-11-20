const express = require("express");
const router = express();
const userRoute = require("./routers/userroute");

router.use("/api/users", userRoute);

module.exports = router;
