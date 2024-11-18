const express = require("express");
const router = express();
const userRoter = require("./routers/userRoute");

router.use("/api/users", userRoter);

module.exports = router;
