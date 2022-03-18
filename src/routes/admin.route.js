//  require dependencies
const express = require("express");
const router = express.Router();
const { authenticate, authorize } = require("../middleware/auth.middleware");
const {
  createAdmin,
  loginAdmin,
  getAllUsers,
  isBlocked,
  countUsers,
} = require("../controllers/admin.controller");
//  creating a route
router.post("/createAdmin", createAdmin);
router.post("/loginAdmin", loginAdmin);
router.get("/getAllUsers", authenticate, authorize, getAllUsers);
router.patch("/block", authenticate, authorize, isBlocked);
router.get("/countUsers", authenticate, authorize, countUsers);

//    exporting modules
module.exports = router;
