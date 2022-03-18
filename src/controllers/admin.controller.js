//  Require dependencies

const Admin = require("../models/admin.model");
const User = require("../models/user.model");
const { successResMsg, errorResMsg } = require("../utils/response");
const AppError = require("../utils/appError");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const bcrypt = require("bcrypt");
const {
  validateRegister,
  validateLogin,
} = require("../middleware/validiate.middleware");

//  creating  Admin
const createAdmin = async (req, res, next) => {
  try {
    const { firstName, lastName, phoneNumber, email, password } = req.body;
    const result = await validateRegister.validateAsync(req.body);

    // validating phoneNumber
    const phoneNumberExist = await Admin.findOne({ phoneNumber });
    if (phoneNumberExist) {
      return res.status(401).json({
        message: "phoneNumber exists, please login",
      });
    }
    // validating email
    const emailExist = await Admin.findOne({ email });
    if (emailExist) {
      return res.status(401).json({
        message: "email exists, please login",
      });
    }
    // hashing password
    const hashPassword = await bcrypt.hash(password, 10);

    // create  a new Admin
    const newAdmin = await Admin.create({
      firstName,
      lastName,
      phoneNumber,
      email,
      password: hashPassword,
    });
    return successResMsg(res, 201, {
      message: "Admin  created",
      newAdmin,
    });
  } catch (error) {
    return errorResMsg(res, 500, { message: error.message });
  }
};
//  login for Admin
const loginAdmin = async (req, res, next) => {
  try {
    const { phoneNumber, password } = req.body;
    const login = await validateLogin.validateAsync(req.body);

    const phoneNumberExist = await Admin.findOne({ phoneNumber });
    if (!phoneNumberExist) {
      return res.status(401).json({
        message: "phoneNumber does not exist, please create an account",
      });
    }
    let isPasswordExist = await bcrypt.compare(
      password,
      phoneNumberExist.password
    );
    if (!isPasswordExist) {
      return res.status(401).json({
        message: "Password Not Correct",
      });
    }
    if (phoneNumberExist.role == "User") {
      return res.status(401).json({
        message: "Unauthorized",
      });
    }
    const data = {
      id: phoneNumberExist._id,
      phoneNumber: phoneNumberExist.phoneNumber,
      role: phoneNumberExist.role,
    };

    const token = await jwt.sign(data, process.env.SECRET_TOKEN, {
      expiresIn: "1h",
    });
    return res.status(200).json({
      success: true,
      message: "Admin login successfully",
      token,
    });
  } catch (error) {
    return res.status(500).json({
      message: error.message,
    });
  }
};
//  getting all Users
const getAllUsers = async (req, res, next) => {
  try {
    const getUsers = await User.find();
    return res.status(200).json({
      getUsers,
    });
  } catch (error) {
    return res.status(500).json({
      message: error.message,
    });
  }
};
//   blocking a user
const isBlocked = async (req, res, next) => {
  try {
    if (
      req.body.firstName ||
      req.body.lastName ||
      req.body.phoneNumber ||
      req.body.email ||
      req.body.password
    ) {
      return res.status(400).json({
        message: `Only blocked status can be modified`,
      });
    }
    const { email } = req.query;
    const blockUser = await User.findOneAndUpdate({ email }, req.body, {
      new: true,
    });
    return res.status(200).json({
      blockUser,
    });
  } catch (error) {
    return res.status(500).json({
      message: error.message,
    });
  }
};
//  counting all registered user
const countUsers = async (req, res, next) => {
  try {
    const usercount = await User.countDocuments();
    return res.status(200).json({
      usercount,
    });
  } catch (error) {
    return res.status(500).json({
      message: error.message,
    });
  }
};

//  exporting module
module.exports = {
  createAdmin,
  loginAdmin,
  getAllUsers,
  isBlocked,
  countUsers,
};
