//  Require dependencies
const User = require("../models/user.model");
const { successResMsg, errorResMsg } = require("../utils/response");
const AppError = require("../utils/appError");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const bcrypt = require("bcrypt");
const {validiateUser, UserLogin} = require("../middleware/validiate.middleware")

//  creating  a user
const createUser = async (req, res, next) => {
  try {
    const { firstName, lastName, phoneNumber, email, password, accountNumber } =
      req.body;
      const registerUser = await validiateUser.validateAsync(req.body);
    let accountNumberGenerator = [];
    for (i = 0; i < 10; i++) {
      num = Math.floor(Math.random() * 9);
      accountNumberGenerator.push(num);
      accountNumberGen = accountNumberGenerator.join("");
    }

    // validating phoneNumber
    const phoneNumberExist = await User.findOne({ phoneNumber });
    if (phoneNumberExist) {
      return res.status(401).json({
        message: "phoneNumber exists, please login",
      });
    }
    // validating email
    const emailExist = await User.findOne({ email });
    if (emailExist) {
      return res.status(401).json({
        message: "email exists, please login",
      });
    }
    //  hashing password
    const hashPassword = await bcrypt.hash(password, 10);
    // creating a new user
    const newUser = await User.create({
      firstName,
      lastName,
      phoneNumber,
      email,
      password: hashPassword,
      accountNumber: accountNumberGen,
    });
    const payload = {
      id: newUser._id,
      email: newUser.email,
      role: newUser.role,
    };
    const token = await jwt.sign(payload, process.env.SECRET_TOKEN, {
      expiresIn: "1h",
    });
    return successResMsg(res, 201, { message: "User created", newUser, token });
  } catch (error) {
    return errorResMsg(res, 500, { message: error.message });
  }
};

// logging in a user
const loginUser = async (req, res, next) => {
  try {
    const { phoneNumber, password } = req.body;
    const loginUser = await UserLogin.validateAsync(req.body);
    const phoneNumberExist = await User.findOne({ phoneNumber });
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
    if (phoneNumberExist.blocked == true) {
      return res.status(403).json({
        message:
          "Your account has been suspended, please contact customer care",
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
      message: "User login successfully",
      token,
    });
  } catch (error) {
    return res.status(500).json({
      message: error.message,
    });
  }
};
//   retrieving accountNumber
const retrieveUser = async (req, res, next) => {
  try {
    const { phoneNumber } = req.query;
    const getUser = await User.findOne({ phoneNumber }).select("accountNumber");
    return res.status(200).json({
      getUser,
    });
  } catch (error) {
    return res.status(500).json({
      message: error.message,
    });
  }
};
//   exporting modules
module.exports = { createUser, loginUser, retrieveUser };
