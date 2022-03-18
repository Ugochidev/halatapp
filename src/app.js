const express = require("express");
const Admin = require("./models/admin.model");
const User = require("./models/user.model");
const app = express();
app.use(express.json());
const connectDB = require("./DBconnect/database");
connectDB;
app.use(express.urlencoded({ extended: true }));

app.get("/test", (req, res) => {
  res.json({ message: "testing endpoints" });
});
const PORT = process.env.PORT;
app.listen(PORT, () => {
  console.log(`server listening on ${PORT}`);
});

app.post("/registerAdmin", async (req, res) => {
  const { firstName, lastName, phoneNumber, email, password } = req.body;
  const newAdmin = new Admin({
    firstName,
    lastName,
    phoneNumber,
    email,
    password,
  });
  const admin = await newAdmin.save();

  res.status(201).json(admin);
});
app.post("/registerUser", async (req, res) => {
  const { firstName, lastName, phoneNumber, email, password } = req.body;
  const newUser = new User({
    firstName,
    lastName,
    phoneNumber,
    email,
    password,
  });
  const user = await newUser.save();

  res.status(201).json(user);
});
app.post("/loginUser", async (req, res) => {
  const { email, password } = req.body;
  const login = { email, password };
  res.status(200).json(login);
});
app.post("/loginAdmin", async (req, res) => {
  const { email, password } = req.body;
  res.status(200).json("login successfully");
});
module.exports = { app };
