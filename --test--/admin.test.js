const { app } = require("../src/app");
const supertest = require("supertest");
const request = supertest(app);
const Admin = require("../src/models/admin.model");
const mongoose = require("mongoose");
const { beforeEach, afterEach } = require("@jest/globals");
const databaseName = "Admin_test";

beforeAll(async () => {
  const url = `mongodb://127.0.0.1/${databaseName}`;
  await mongoose.connect(url, { useNewUrlParser: true });
});
beforeEach(async () => {
  await Admin.create(Admin);
});
describe("Admin /api/v1", () => {
  it("should save admin in the database", async () => {
    const res = await request.post("/registerAdmin").send({
      firstName: "Chioma",
      lastName: "Ugochi",
      phoneNumber: "0998087765",
      email: "dada@gmail.com",
      password: "fdsahuiuh",
    });
    const admin = await Admin.findOne({ email: "dada@gmail.com" });
    expect(res.status).toBe(201);
    expect(admin.firstName).toBeTruthy();
    expect(admin.lastName).toBeTruthy();
    expect(admin.phoneNumber).toBeTruthy();
    expect(admin.email).toBeTruthy();
    expect(admin.password).toBeTruthy();
  });

  it("should login an admin", async () => {
    const res = await request.post("/loginAdmin").send({
      email: "dude@gmail.com",
      password: "gf9jdhdkj",
    });
    const admin = await Admin.findOne({ email: "dude@gmail.com" });
    expect(res.status).toBe(200);
  });
});
afterEach(async () => {
  await Admin.deleteMany();
});
