const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const User = require("./models/user.model");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const app = express();

app.use(cors());
app.use(express.json());

const accessTokenSecret = "accessSecret123";
const refreshTokenSecret = "refreshSecret123";
const aExpiresIn = "6m";
const rExpiresIn = "7d";

mongoose
  .connect("mongodb://127.0.0.1:27017/login", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to database"))
  .catch(console.error);


app.post("/api/register", async (req, res) => {
  try {
    const newPassword = await bcrypt.hash(req.body.password, 10);
    await User.create({
      name: req.body.name,
      email: req.body.email,
      password: newPassword,
    });
    res.send({ status: "ok" });
  } catch (err) {
    console.log(err);
    res.send({ status: "error", error: "email already exists"});
  }
});

app.post("/api/login", async (req, res) => {

  const user = await User.findOne({ email: req.body.email });

  if (!user) {
    return res.json({ status: "error", error: "Invalid login credentials" });
  }

  const isPasswordValid = await bcrypt.compare(
    req.body.password,
    user.password
  );
  if (isPasswordValid) {
    const accessToken = jwt.sign({ email: user.email }, accessTokenSecret, {
      expiresIn: aExpiresIn,
    });
    const refreshToken = jwt.sign({ email: user.email }, refreshTokenSecret, {
      expiresIn: rExpiresIn,
    });

    return res.json({
      status: "ok",
      atoken: accessToken,
      rtoken: refreshToken,
    });
  } else {
    return res.json({ status: "error", user: false });
  }
});

app.get("/api/quote", async (req, res) => {
  const token = req.headers["x-access-token"];
  try {
    const decoded = jwt.verify(token, "accessSecret123");
    const email = decoded.email;
    const user = await User.findOne({ email: email });

    return res.json({ status: "ok", quote: user.quote });
  } catch (error) {
    console.log(error);
    res.json({ status: "error", error: "invalid token" });
  }
});

app.post("/api/quote", async (req, res) => {
  const token = req.headers["x-access-token"];
  try {
    const decoded = jwt.verify(token, "accessSecret123");
    const email = decoded.email;
    await User.updateOne({ email: email }, { $set: { quote: req.body.quote } });
    return res.json({ status: "ok" });
  } catch (error) {
    res.json({ status: "error", error: "invalid token" });
  }
});



app.post("/api/refresh-token", (req, res) => {
  const refreshToken = req.body.refreshToken;

  if (!refreshToken) {
    return res.json({ status: "error", error: "No refresh token" });
  }

  try {
    const decoded =  jwt.verify(refreshToken, refreshTokenSecret);
    const userEmail = decoded.email;
    const accessToken = jwt.sign({ email: userEmail }, accessTokenSecret, {
      expiresIn: aExpiresIn,
    });

    return res.json({ status: "ok", atoken: accessToken });
  } catch (err) {
    return res.json({ status: "error", error: "Invalid refresh token" });
  }
});


app.post("/api/update-password", async (req, res) => {

  const user = await User.findOne({ email:req.body.email });
  if (!user) {
    return res.json({ status: "error", error: "User not found" });
  }

  const isPasswordValid = await bcrypt.compare(req.body.password, user.password);

  if (!isPasswordValid) {
    return res.json({ status: "error", error: "Invalid current password" });
  }

  const newPasswordHash = await bcrypt.hash(req.body.newPassword, 10);
  user.password = newPasswordHash;
  await user.save();

  return res.json({ status: "ok", message: "Password updated successfully" });
});

app.post("/api/forgot-password", async (req, res) => {
  try {
    const user = await User.findOne({ email:req.body.email });

    if (!user) {
      return res.json({ status: "error", error: "User not found" });
    }

    const resetToken = jwt.sign({ email: user.email }, accessTokenSecret, {
      expiresIn: "15m",
    });

    return res.json({ status: "ok", resetToken });
  } catch (error) {
    console.log(error);
    res.json({ status: "error", error: "Failed to set password" });
  }
});

app.post("/api/reset-password", async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;

    if (!resetToken || !newPassword) {
      return res.json({ status: "error", error: "Invalid request" });
    }

    const decoded = jwt.verify(resetToken, accessTokenSecret);
    const email = decoded.email;

    const user = await User.findOne({ email });

    if (!user) {
      return res.json({ status: "error", error: "User not found" });
    }

    const newPasswordHash = await bcrypt.hash(newPassword, 10);
    user.password = newPasswordHash;
    await user.save();

    return res.json({ status: "ok", message: "Password reset successful" });
  } catch (error) {
    if (error.name === "JsonWebTokenError") {
      return res.json({ status: "error", error: "Invalid reset token" });
    }
    console.log(error);
    res.json({ status: "error", error: "Failed to reset password" });
  }
});

app.listen(3009, () => {
  console.log("Server running on 3009 port");
});
