import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import sequelize from "./config/db.js";
import "dotenv/config";
import User from "./models/User.js";
import bcrypt from "bcrypt";
import authenticateJWT from "./middelware/authenticateJWT.js";
import authorizeRole from "./middelware/authorizeRole.js";

const app = express();
const port = process.env.PORT;
const jwtSecret = process.env.JWT_SECRET;
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.post("/register", async (req, res) => {
  const { username, email, password, role } = req.body;
  try {
    if (!username || !email || !password) {
      return res.status(400).json({ message: "All field are required" });
    }
    const emailExists = await User.findOne({ where: { email: email } });
    if (emailExists) {
      return res.status(403).json({ message: "The email already exists" });
    }
    const heshedPassword = await bcrypt.hash(password, 5);
    await User.create({
      username,
      email,
      password: heshedPassword,
      role,
    });
    res.status(201).json({ message: `User ${username} was created` });
  } catch (error) {
    res.status(500).json({ message: "Something went wrong" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }
    const user = await User.findOne({ where: { email: email } });
    if (!user) {
      return res.status(404).json({ message: "user was not found" });
    }
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: "Incorrect password" });
    }
    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
      jwtSecret,
      { expiresIn: "1h" }
    );
    res.status(200).json({ token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Something went wrong" });
  }
});

app.put("/update-email", authenticateJWT, async (req, res) => {
  const userId = req.user.id;
  const { email } = req.body;
  try {
    const emailExists = await User.findOne({ where: { email: email } });
    if (emailExists) {
      return res.status(403).json({ message: "The email already exists" });
    }
    const [numberOfAffectedRows] = await User.update(
      {
        email: email,
      },
      { where: { id: userId } }
    );

    if (numberOfAffectedRows > 0) {
      const user = await User.findOne({ where: { id: userId } });
      return res.status(200).json({
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role,
      });
    } else {
      return res
        .status(404)
        .json({ message: `user with ID ${userId} not found` });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Something went wrong" });
  }
});

app.delete("/delete-account", authenticateJWT, async (req, res) => {
  const userId = req.user.id;
  try {
    const numberOfDeletedRows = await User.destroy({
      where: { id: userId },
    });
    if (numberOfDeletedRows > 0) {
      return res
        .status(200)
        .json({ message: `user with ID ${userId} was deleted` });
    } else {
      return res
        .status(404)
        .json({ message: `user with ID ${userId} was not found` });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Something went wrong" });
  }
});

app.put(
  "/update-role",
  authenticateJWT,
  authorizeRole("admin"),
  async (req, res) => {
    const { id, role } = req.body;
    try {
      if (!id || !role) {
        return res.status(400).json({ message: "All fields are required" });
      }
      const numberOfAffectedRows = await User.update(
        { role: role },
        { where: { id: id } }
      );
      if (numberOfAffectedRows > 0) {
        return res
          .status(200)
          .json({ message: `User with id ${id} was updated` });
      } else {
        return res
          .status(404)
          .json({ message: `User with Id ${id} was not found` });
      }
    } catch (error) {
      console.log(error);
      res.status(500).json({ message: "something went wrong" });
    }
  }
);

app.listen(port, () => {
  try {
    sequelize.authenticate();
    console.log("Connected database was successfully");
    console.log(`Server running on http://127.0.0.1:${port}`);
  } catch (error) {
    console.log(error);
  }
});
