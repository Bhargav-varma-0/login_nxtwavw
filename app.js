const express = require("express");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const path = require("path");
const bcrypt = require("bcrypt");

const app = express();

app.use(express.json());

const dbPath = path.join(__dirname, "userData.db");

let db = null;

const initializeBdAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    const createTableIfNotExist = `CREATE TABLE IF NOT EXISTS user(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        name TEXT NOT NULL,
        password TEXT NOT NULL,
        gender TEXT NOT NULL,
        location TEXT NOT NULL
        )`;
    await db.run(createTableIfNotExist);
    app.listen(3000, () => console.log("server started at 3000"));
  } catch (err) {
    console.log("inti Error : " + err);
  }
};
initializeBdAndServer();

app.post("/register", async (req, res) => {
  try {
    const { username, name, password, gender, location } = req.body;
    const userExistsQuery = `SELECT * FROM user WHERE username = ?`;
    const userExist = await db.get(userExistsQuery, username);
    console.log(`userExist : ${userExist}`);
    if (userExist === undefined && password.length < 5) {
      res.status(400).send("Password is too short");
    } else if (userExist === undefined) {
      const encryptedPassword = await bcrypt.hash(password, 10);
      const createUserQuery = `INSERT INTO user (username, name, password, gender, location)
      VALUES(?,?,?,?,?)`;
      const values = [username, name, encryptedPassword, gender, location];
      const creatingUser = await db.run(createUserQuery, values);
      res.send("User created successfully");
    } else {
      res.status(400).send("User already exists");
    }
  } catch (err) {
    console.log(`user authentication error : ${err}`);
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const userExistsQuery = `SELECT username,password FROM user WHERE username = ?`;
    const userExist = await db.get(userExistsQuery, username);
    if (userExist === undefined) {
      res.status(400).send("Invalid user");
    } else {
      const isPasswordCorrect = await bcrypt.compare(
        password,
        userExist.password
      );
      console.log(isPasswordCorrect);
      if (isPasswordCorrect) {
        res.send("Login success!");
      } else {
        res.status(400).send("Invalid password");
      }
    }
  } catch (err) {
    console.log(`user authentication error : ${err}`);
  }
});

app.post("/change-password", async (req, res) => {
  try {
    const { username, oldPassword, newPassword } = req.body;
    const userExistsQuery = `SELECT username,password FROM user WHERE username = ?`;
    const userExist = await db.get(userExistsQuery, username);
    // if (userExist === undefined) {
    //   res.status(400).send("Invalid user");
    // } else {
    console.log(`${oldPassword}, ${userExist.password}`);
    const isPasswordCorrect = await bcrypt.compare(
      oldPassword,
      userExist.password
    );
    console.log(isPasswordCorrect);
    if (isPasswordCorrect && newPassword.length < 5) {
      res.status(400).send("Password is too short");
    } else if (isPasswordCorrect) {
      const newEncryptedPassword = await bcrypt.hash(newPassword, 10);
      const updatePasswordQuery = `UPDATE user SET password = ? WHERE username = ?;`;
      await db.run(updatePasswordQuery, [newEncryptedPassword, username]);
      res.send("Password updated");
    } else {
      res.status(400).send("Invalid current password");
    }
    // }
  } catch (err) {
    console.log(`user authentication error : ${err}`);
  }
});

module.exports = app;
