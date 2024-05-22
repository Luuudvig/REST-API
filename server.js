const express = require("express");
const app = express();
const mysql = require("mysql2/promise");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const secretKey = "Loman<3";

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

async function getDBConnection() {
  return await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "restapi",
  });
}

function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, secretKey, {
    expiresIn: 150,
  });
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.get("/", (req, res) => {
  res.send(`
      <h1>Dokumentation av det här APIet</h1>
      <p>Här är en lista över tillgängliga routes:</p>
      <ul>
        <li><strong>GET /users</strong> - kräver inloggning. returnerar alla användare som JSON objekt i en array.</li>
        <li><strong>GET /users/{id}</strong> - kräver inloggning. returnerar en user med angivet id eller status 204 om användaren saknas.</li>
        <li><strong>PUT /users/{id}</strong> - kräver inloggning. uppdaterar en users värden beroende på vilka värden som angivs. Accepterar JSON objekt som har något av värdena username, firstname, lastname, password.</li>
        <li><strong>POST /users</strong> - kräver inloggning. skapar en ny användare. Accepterar JSON objekt på formatet {"username": "uniktnamn", "firstname": "namn", "lastname": "namn", "password": "lösenord"}. Username är obligatoriskt och ska vara unikt.</li>
        <li><strong>POST /login</strong> - för inloggning. Returnerar en JWT som används som bearer token i anrop till routes skyddade med auth. Accepterar JSON objekt på formatet {"username": "", "password": ""}.</li>
      </ul>
    `);
});

app.get("/users", authenticateToken, async (req, res) => {
  const conn = await getDBConnection();
  let sql = "SELECT id, username, firstname, lastname FROM users";
  const [rows] = await conn.execute(sql);
  conn.end();
  res.json(rows);
});

app.get("/users/:id", authenticateToken, async (req, res) => {
  const conn = await getDBConnection();
  let sql = "SELECT id, username, firstname, lastname FROM users WHERE id = ?";
  const [rows] = await conn.execute(sql, [req.params.id]);
  conn.end();
  if (rows.length > 0) {
    res.json(rows[0]);
  } else {
    res.status(404).send("Hittade inte user");
  }
});

app.put("/users/:id", authenticateToken, async (req, res) => {
  const { firstname, lastname, username, password } = req.body;
  const conn = await getDBConnection();
  const updates = [];
  const values = [];

  if (firstname) {
    updates.push("firstname = ?");
    values.push(firstname);
  }
  if (lastname) {
    updates.push("lastname = ?");
    values.push(lastname);
  }
  if (username) {
    updates.push("username = ?");
    values.push(username);
  }
  if (password) {
    try {
      const hashedPassword = await bcrypt.hash(password, 7);
      updates.push("password = ?");
      values.push(hashedPassword);
    } catch (error) {
      res.status(500).send("Misslyckades med hasning");
      return;
    }
  }

  if (updates.length === 0) {
    res.status(400).send("Ingen indata");
    return;
  }

  let sql = `UPDATE users SET ${updates.join(", ")} WHERE id = ?`;
  values.push(req.params.id);

  try {
    await conn.execute(sql, values);

    const [rows] = await conn.execute(
      "SELECT id, username, firstname, lastname FROM users WHERE id = ?",
      [req.params.id]
    );
    if (rows.length > 0) {
      res.status(200).json(rows[0]);
    } else {
      res.status(404).send("User inte hittad efter update");
    }
  } catch (error) {
    res.status(500).send("Gick inte att uppdatera user");
  } finally {
    conn.end();
  }
});

app.post("/users", authenticateToken, async (req, res) => {
  const { username, password, firstname, lastname } = req.body;
  const hashedPassword = await bcrypt.hash(password, 7);

  const conn = await getDBConnection();
  let sql =
    "INSERT INTO users (username, password, firstname, lastname) VALUES (?, ?, ?, ?)";
  try {
    const [result] = await conn.execute(sql, [
      username,
      hashedPassword,
      firstname,
      lastname,
    ]);
    res.status(201).send(`User skapad med ID: ${result.insertId}`);
  } catch (error) {
    res.status(500).send("Error, gick inte att skapa user");
  } finally {
    conn.end();
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const conn = await getDBConnection();
  let sql = "SELECT * FROM users WHERE username = ?";
  const [users] = await conn.execute(sql, [username]);

  if (users.length == 0) {
    res.status(401).send("Fel inloggningsuppgifter");
    conn.end();
    return;
  }

  const user = users[0];
  const passwordMatch = await bcrypt.compare(password, user.password);

  if (passwordMatch) {
    const token = generateToken(user);
    res.json({ jwt: token });
  } else {
    res.status(401).send("Fel inloggningsuppgifter");
  }

  conn.end();
});

const port = 3000;
app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});
