const jwt = require("jsonwebtoken");
const express = require("express");
const cors = require("cors");
const app = express();
const port = 3000;

const SECRET_KEY = "your random string secret key";
const REFRESH_SECRET_KEY = "your random string secret key";
let tokenList = []; // For storing your secret token

// For validate token
function verifyToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token)
    return res.status(403).send({ auth: false, message: "No token provided." });

  // verify if jwt valid with secret key
  jwt.verify(token, SECRET_KEY, function (err, decoded) {
    if (err) {
      return res
        .status(500)
        .send({ auth: false, message: "Failed to authenticate token." });
    } else {
      next();
    }
  });
}

// function for create access token and refresh token
function createToken(payload) {
  //   access token will expired in 1 hour
  const accessToken = jwt.sign(payload, SECRET_KEY, { expiresIn: "30s" });

  //   refresh token will expired in 1 month
  const refreshToken = jwt.sign(payload, REFRESH_SECRET_KEY, {
    expiresIn: "30d",
  });

  return { accessToken, refreshToken };
}

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// CREATE NEW TOKEN
app.post("/create-token", (req, res) => {
  // create token and send data from body
  const token = createToken(req.body);

  //   push refresh token to array
  tokenList.push(token.refreshToken);

  res.json({
    auth: true,
    accessToken: token.accessToken,
    refreshToken: token.refreshToken,
  });
});

// REFRESH TOKEN
app.post("/refresh-token", verifyToken, (req, res) => {
  const authorization = req.headers["authorization"];
  const checkToken = tokenList.filter((res) => res === authorization)?.length;

  if (checkToken) {
    var decoded = jwt.verify(authorization, REFRESH_SECRET_KEY);

    // create token and send data from decode
    const token = createToken({ email: decoded.email });
    const currentToken = tokenList.filter((res) => res !== authorization);

    // remove old token
    tokenList = currentToken;
    // push refresh token to array
    tokenList.push(token.refreshToken);

    res.json({
      auth: true,
      accessToken: token.accessToken,
      refreshToken: token.refreshToken,
    });
  } else {
    res.status(500).send({
      auth: false,
      message: "Failed, no refresh token token in list.",
    });
  }
});

// PRIVATE ROUTE
app.get("/get-data", verifyToken, (req, res) => {
  res.status(200).send({
    auth: true,
    message: "Success Get data",
  });
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
