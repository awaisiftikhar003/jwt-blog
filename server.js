/* Importing required packages */
const express = require('express')
const jwt = require('jsonwebtoken')
var bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
/* Creating Express server */
const app = express()

/* 
Since this blog is solely written to demonstrate 
the working of JSON web tokens so, I haven't 
used any DB for this blog intentionally. 
*/
const user = {
    "id": 1,
    "username": "abc",
    "password": "abc",
    "role": "user",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFiYyIsImlkIjoxLCJyb2xlIjoidXNlciIsImlhdCI6MTYxNzAyMzAwOX0.4NsYHIOmMtY4FWWQ4brGwK4PfbOcWQ9NAtrL9X9ttT0"
}
/* 
    to parse JSON and urlencoded data 
    Content-Type of req header shoould be application/x-www-form-urlencoded
*/
app.use(express.json());
app.use(bodyParser.urlencoded({
    extended: true
}));

/* An open Api accessable by all users */
app.get('/', (req, res) => {
    res.status(200).json({ "code": 200, "success": true, "resp": "Helo world." })
});

/* A JWT enabled Api only accessable by authenticated users */
app.get('/authUser', authenticateToken, (req, res) => {
    res.status(200).json({ "code": 200, "success": true, "resp": "sensitive data for authorized user only." })
});

/* login api */
app.post('/login', async (req, res) => {
    let result
    try {
        if (req.body.username.trim().length > 0 && req.body.password.trim().length > 0) {
            if (req.body.username == user.username && req.body.password == user.password) {
                const tokens = generateAccessToken({ email: user.username, id: user.id, role: user.role })
                res.json({ "code": 200, "success": true, accessToken: tokens })
            }
            else {
                res.status(401).json({ "code": 401, "success": false, "resp": "Invalid Credentials." })
            }
        } else {
            throw "Username or password cannot be empty."
        }
    } catch (err) {
        console.log(err)
        res.status(500).json({ "code": 500, "success": false, "resp": err.message ? err.message : err })
    }
})

/* regenerate  tokens */

app.post("/refreshToken", async (req, res) => {
    try {
        const refreshToken = req.body.refreshToken
        /* you must validate incoming refresh token too */
        const valide_user = await jwt.verify(refreshToken, "JWT_REFRESH_SECRET")
        if (valide_user && refreshToken == user.refreshToken) {
            const accessToken = jwt.sign({ email: valide_user.username, id: valide_user.id, role: valide_user.role }, "ACCESS_TOKEN_SECRET", { expiresIn: '30s' })
            res.json({ "code": 200, "success": true, accessToken: accessToken })
        }
        else {
            res.sendStatus(403);
        }
    }
    catch (err) {
        console.log(err)
        res.status(500).json({ "code": 500, "success": false, "resp": err.message ? err.message : err })
    }
})

/*  */
function generateAccessToken(generateAccessToken) {
    // you must save your ACCESS_TOKEN_SECRET key in your .env or any other config file 
    // and it should not be publicly accessible.
    // Following token will automatically expire after 30 seconds
    const accessToken = jwt.sign(generateAccessToken, "ACCESS_TOKEN_SECRET", { expiresIn: '30s' })
    const refreshtoken = jwt.sign(generateAccessToken, "JWT_REFRESH_SECRET")
    return { "accessToken": accessToken, "refreshtoken": refreshtoken }
}

/*  */
async function authenticateToken(req, res, next) {
    try {
        /* first, check for token in authorization request header */
        const authHeader = req.headers['authorization']
        const token = authHeader && authHeader.split(' ')[1]
        if (token == null) return res.sendStatus(401)

        const user = await jwt.verify(token, "ACCESS_TOKEN_SECRET")
        if (!user) return res.sendStatus(403)
        res.status(200).json({ "code": 200, "success": true, "resp": user })
    } catch (err) {
        res.status(500).json({ "code": 500, "success": false, "resp": err.message ? err.message : err })
    }
}


app.listen(5000, () => console.log('Server Started'))