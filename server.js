const express = require('express')
const app = express()

const dotenv = require("dotenv");
dotenv.config();

const cors = require('cors')

const mongodb = require('mongodb')
const mongoClient = mongodb.MongoClient
const DB_URL = process.env.MONGODB_HOST;

const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require('nodemailer');

const PORT = process.env.PORT || 5000;


app.use(express.json()); //middleware
app.use(cors({
    origin: "*"
}))

// For Private Routing
function authenticate(req, res, next) {
    try {
        if (req.headers.authorization) {
            jwt.verify(req.headers.authorization, process.env.JWT_SECRET, (error, decoded) => {
                if (error) {
                    res.status(401).json({
                        message: "Unauthorized"
                    })
                } else {
                    req.userid = decoded.id
                    next()
                }
            })
        } else {
            res.status(401).json({
                message: "No Token Present"
            })
        }
    } catch (error) {
        res.status(500).json({
            message: "Something went wrong"
        })
    }
}

app.post("/register", async (req, res) => {
    try {
        let client = await mongoClient.connect(DB_URL)
        let db = client.db("blogapp")
        let duplicate_email = await db.collection("users").findOne({ "email": `${req.body.email}` })
        if (duplicate_email) {
            await client.close()
            res.status(204).json({
                message: "Duplicate Entry"
            })
        } else {
            // Hashing the password
            let salt = bcryptjs.genSaltSync(10);
            let hash = bcryptjs.hashSync(req.body.password, salt);
            req.body.password = hash;
            let data = await db.collection("users").insertOne(req.body)
            await client.close()
            res.json({
                message: "User Created",
                id: data._id
            })
        }
    } catch (error) {
        res.status(500).json({
            message: "something went wrong"
        })
    }
})

app.post('/login', async (req, res) => {
    try {
        let client = await mongoClient.connect(DB_URL)
        let db = client.db("blogapp")
        let user = await db.collection("users").findOne({ email: req.body.email })
        if (user) {
            let matchpassword = bcryptjs.compareSync(req.body.password, user.password)
            if (matchpassword) {
                let token = jwt.sign({ id: user._id }, process.env.JWT_SECRET)
                res.json({
                    message: "Logged in!",
                    token
                })
            } else {
                res.status(400).json({
                    message: "Username/Password incorrect"
                })
            }
        } else {
            res.status(400).json({
                message: "Username/Password incorrect"
            })
        }
    } catch (error) {
        res.status(500).json({
            message: 'Something went wrong'
        })
    }
})

app.post("/post-blog", [authenticate], async (req, res) => {
    try {
        let client = await mongoClient.connect(DB_URL)
        let db = client.db("blogapp")
        req.body.userid = req.userid
        await db.collection("content").insertOne(req.body)
        await client.close()
        res.json({
            message: "Blog content posted Successfully"
        })
    } catch (error) {
        res.status(500).json({
            message: "something went wrong"
        })
    }
})

app.get("/blogs", async (req, res) => {
    try {
        let client = await mongoClient.connect(DB_URL)
        let db = client.db("blogapp")
        let data = await db.collection("content").find().toArray()
        await client.close()
        res.json(data)
    } catch (error) {
        res.status(500).json({
            message: "something went wrong"
        })
    }
})

app.get("/view-blog", async (req, res) => {
    try {
        let client = await mongoClient.connect(DB_URL)
        let db = client.db("blogapp")
        let data = await db.collection("content").find({ _id: mongodb.ObjectId(req.query.q) }).toArray()
        await client.close()
        res.json(data)
    } catch (error) {
        res.status(500).json({
            message: "something went wrong"
        })
    }
})

app.get("/userName", async (req, res) => {
    try {
        let client = await mongoClient.connect(DB_URL)
        let db = client.db("blogapp")
        let data = await db.collection("users").find({ _id: mongodb.ObjectId(req.query.q) }).toArray()
        await client.close()
        res.json(data)
    } catch (error) {
        res.status(500).json({
            message: "something went wrong"
        })
    }
})

app.get("/myblogs", [authenticate], async (req, res) => {
    try {
        let client = await mongoClient.connect(DB_URL)
        let db = client.db("blogapp")
        let data = await db.collection("content").find({ userid: req.userid }).toArray()
        await client.close()
        res.json(data)
    } catch (error) {
        res.status(500).json({
            message: "something went wrong"
        })
    }
})

app.put("/edit-post/:id", [authenticate], async (req, res) => {
    try {
        let client = await mongoClient.connect(DB_URL)
        let db = client.db("blogapp")
        await db.collection("content").updateMany({ _id: { $eq: mongodb.ObjectId(req.params.id) } }, { $set: { "title": `${req.body.title}`, "content": `${req.body.content}` } })
        await client.close()
        res.json({
            message: "Edited Successfully"
        })
    } catch (error) {
        res.status(500).json({
            message: "Something went wrong"
        })
    }
})

const contactEmail = nodemailer.createTransport({
    host: process.env.MAIL_HOST,
    port: process.env.MAIL_PORT,
    auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS
    }
})

contactEmail.verify((error) => {
    if (error) {
        console.log(error);
    } else {
        console.log("Ready to Send");
    }
});

app.post("/forgot-password-email", async (req, res) => {
    let resetPin = (Math.floor(100000 + Math.random() * 900000))
    try {
        let client = await mongoClient.connect(DB_URL)
        let db = client.db("blogapp")
        let data = await db.collection("users").findOneAndUpdate({ email: req.query.q }, { $set: { PIN: resetPin } })
        if (data.value) {
            const message = resetPin;
            const mail = {
                from: `Blog Application <${process.env.MAIL_USER}>`,
                to: req.query.q,
                subject: "Blog Application Password Reset OTP",
                html:
                    `<h2>Hi User, This is your reset pin ${message}</h2>`
            };
            contactEmail.sendMail(mail, (error) => {
                if (error) {
                    res.json({ status: "ERROR" });
                } else {
                    res.json({ status: "Message Sent" });
                }
            });
            await client.close()
        } else {
            res.status(404).json({
                message: "No user Found!"
            })
        }
    } catch (error) {
        res.status(500).json({
            message: "No user ID found"
        })
    }
});

app.post("/verify-otp", async (req, res) => {
    try {
        const client = await mongoClient.connect(DB_URL)
        const db = client.db("blogapp")
        const data = await db.collection("users").findOne({ email: req.body.email })
        if (data) {
            if (data.PIN == req.body.PIN) {
                await db.collection("users").findOneAndUpdate({ email: data.email }, { $set: { PIN: "" } })
                await client.close()
                res.json({
                    message: "Success"
                })
            } else {
                res.status(402).json({
                    message: "Invalid OTP"
                })
            }
        } else {
            res.status(500).json({
                message: "Internal Server Error... Pls try again"
            })
        }
    } catch (error) {
        res.status(500).json({
            message: "Internal Server Error... Pls try again"
        })
    }
})

app.post("/newPassword", async (req, res) => {
    try {
        let client = await mongoClient.connect(DB_URL)
        let db = client.db("blogapp")
        let data = await db.collection("users").findOne({ "email": `${req.body.email}` })
        if (data) {
            let salt = bcryptjs.genSaltSync(10);
            let hash = bcryptjs.hashSync(req.body.password, salt);
            req.body.password = hash;
            await db.collection("users").findOneAndUpdate({ email: data.email }, { $set: { password: req.body.password } })
            await client.close()
            res.json({
                message: "Password updated",
            })
        } else {
            await client.close()
            res.status(500).json({
                message: "Something went wrong"
            })
        }
    } catch (error) {
        res.status(500).json({
            message: "something went wrong"
        })
    }
})

app.delete("/delete-blog", [authenticate], async (req, res) => {
    try {
        let client = await mongoClient.connect(DB_URL)
        let db = client.db("blogapp")
        await db.collection("content").deleteOne({ _id: { $eq: mongodb.ObjectId(req.query.q) } })
        await client.close()
        res.json({
            message: "Deleted Successfully"
        })
    } catch (error) {
        res.status(500).json({
            message: "Something went wrong"
        })
    }
})

app.listen(PORT, () => console.log(`Server started running in ${PORT}`))