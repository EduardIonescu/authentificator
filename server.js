const express = require('express')
const path = require('path')
const mongoose = require('mongoose')
const User = require('./model/user')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

require('dotenv/config')

mongoose.connect(process.env.DB_CONNECTION, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true
})

const app = express()
app.use('/', express.static(path.join(__dirname, 'static')))
app.use(express.urlencoded({ extended: true }))
app.use(express.json())

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body
    const user = await User.findOne({ username }).lean()

    if (!user) {
        return res.json({ status: 'error', error: 'Invalid username/password!' })
    }

    if (await bcrypt.compare(password, user.password)) {
        //the username and password combination is successful

        const token = jwt.sign(
            {
                id: user._id,
                username: user.username
            },
            process.env.JWT_SECRET
        )

        return res.json({ status: 'ok', data: token })
    }

    res.json({ status: 'error', error: 'Invalid username/password' })
})

app.post('/api/register', async (req, res) => {
    const { username, password: plainTextPassword } = req.body

    if (!username || typeof username !== 'string') {
        return res.json({ status: 'error', error: 'Invalid username!' })
    } else if (username.length < 5) {
        return res.json({
            status: 'error', error: 'Username too short! ' +
                'It should be at least 5 characters.'
        })
    }

    if (!plainTextPassword || typeof plainTextPassword !== 'string') {
        return res.json({ status: 'error', error: 'Invalid password!' })
    } else if (plainTextPassword.length < 6) {
        return res.json({
            status: 'error', error: 'Password too short! ' +
                'It should be at least 6 characters.'
        })
    }

    const password = await bcrypt.hash(plainTextPassword, 10)

    try {
        const response = await User.create({
            username,
            password
        })
        console.log('User created successfully: ', response)
    } catch (error) {
        if (error.code === 11000) {
            //duplicate key
            return res.json({ status: 'error', error: 'Username already in use.' })
        }
        throw error
    }
    res.json({ status: 'ok' })
})

app.listen(3000, () => {
    console.log('Server up at 3000')
})