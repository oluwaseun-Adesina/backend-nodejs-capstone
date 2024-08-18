const express = require('express')
const { validationResult } = require('express-validator')
const bcryptjs = require('bcryptjs')
const jwt = require('jsonwebtoken')
const connectToDatabase = require('../models/db')
const dotenv = require('dotenv')
const pino = require('pino')

dotenv.config()

const router = express.Router()
const logger = pino()
const { JWT_SECRET } = process.env

router.post('/register', async (req, res) => {
  try {
    const db = await connectToDatabase()
    const collection = db.collection('users')
    const existingEmail = await collection.findOne({ email: req.body.email })
    if (existingEmail) {
      logger.error('Email id already exists')
      return res.status(400).json({ error: 'Email id already exists' })
    }

    const salt = await bcryptjs.genSalt(10)
    const hash = await bcryptjs.hash(req.body.password, salt)

    const newUser = await collection.insertOne({
      email: req.body.email,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      password: hash,
      createdAt: new Date()
    })

    const payload = {
      user: {
        id: newUser.insertedId
      }
    }

    const authtoken = jwt.sign(payload, JWT_SECRET)
    logger.info('User registered successfully')
    return res.json({ authtoken, email: req.body.email })
  } catch (e) {
    logger.error(e.message)
    return res.status(500).send('Internal server error')
  }
})

router.post('/login', async (req, res) => {
  try {
    const db = await connectToDatabase()
    const collection = db.collection('users')

    const theUser = await collection.findOne({ email: req.body.email })
    if (!theUser) {
      logger.error('User not found')
      return res.status(404).json({ error: 'User not found' })
    }

    const isMatch = await bcryptjs.compare(req.body.password, theUser.password)
    if (!isMatch) {
      logger.error('Passwords do not match')
      return res.status(404).json({ error: 'Wrong password' })
    }

    const payload = {
      user: {
        id: theUser._id.toString()
      }
    }

    const authtoken = jwt.sign(payload, JWT_SECRET)
    logger.info('User logged in successfully')
    return res.status(200).json({
      authtoken,
      userName: theUser.firstName,
      userEmail: theUser.email
    })
  } catch (e) {
    logger.error(e.message)
    return res.status(500).json({ error: 'Internal server error', details: e.message })
  }
})

router.put('/update', async (req, res) => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    logger.error('Validation errors in update request', errors.array())
    return res.status(400).json({ errors: errors.array() })
  }

  try {
    const email = req.headers.email
    if (!email) {
      logger.error('Email not found in the request headers')
      return res.status(400).json({ error: 'Email not found in the request headers' })
    }

    const db = await connectToDatabase()
    const collection = db.collection('users')

    const existingUser = await collection.findOne({ email })
    if (!existingUser) {
      logger.error('User not found')
      return res.status(404).json({ error: 'User not found' })
    }

    existingUser.updatedAt = new Date()

    const updatedUser = await collection.findOneAndUpdate(
      { email },
      { $set: existingUser },
      { returnDocument: 'after' }
    )

    const payload = {
      user: {
        id: updatedUser.value._id.toString()
      }
    }

    const authtoken = jwt.sign(payload, JWT_SECRET)
    return res.json({ authtoken })
  } catch (e) {
    logger.error(e.message)
    return res.status(500).send('Internal server error')
  }
})

module.exports = router
