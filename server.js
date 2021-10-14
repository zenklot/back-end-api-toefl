const express = require('express');
const mongoose = require('mongoose');
require('dotenv').config();
const cors = require('cors');
const cookieParser = require('cookie-parser');
const auth = require('./routes/auth');
const user = require('./routes/user');

const port = process.env.PORT || 5000;
mongoose.connect(process.env.MONGO_URI);
const db = mongoose.connection;
db.on('error', (err) => {
  console.log(err);
});

db.once('open', () => {
  console.log('Database Connection Established!');
});

const app = express();
app.use(cookieParser());
app.use(cors({
  credentials: true,
  origin: ['http://localhost:3000', 'http://localhost:8080', 'http://localhost:4200'],
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/auth', auth);
app.use('/user', user);

app.listen(port, () => {
  console.log(`Server Is Running on Port : ${port}`);
});
