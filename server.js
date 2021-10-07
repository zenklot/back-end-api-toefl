const express = require('express');
const mongoose = require('mongoose');
require('dotenv').config();
const auth = require('./routes/auth');

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
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/api', auth);

app.listen(port, () => {
  console.log(`Server Is Running on Port : ${port}`);
});
