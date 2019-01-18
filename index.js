const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session');

const db = require('./database/dbHelpers.js');

const server = express();

function protect(req, res, next) {
  if (req.session && req.session.userId) {
    next();
  } else {
    res.status(400).send('access denied');
  }
}

server.use(express.json());
server.use(cors());
server.use(session({
    name: 'notsession', // default is connect.sid
    secret: 'nobody tosses a dwarf!',
    cookie: {
      maxAge: 1 * 24 * 60 * 60 * 1000
    }, // 1 day in milliseconds
    httpOnly: true, // don't let JS code access cookies. Browser extensions run JS code on your browser!
    resave: false,
    saveUninitialized: false,
}));

server.get('/', (req, res) => {
  res.send('Its Alive!');
});

server.post('/api/register', (req, res) => {
  const user = req.body;
  user.password = bcrypt.hashSync(user.password, 14);
  db.insertUser(user)
  .then(ids => {
    res.status(201).json({id: ids[0]});
  })
  .catch(err => {
    res.status(500).send(err);
  });
});

server.post('/api/login', (req, res) => {
  const user = req.body;
  db.findByUsername(user.username)
  .then(users => {
    if (users.length && bcrypt.compareSync(user.password, users[0].password)) {
      req.session.userId = users[0].id;
      res.json({info: "correct"});
    } else {
      res.status(404).json({err: "Invalid username or password"}) ;
    }
  })
  .catch(err => {
    res.status(500).send(err);
  });
});

server.get('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      res.status(500).send({err: 'Failed to logout'});
    } else {
      res.send({info: 'Logout successful'});
    }
  });
});

// protect this route, only authenticated users should see it
server.get('/api/users', protect, (req, res) => {
    db.getUsers()
      .then(users => {
        res.json(users);
      })
      .catch(err => res.send(err));
});

server.listen(3300, () => console.log('\nrunning on port 3300\n'));
