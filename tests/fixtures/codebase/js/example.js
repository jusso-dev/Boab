const crypto = require('crypto');
const forge = require('node-forge');
const jwt = require('jsonwebtoken');

// JWT alg patterns appear in literal strings.
const token = {"alg":"RS256"};
const e = {"alg":"ES256"};
const h = {"alg":"HS256"};

// Banned 3DES legacy.
const banned = "3DES";
