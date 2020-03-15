const { sign } = require('jsonwebtoken');

// create tokens
const createAccessToken = userId => {
  console.log('process.env.ACCESS_TOKEN_SECRET', process.env.ACCESS_TOKEN_SECRET);
  
  return sign({ userId }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: '15m',
  });
};

const createRefreshToken = userId => {
  return sign({ userId }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: '1m',
  });
};

// send token
const sendAccessToken = (res, email, accesstoken) => {
  res.send({
    accesstoken,
    email,
  });
};

const sendRefreshToken = (res, token) => {
  res.cookie('refreshtoken', token, {
    httpOnly: true,
    path: '/refresh_token',
  });
};

module.exports = {
  createAccessToken,
  createRefreshToken,
  sendAccessToken,
  sendRefreshToken,
};
