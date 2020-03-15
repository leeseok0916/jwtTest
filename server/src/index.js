require('dotenv').config();

const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const { verify } = require("jsonwebtoken");
const { hash, compare } = require("bcryptjs");
const {
  createAccessToken,
  createRefreshToken,
  sendRefreshToken,
  sendAccessToken
} = require("./tokens");
const { fakeDB } = require("./fakeDb");
const { isAuth } = require("./isAuth");

const PORT = 4000;

/*
1. user 등록
2. user 로그인
3. user 로그아웃
4. 보호된 route 설정
5. refresh token으로 새 access token 얻기
*/

const server = express();

// 간편한 cookie를 쉽게 처리하기 위해 express 미들웨어 사용
server.use(cookieParser());

// 크로스 도메인 해결하가 위해 설정
server.use(cors({
  origin: 'http://localhost:3000', // 허락하고자 하는 요청 주소
  credentials: true, // true로 하면 설정한 내용을 response 헤더에 추가함
}));

// request body data를 읽어야 함
// express v4.16.0 기준으로 body-parser가 포함됨
server.use(express.json());
server.use(express.urlencoded({ extended: true })); // url의 query string을 object로 만들어준다

server.get('/ping', (req, res) => {
  res.send('pong');
});

// 1. 유저  등록
server.post('/register', async (req, res) => {
  const {
    email,
    password,
  } = req.body;

  try {
    // 1. user가 존재하는지 확인
    const user = fakeDB.find((user) => {
      return user.email === email;
    });
    
    if (user) {
      throw new Error('User already exist');
    }

    // 2. user가 존재하지 않으면 비밀번호 hash로 변환
    const hashPassword = await hash(password, 10);

    // 3. user 생성
    fakeDB.push({
      id: fakeDB.length,
      email,
      password: hashPassword,
    });

    res.send({ message: 'User Created' });
    console.log(fakeDB);
    
  } catch (error) {
    res.send({
      error: `${error.message}`,
    });
  }
});

// 2. login
server.post('/login', async (req, res) => {
  const {
    email,
    password,
  } = req.body;

  try {
    // 1. find user
    const user = fakeDB.find(user => user.email === email);
    if (!user) throw new Error('User does not exist');

    // 2. compare crypted password and see if it check out. send error if not
    const valid = await compare(password, user.password);
    if (!valid) throw new Error('Password npt correct');

    // 3. create refreshtoken and accesstoken
    const accesstoken = createAccessToken(user.id);
    const refreshtoken = createRefreshToken(user.id);

    // 4. db user 정보에 refreshtoken 저장
    // 다른 버전의 번호를 대신 사용할 수 있다
    // 그러면 revoke endpoint에서 버전 번호를 증가해야 한다
    user.refreshtoken = refreshtoken;

    // 5. send token.
    // refreshtoken은 cookie로
    // accesstoken은 정규 response로 
    sendRefreshToken(res, refreshtoken);
    sendAccessToken(res, email, accesstoken);
  } catch (error) {
    console.log(error);
    
    res.send({
      error: `${error.message}`,
    });
  }
});

// 3. logout
server.post('/logout', (_req, res) => {
  res.clearCookie('refreshtoken', {
    path: '/refresh_token'
  });

  return res.send({
    message: 'Logged out',
  });
});

// 4. protected route
server.post('/protected', async (req, res) => {
  try {
    const userId = isAuth(req);

    if (userId !== null) {
      res.send({
        data: 'This is proteched data.',
      });
    }
  } catch (error) {
    res.send({
      error: `${error.message}`,
    });
  }
});

// 5. refresh token으로 새 access token 구하기
server.post('/refresh_token', async (req, res) => {
  const token = req.cookies.refreshtoken;

  // token이 없으면
  if (!token) {
    return res.send({
      accesstoken: '',
    })
  }

  // token이 있으면 검증
  let payload = null;
  try {
    payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
  } catch (error) {
    return res.send({ 
      accesstoken: '', 
    });
  }

  // token이 유효, token의 user가 존재하는지 확인
  const user = fakeDB.find(user => user.id === payload.userId);
  if (!user) {
    return res.send({ 
      accesstoken: '', 
    });
  }

  // refreshtoken이 있는지 확인
  if (user.refreshtoken !== token) {
    return res.send({ 
      accesstoken: '', 
    });
  }

  // create new refreshtoken, accesstoken
  const accesstoken = createAccessToken(user.id);
  const refreshtoken = createRefreshToken(user.id);

  // update refreshtoken
  // 다른 버전을 가질 수 있음
  user.refreshtoken  = refreshtoken;

  // send new refreshtoken, accesstoken
  sendRefreshToken(res, refreshtoken);
  return res.send({accesstoken});
});

server.listen(PORT, () => {
  console.log(`server listening on port ${PORT}`);
});