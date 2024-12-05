require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

// MongoDB 연결
mongoose
    .connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB connected'))
    .catch((err) => console.error(err));

// 데이터 스키마 및 모델 정의
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    emailAddress: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

const PostSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    author: { type: String, required: true },
});

const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', PostSchema);

// CORS 미들웨어 설정
app.use(
    cors({
        origin: 'http://localhost:8080',
        methods: ['GET', 'POST', 'PUT', 'DELETE'],
        credentials: true,
        allowedHeaders: ['Content-Type', 'Authorization'],
        exposedHeaders: ['Authorization'], // 클라이언트에서 읽을 수 있는 헤더 지정
    })
);

// 미들웨어
app.use(bodyParser.json());

// JWT 인증 미들웨어
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Access token missing' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid Token' });
        console.log('Authenticated user:', user); // 디버깅용 로그
        req.user = user; // req.user에 토큰에서 파싱한 사용자 정보 저장
        next();
    });
};

// 회원가입
app.post('/register', async (req, res) => {
    const { name, emailAddress, username, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, emailAddress, username, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ message: 'User registered' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// 로그인
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ message: 'User not found' });

        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) return res.status(400).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // 토큰을 헤더에 담아 응답
        res.setHeader('Authorization', `Bearer ${token}`);
        res.status(200).json({ message: 'Login successful' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 마이페이지
app.get('/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.user.username }).select('-password');
        if (!user) return res.status(404).json({ message: 'User not found' });

        res.status(200).json(user);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 마이페이지 수정
app.put('/profile', authenticateToken, async (req, res) => {
    const { username, name, emailAddress } = req.body;

    try {
        // 현재 인증된 사용자
        const user = await User.findOne({ username: username });
        if (!user) return res.status(404).json({ message: 'User not found' });

        // 업데이트할 필드
        if (username) user.username = username;
        if (name) user.name = name;
        if (emailAddress) user.emailAddress = emailAddress;

        await user.save();
        res.status(200).json({ message: 'Profile updated successfully', user });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 게시글 작성
app.post('/posts', authenticateToken, async (req, res) => {
    const { title, content } = req.body;
    const author = req.user.username;

    try {
        const newPost = new Post({ title, content, author });
        await newPost.save();
        res.status(201).json(newPost);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// 게시글 조회
app.get('/posts', async (req, res) => {
    try {
        const posts = await Post.find();
        res.json(posts);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 내가 쓴 글만 조회 (고정 경로 우선)
app.get('/posts/myposts', authenticateToken, async (req, res) => {
    try {
        if (!req.user || !req.user.username) {
            return res.status(400).json({ error: 'User not authenticated' });
        }

        const posts = await Post.find({ author: req.user.username });
        res.json(posts);
    } catch (err) {
        console.error('Error fetching posts:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// 게시글 상세 조회 (동적 경로는 아래에 배치)
app.get('/posts/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const post = await Post.findById(id);
        if (!post) return res.status(404).json({ message: 'Post not found' });
        res.json(post);
    } catch (err) {
        console.error('Error fetching post:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// 게시글 수정
app.put('/posts/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { title, content } = req.body;

    try {
        const post = await Post.findById(id);
        if (!post) return res.status(404).json({ message: 'Post not found' });
        if (post.author !== req.user.username) return res.status(403).json({ message: 'You can only edit your own posts' });

        post.title = title;
        post.content = content;
        await post.save();
        res.json(post);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 게시글 삭제
app.delete('/posts/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;

    try {
        const post = await Post.findById(id);
        if (!post) return res.status(404).json({ message: 'Post not found' });
        if (post.author !== req.user.username) return res.status(403).json({ message: 'You can only delete your own posts' });

        await post.deleteOne();
        res.json({ message: 'Post deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 서버 시작
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
