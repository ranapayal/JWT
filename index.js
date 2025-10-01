const express=require('express');
const jwt=require('jsonwebtoken');
const bodyParser=require('body-parser');
const cookieParser=require('cookie-parser');
const bcrypt=require('bcryptjs');
const users=require('./users');
const auth=require('./middleware/auth');

const app=express();
app.use(bodyParser.json());
app.use(cookieParser());

const ACCESS_SECRET='access_secret_key';
const REFRESH_SECRET='refresh_secret_key';

const generateAccessToken=(user)=>
    jwt.sign({id:user.id,username:user.username},ACCESS_SECRET,{expiresIn:'1m'});

const generateRefreshToken=(user)=>
    jwt.sign({id:user.id},REFRESH_SECRET,{expiresIn:'7d'});

app.post('/login',(req,res)=>{
    const { username,password }=req.body;
    const user=users.find(u=> u.username === username);

    if(!user || !bcrypt.compareSync(password,user.password))
    {
        return res.status(401).json({message:'Invalid credentials'});
    }
    const accessToken=generateAccessToken(user);
    const refreshToken=generateRefreshToken(user);

    user.refreshToken=refreshToken;

    res.cookie('refreshToken',refreshToken,{
        httpOnly:true,
        secure:false,
        sameSite:'strict',
        maxAge:7*24*60*60*1000
    });

    res.json({accessToken});
});

app.get('/dashboard',auth,(req,res)=>{
    res.json({message:`Welcome, ${req.user.username}`});
});

app.post('/refresh',(req,res)=>{
    const token=req.cookies.refreshToken;
    if(!token)  return res.status(401).json({message:'No refresh token provided'});

    const user=users.find(u=>u.refreshToken===token);
    if(!user)   return res.status(403).json({message:'Invalid refresh token'});

    try{
        jwt.verify(token,REFRESH_SECRET);
        const accessToken=generateAccessToken(user);
        res.json({accessToken});
    }catch(err){
        res.status(403).json({message:'Refresh token expired or invalid'});
    }
});

app.post('/logout',(req,res)=>{
    const token=req.cookies.refreshToken;
    const user=users.find(u=>u.refreshToken===token);
    if(user)    user.refreshToken=null;
    res.clearCookie('refreshToken');
    res.json({message:'Logged out'});
});

app.listen(3000,()=>console.log('Running on http://localhost:3000'));