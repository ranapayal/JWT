const jwt=require('jsonwebtoken');
const ACCESS_SECRET='access_secret_key';

module.exports=function (req,res,next)
{
    const authHeader=req.headers.authorization;
    const token=authHeader?.split(' ')[1];

    if(!token)
        return res.status(401).json({message:'Access token missing'});
    try{
        const decoded=jwt.verify(token,ACCESS_SECRET);
        req.user=decoded;
        next();
    }catch(err){
        return res.status(403).json({message:'Access token expired or invalid'});
    }
};