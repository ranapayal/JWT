const bcrypt=require('bcryptjs');

const users=[
    {
        id:1,
        username:"john",
        password:bcrypt.hashSync("password123",8),
        refreshToken:null
    }
];

module.exports=users;