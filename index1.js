const express=require("express");
const mongoose=require("mongoose")
const cors=require("cors");
const User=require("./models/user.model")
const jwt=require('jsonwebtoken')
const bcrypt=require('bcryptjs')
const app=express()

app.use(cors())
app.use(express.json())


const expiresIn = '2m';

mongoose.connect("mongodb://127.0.0.1:27017/login",{
    useNewUrlParser:true,
    useUnifiedTopology:true
}).then(()=>console.log("connected to db")).catch(console.error);

app.post("/api/register",async (req,res)=>{
    console.log(req.body);
    try{
        const newPassword=await bcrypt.hash(req.body.password,10)
        await User.create({
            name:req.body.name,
            email:req.body.email,
            password:newPassword,
        })
        res.send({status:"ok"})
    }
    catch(err){
        console.log(err);
        res.send({status:"error" , error: "email already exists"})
    }
})

app.post('/api/login', async (req, res) => {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.json({ status: 'error', error: 'Invalid login credentials' });
    }
  
    const isPasswordValid = await bcrypt.compare(req.body.password, user.password);
    if (isPasswordValid) {
      const accessToken = jwt.sign(
        {
          name: user.name,
          email: user.email
        },
        'access-secret123',
        { expiresIn: '15m' } // Access token expiration time
      );
  
      const refreshToken = jwt.sign(
        {
          name: user.name,
          email: user.email
        },
        'refreshToken',
        { expiresIn: '7d' } // Refresh token expiration time
      );
  
      return res.json({ status: 'ok', user:accessToken, rtoken:refreshToken });
    } else {
      return res.json({ status: 'error', user: false });
    }
  });
 

app.get("/api/quote",async (req,res)=>{
    const token=req.headers['x-access-token'];

    try{
        const decoded=jwt.verify(token,'secret123');
        const email=decoded.email;
        const user= await User.findOne({email:email})

        return res.json({status:'ok',quote:user.quote})
    }
    catch(error){
        console.log(error);
        res.json({status:"error" ,error:"invalid token"})
    }
})

app.post("/api/quote",async (req,res)=>{
    const token=req.headers['x-access-token'];

    try{
        const decoded=jwt.verify(token,'secret123');
        const email=decoded.email;
        await User.updateOne({email:email},{$set:{quote:req.body.quote}})

        return res.json({status:'ok'})
    }
    catch(error){
        console.log(error,"hello");
        res.json({status:"error" ,error:"invalid token"})
    }
})



app.listen(3009,()=>{
    console.log("Server on 3009");
})