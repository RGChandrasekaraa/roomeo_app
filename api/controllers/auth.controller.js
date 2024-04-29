import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken'; 
import prisma from '../lib/prisma.js';

export const register = async (req, res) => {
    const { username, email, password } = req.body;

    try {
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        console.log(hashedPassword);  
        // Save user to database
        const newUser = await prisma.user.create({
            data: {
                username,
                email,
                password: hashedPassword,
            },
        });   
        console.log(newUser);    
        res.status(201).json({ message: 'User created' })   ; 
    }
    catch (error) {
        console.log(error)
        res.status(500).json({ message: 'Error creating user' });
    }  
}

export const login = async (req, res) => {
    console.log("Login request received", req.body);
    const { username, password } = req.body;
    
    try {
        const age = (1000 * 60 * 60 * 24 * 7)
        // Find user in database
        const user = await prisma.user.findUnique({
            where: { username: username }
        })
        // Check if user exists
        if (!user) {
            return res.status(401).json({ message: 'invalid credential ' });
        }
        // Check if password is valid
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'invalid credential ' });
        }
        
        // Generate token
        const token = jwt.sign({
            id: user.id,
        },process.env.JWT_SECRET_KEY, { expiresIn: age }); 
        // cookie
        res.cookie("token ", token, {
            httpOnly: true,
            // secure: true,
            maxAge: age,  
        }).status(200).json({ message: 'Logged in' });
    }

    catch (error) {
        console.log(error)
        res.status(500).json({ message: 'Error logging in' });
    }
}; 

export const logout = (req, res) => {
    try {
        res.clearCookie('token').status(200).json({ message: 'Logged out' });
    }
    catch (error) {
        console.log(error)
        res.status(500).json({ message: 'Error logging out' });
    }
}  