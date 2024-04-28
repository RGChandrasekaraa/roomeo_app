import bcrypt from 'bcrypt';

export const register = async (req, res) => {
    const { username, email, password } = req.body;
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    console.log(hashedPassword);
    

}

export const login = (req, res) => {
    res.send('Login page');
}

export const logout = (req, res) => {
    res.send('Logout page');
}  