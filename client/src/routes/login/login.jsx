import { useState } from "react";
import "./login.scss";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";

function Login() {
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false); // [1  
  const navigate = useNavigate();
  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true); // [2  
    const formData = new FormData(e.target);
    
    const username = formData.get("username");
    const email = formData.get("email");
    const password = formData.get("password");
    try {
      const response = await axios.post("http://localhost:8800/api/auth/login", {
        username,
        email,
        password
      });
      navigate("/n "); 
    }
    catch (err) {
      console.log(err);
      setError(err.response.data.message); 
    }
    finally
    {
      setIsLoading(false); // [3  
    }
  };
  return (
    <div className="login">
      <div className="formContainer">
        <form onSubmit={handleSubmit}>
          <h1>Welcome back</h1>
          <input name="username" required minLength={3} maxLength={20 } type="text" placeholder="Username" />
          <input name="password" type="password" placeholder="Password" />
          <button disabled={isLoading} >Login</button>
          {error && <span className="error">{error}</span>}
          <Link to="/register">{"Don't"} you have an account?</Link>
        </form>
      </div>
      <div className="imgContainer">
        <img src="/bg.png" alt="" />
      </div>
    </div>
  );
}

export default Login;
