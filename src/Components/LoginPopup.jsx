import { useState } from 'react';
import axios from 'axios';
import './LoginPopup.css';
import { useNavigate } from 'react-router-dom';


const LoginPopup = () => {
    const [currentState, setCurrentState] = useState('Login');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [username, setUsername] = useState('');
    const navigate = useNavigate(); // Initialize useNavigate


    const handleLogin = async (event) => {
        event.preventDefault();
    
        const formData = new URLSearchParams();
        formData.append('username', email);
        formData.append('password', password);
    
        try {
            const response = await axios.post('http://localhost:8000/auth/token', formData, {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
            });
            
            const { access_token, username } = response.data;
            
            // Store token and username in localStorage for other purposes (if needed)
            localStorage.setItem('token', access_token);
            localStorage.setItem('username', username);
    
            // Set session token as cookie
            document.cookie = `session_token=${access_token}; path=/;`;
    
            // Redirect or update UI to indicate successful login
            console.log("Successful login", response.data);
            navigate('/Todolist'); 
        } catch (error) {
            // Handle login failure
            console.error('Login failed:', error.response);
        }
    };
    

    const handleSignup = async (event) => {
        event.preventDefault();
        try {
            const response = await axios.post('http://localhost:8000/auth/', {
                username,
                email,
                password,
            });
            console.log('Signup successful', response.data);
            setCurrentState('Login');
        } catch (error) {
            console.error('Signup failed', error.response.data);
        }
    };

    return (
        <div className='login-popup'>
            <div className='login-popup-container'>
                <form onSubmit={currentState === 'Login' ? handleLogin : handleSignup}>
                    <div className='login-popup-title'>
                        <h2>{currentState}</h2>
                    </div>
                    <div className='login-popup-inputs'>
                        {currentState === "Sign Up" && <input type='text' placeholder='Username' required value={username} onChange={(e) => setUsername(e.target.value)} />}
                        <input type='email' placeholder='Your email' required value={email} onChange={(e) => setEmail(e.target.value)} />
                        <input type='password' placeholder='Password' required value={password} onChange={(e) => setPassword(e.target.value)} />
                    </div>
                    <button type="submit">{currentState === "Sign Up" ? "Create account" : "Login"}</button>
                </form>
                <div className='login-popup-condition'>
                    <input type='checkbox' required/>
                    <div className='condition-leaf-p'>
                        <p>By continuing, you agree to <span className='green'>Leaf</span><span className='black'>Invoice</span> terms of use and privacy policy.</p>
                    </div>
                </div>
                {currentState === "Login" ? 
                    <p>Create a new account? <span className='signup-green' onClick={() => setCurrentState("Sign Up")}>Sign up here</span></p> :
                    <p>Already have an account? <span className='signup-green' onClick={() => setCurrentState("Login")}>Login here</span></p>}
            </div>
        </div>
    );
};

export default LoginPopup;
