import React, { useEffect, useState } from 'react';
import axios from 'axios';

const Login = () => {
  
  const [email, setEmail] = useState('');
  const [message, setMessage] = useState('');
  const [auth, setAuth] = useState(false);
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const response = await axios.post<{ token: string }>('http://localhost:8080/login', { email });
      console.log(response)
      const token = response.data.token;

      
      localStorage.setItem('token', token);

      setMessage('Login successful!');
      setAuth(true);
    } catch (error) {
      setMessage('Login failed. Please try again.'+ error);
    }
  };

  const checkToken = async () => {
    const token = localStorage.getItem('token');
    try {
      const response = await axios.get('http://localhost:8080/validate', {
        headers: { Authorization: token },
      });
      setMessage(response.data);
      if(response.data === 'Token is valid!'){
        setAuth(true);}
    } catch (error) {
      setMessage('Token is invalid or expired' + error);
    }
  };
  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      checkToken();
      
    }
  }, []);
  return (
    <div>{auth ? <h2>Logged in</h2> :<div><h2>Login</h2>
      <form onSubmit={handleLogin}>
        <input
          type="email"
          placeholder="Enter your email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <button type="submit">Login</button>
      </form>
      {message && <p>{message}</p>}
      <button onClick={checkToken}>Check Token</button></div>
      }
    </div>
  );
};

export default Login;
