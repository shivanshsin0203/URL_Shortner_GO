import React, { useEffect, useState } from 'react';
import axios from 'axios';
import "./App.css"
const Login = () => {
  
  const [email, setEmail] = useState('');
  const [message, setMessage] = useState('');
  const [auth, setAuth] = useState(false);
  const [url, setUrl] = useState('');
  const [shortUrl, setShortUrl] = useState('');
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
  const handleUrlShorten = async (e: React.FormEvent) => {
    e.preventDefault();
    const token = localStorage.getItem('token');
    try {
      const response = await axios.post<{ shortUrl: string }>(
        'http://localhost:8080/shorten',
        { url },
        {
          headers: { Authorization: token },
        }
      );
      console.log(response)
      setShortUrl(response.data.shortUrl);
      setMessage('URL shortened successfully!');
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (error:any) {
      if (error.response && error.response.status === 429) {
        setMessage('Rate limit exceeded. Please try again later.');
    } else {
        setMessage('Failed to shorten URL. Please try again.' + error);
    }
    }
  };
  return (
    <div className="container">{auth ? <div><h2>Logged in</h2>
      <form onSubmit={handleUrlShorten}>
        <input
          type="url"
          placeholder="Enter your URL"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          required
        />
        <button type="submit">Shorten URL</button>
      </form>
      {message && <p>{message}</p>}
      {shortUrl && (
        <p>
          Shortened URL: <a href={shortUrl} target="_blank" rel="noopener noreferrer">{shortUrl}</a>
        </p>
      )}</div> :<div><h2>Login</h2>
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
