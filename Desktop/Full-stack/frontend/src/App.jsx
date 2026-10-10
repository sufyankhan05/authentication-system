import { useState } from "react";
import "./App.css";

function App() {
  const [message, setMessage] = useState("Frontend is ready");
  return (
    <main className="app">
      <h1>Authentication System</h1>
      <p>{message}</p>
      <button onClick={() => setMessage("Ready to connect to the backend!")}>
        Get Started
      </button>
    </main>
  );
}
export default App;
