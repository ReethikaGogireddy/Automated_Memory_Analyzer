import { useState, useEffect } from "react";
import axios from "axios";
import "./App.css";

const API_BASE = "http://localhost:5000";

function App() {
  const [page, setPage] = useState(1);

  return (
    <div className="app">
      <header className="header">
        <h1 className="gradient-text">Automated Memory Analyzer</h1>
        <p className="subtitle">Upload your dump, inspect classifications & SHAP values, and chat with it.</p>
      </header>

      <nav className="nav">
        <button
          className={page === 1 ? "nav-btn active" : "nav-btn"}
          onClick={() => setPage(1)}
        >
          1 · Upload
        </button>
        <button
          className={page === 2 ? "nav-btn active" : "nav-btn"}
          onClick={() => setPage(2)}
        >
          2 · Classification & SHAP
        </button>
        <button
          className={page === 3 ? "nav-btn active" : "nav-btn"}
          onClick={() => setPage(3)}
        >
          3 · Chat with your dump
        </button>
      </nav>

      <main className="card">
        {page === 1 && <UploadPage />}
        {page === 2 && <AnalysisPage />}
        {page === 3 && <ChatPage />}
      </main>
    </div>
  );
}

function UploadPage() {
  const [file, setFile] = useState(null);
  const [status, setStatus] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) {
      setStatus("Please select a file.");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    try {
      setStatus("Uploading...");
      const res = await axios.post(`${API_BASE}/api/upload`, formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setStatus(res.data.message || "Uploaded!");
    } catch (err) {
      console.error(err);
      setStatus("Upload failed.");
    }
  };

  return (
    <div>
      <h2>Upload your dump</h2>
      <form onSubmit={handleSubmit} className="upload-form">
        <input
          type="file"
          onChange={(e) => setFile(e.target.files[0])}
        />
        <button type="submit">Upload</button>
      </form>
      {status && <p className="status-text">{status}</p>}
    </div>
  );
}

function AnalysisPage() {
  const [classification, setClassification] = useState([]);
  const [shap, setShap] = useState([]);
  const [loading, setLoading] = useState(false);

  const loadData = async () => {
    try {
      setLoading(true);
      const [classRes, shapRes] = await Promise.all([
        axios.get(`${API_BASE}/api/classification`),
        axios.get(`${API_BASE}/api/shap`),
      ]);
      setClassification(classRes.data.results || []);
      setShap(shapRes.data.values || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  return (
    <div className="grid">
      <section>
        <h2>Classification</h2>
        {loading && <p>Loading…</p>}
        {!loading && (
          <ul>
            {classification.map((c) => (
              <li key={c.label}>
                <strong>{c.label}</strong> — {(c.score * 100).toFixed(1)}%
              </li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <h2>SHAP values</h2>
        {!loading && (
          <ul>
            {shap.map((s) => (
              <li key={s.feature}>
                <strong>{s.feature}</strong>: {s.value.toFixed(2)}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function ChatPage() {
  const [message, setMessage] = useState("");
  const [conversation, setConversation] = useState([]);

  const sendMessage = async (e) => {
    e.preventDefault();
    if (!message.trim()) return;

    const userMsg = { from: "you", text: message };
    setConversation((prev) => [...prev, userMsg]);
    setMessage("");

    try {
      const res = await axios.post(`${API_BASE}/api/chat`, { message });
      const botMsg = { from: "bot", text: res.data.reply };
      setConversation((prev) => [...prev, botMsg]);
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div>
      <h2>Chat with your dump</h2>
      <div className="chat-box">
        {conversation.map((m, idx) => (
          <div
            key={idx}
            className={m.from === "you" ? "chat-msg you" : "chat-msg bot"}
          >
            <span>{m.text}</span>
          </div>
        ))}
      </div>

      <form onSubmit={sendMessage} className="chat-form">
        <input
          type="text"
          placeholder="Ask anything you didn't understand…"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
        />
        <button type="submit">Send</button>
      </form>
    </div>
  );
}

export default App;
