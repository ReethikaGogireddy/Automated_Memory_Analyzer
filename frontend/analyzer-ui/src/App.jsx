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
  formData.append("file", file); // must match 'file' in routes.py

  try {
    setStatus("Uploading...");
    const res = await axios.post(`${API_BASE}/api/upload`, formData, {
      headers: { "Content-Type": "multipart/form-data" },
    });

    console.log("Upload response:", res.status, res.data);

    const { message, saved_to } = res.data;
    setStatus(saved_to ? `${message} Saved at: ${saved_to}` : message);
  } catch (err) {
    console.error("Upload error:", err);

    // If the backend sent a JSON error, show that
    const backendMsg = err.response?.data?.message;
    if (backendMsg) {
      setStatus(`Upload failed: ${backendMsg}`);
    } else if (err.message) {
      setStatus(`Upload failed: ${err.message}`);
    } else {
      setStatus("Upload failed due to an unknown error.");
    }
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

  const [showExplain, setShowExplain] = useState(false);
  const [explanation, setExplanation] = useState("");
  const [explainLoading, setExplainLoading] = useState(false);

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

  const handleExplainClick = async () => {
    if (!explanation) {
      try {
        setExplainLoading(true);
        const res = await axios.get(`${API_BASE}/api/shap-explanation`);
        setExplanation(res.data.explanation || "No explanation available.");
      } catch (err) {
        console.error("Explain error:", err);
        const backendMsg =
          err.response?.data?.explanation ||
          err.response?.data?.message ||
          err.message;
        setExplanation(backendMsg || "Failed to load explanation.");
      } finally {
        setExplainLoading(false);
      }
    }

    setShowExplain((prev) => !prev);
  };

  return (
    <div className="grid">
      <section>
        <h2>Classification</h2>
        {loading && <p>Loading…</p>}
        {!loading && (
          <ul>
            {classification.map((c) => (
              <li key={c.label}>
                <strong>Suspicious Score</strong> — {(c.score * 100).toFixed(1)}%
              </li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <h2>SHAP values</h2>
        {loading && <p>Loading…</p>}
        {!loading && (
          <ul className="shap-list">
            {shap.map((s) => (
              <li key={s.feature}>
                <strong>{s.feature}</strong>: {Number(s.value).toFixed(4)}
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* explanation row spanning both columns */}
      <div className="explain-row">
        <button
          type="button"
          className="explain-btn"
          onClick={handleExplainClick}
        >
          {showExplain ? "Hide explanation" : "Explain (Ollama)"}
        </button>

        {showExplain && (
          <div className="shap-explanation">
            {explainLoading ? (
              <p>Loading explanation…</p>
            ) : (
              <pre className="explanation-text">
                {explanation || "(no explanation text)"}
              </pre>
            )}
          </div>
        )}
      </div>
    </div>
  );
}




function ChatPage() {
  const [message, setMessage] = useState("");
  const [conversation, setConversation] = useState([]);
  const [isThinking, setIsThinking] = useState(false);

  const sendMessage = async (e) => {
    e.preventDefault();
    if (!message.trim()) return;

    const userMsg = { from: "you", text: message };
    setConversation((prev) => [...prev, userMsg]);
    setMessage("");

    try {
      setIsThinking(true); // 🔥 start thinking effect

      const res = await axios.post(`${API_BASE}/api/chat`, { message });
      const botMsg = { from: "bot", text: res.data.reply };
      setConversation((prev) => [...prev, botMsg]);
    } catch (err) {
      console.error(err);
      const botMsg = {
        from: "bot",
        text: "Sorry, I couldn't respond. Please try again.",
      };
      setConversation((prev) => [...prev, botMsg]);
    } finally {
      setIsThinking(false); // 🔥 stop thinking effect
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

        {/* 🔥 Thinking bubble */}
        {isThinking && (
          <div className="chat-msg bot thinking">
            <span className="thinking-dots">
              <span>.</span>
              <span>.</span>
              <span>.</span>
            </span>
          </div>
        )}
      </div>

      <form onSubmit={sendMessage} className="chat-form">
        <input
          type="text"
          placeholder="Ask anything you didn't understand…"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
        />
        <button type="submit" disabled={isThinking}>
          {isThinking ? "Thinking…" : "Send"}
        </button>
      </form>
    </div>
  );
}

export default App;
