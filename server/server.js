require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const mongoose = require("mongoose");
const net = require("node:net");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(helmet());
app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:5173",
  })
);
app.use(express.json());

// MongoDB schema
const scanSchema = new mongoose.Schema(
  {
    ip: { type: String, required: true },
    risk: { type: String, required: true },
    status: { type: String, required: true },
    riskClass: { type: String, required: true },
    reputation: { type: Number, default: 0 },
    analysis: {
      malicious: { type: Number, default: 0 },
      suspicious: { type: Number, default: 0 },
      harmless: { type: Number, default: 0 },
      undetected: { type: Number, default: 0 },
    },
    lastAnalysisDate: { type: Number, default: null },
  },
  { timestamps: true }
);

const Scan = mongoose.model("Scan", scanSchema);

// Private IPv4 check
function isPrivateIP(ip) {
  const [a, b] = ip.split(".").map(Number);

  return (
    a === 10 ||
    a === 127 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254)
  );
}

// Health check
app.get("/", (req, res) => {
    console.log("HEALTH ROUTE HIT:", mongoose.connection.readyState);
    
  res.json({
    success: true,
    message: "SENTRIX backend is running.",
    database:
      mongoose.connection.readyState === 1
        ? "Connected"
        : "Disconnected",
  });
});
// Check IP reputation and save result
app.post("/api/ip/check", async (req, res) => {
  try {
    const { ip } = req.body;

    if (!ip || net.isIP(ip) !== 4) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid IPv4 address.",
      });
    }

    if (isPrivateIP(ip)) {
      return res.status(400).json({
        success: false,
        message: "Private IP addresses cannot be checked.",
      });
    }

    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({
        success: false,
        message: "Database is not connected.",
      });
    }

    const apiKey = process.env.VIRUSTOTAL_API_KEY;

    if (!apiKey) {
      return res.status(503).json({
        success: false,
        message: "VirusTotal API key is not configured.",
      });
    }

    const response = await fetch(
      `https://www.virustotal.com/api/v3/ip_addresses/${ip}`,
      {
        headers: { "x-apikey": apiKey },
      }
    );

    if (!response.ok) {
      const messages = {
        401: "Invalid VirusTotal API key.",
        403: "VirusTotal access forbidden.",
        404: "No VirusTotal record found for this IP.",
        429: "VirusTotal rate limit reached.",
      };

      return res.status(response.status).json({
        success: false,
        message: messages[response.status] || "VirusTotal request failed.",
      });
    }

    const data = await response.json();
    const attributes = data.data.attributes;
    const stats = attributes.last_analysis_stats || {};

    const analysis = {
      malicious: stats.malicious ?? 0,
      suspicious: stats.suspicious ?? 0,
      harmless: stats.harmless ?? 0,
      undetected: stats.undetected ?? 0,
    };

    let risk = "LOW";
    let status = "No detections";
    let riskClass = "low";

    if (analysis.malicious > 0) {
      risk = "HIGH";
      status = "Malicious detections";
      riskClass = "high";
    } else if (analysis.suspicious > 0) {
      risk = "MEDIUM";
      status = "Suspicious detections";
      riskClass = "medium";
    }

    const scan = await Scan.create({
      ip,
      risk,
      status,
      riskClass,
      reputation: attributes.reputation ?? 0,
      analysis,
      lastAnalysisDate: attributes.last_analysis_date ?? null,
    });

    res.json({
      success: true,
      id: scan._id,
      ip: scan.ip,
      risk: scan.risk,
      status: scan.status,
      riskClass: scan.riskClass,
      reputation: scan.reputation,
      analysis: scan.analysis,
      lastAnalysisDate: scan.lastAnalysisDate,
      message: "IP scan completed and saved successfully.",
    });
  } catch (error) {
    console.error("IP check error:", error.message);

    res.status(500).json({
      success: false,
      message: "Internal server error. Please try again.",
    });
  }
});

// Get saved scan history
app.get("/api/scans", async (req, res) => {
  try {
    const scans = await Scan.find()
      .sort({ createdAt: -1 })
      .limit(100);

    res.json({
      success: true,
      count: scans.length,
      scans,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Unable to fetch scan history.",
    });
  }
});

// Delete all saved scans
app.delete("/api/scans", async (req, res) => {
  try {
    await Scan.deleteMany({});

    res.json({
      success: true,
      message: "All scan history deleted successfully.",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Unable to delete scan history.",
    });
  }
});

// Connect MongoDB, then start server
async function startServer() {
  try {
    if (!process.env.MONGODB_URI) {
      throw new Error("MONGODB_URI is missing in .env file.");
    }

    await mongoose.connect(process.env.MONGODB_URI);

    console.log("MongoDB connected successfully.");

    app.listen(PORT, () => {
      console.log(`SENTRIX backend is running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Server startup failed:", error.message);
    process.exit(1);
  }
}

startServer();