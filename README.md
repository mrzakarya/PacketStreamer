<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PacketStreamer - README</title>
    <style>
        :root {
            --bg-color: #0d1117;
            --text-color: #c9d1d9;
            --heading-color: #ffffff;
            --link-color: #58a6ff;
            --border-color: #30363d;
            --code-bg: #161b22;
            --accent-green: #238636;
            --accent-blue: #1f6feb;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            max-width: 900px;
            margin: 0 auto;
            padding: 2rem;
        }

        h1, h2, h3 {
            color: var(--heading-color);
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.3rem;
            margin-top: 2rem;
        }

        h1 { border-bottom: none; font-size: 2.5rem; margin-top: 0; }
        
        a { color: var(--link-color); text-decoration: none; }
        a:hover { text-decoration: underline; }

        .badges {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 1.5rem;
        }

        .badge {
            background-color: var(--code-bg);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            padding: 4px 12px;
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--heading-color);
        }

        pre {
            background-color: var(--code-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 1rem;
            overflow-x: auto;
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 0.9rem;
        }

        code {
            background-color: rgba(110, 118, 129, 0.4);
            border-radius: 4px;
            padding: 0.2em 0.4em;
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 85%;
        }

        pre code {
            background-color: transparent;
            padding: 0;
        }

        ul, ol { padding-left: 2rem; }
        li { margin-bottom: 0.5rem; }

        table {
            border-collapse: collapse;
            width: 100%;
            margin: 1.5rem 0;
        }

        th, td {
            border: 1px solid var(--border-color);
            padding: 0.75rem;
            text-align: left;
        }

        th { background-color: var(--code-bg); font-weight: 600; }

        .screenshot-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            margin-top: 1rem;
        }

        .screenshot-box {
            background-color: var(--code-bg);
            border: 1px dashed var(--border-color);
            border-radius: 6px;
            padding: 2rem;
            text-align: center;
            color: #8b949e;
            font-style: italic;
        }

        .alert {
            background-color: rgba(56, 139, 253, 0.1);
            border-left: 4px solid var(--accent-blue);
            padding: 1rem;
            border-radius: 0 6px 6px 0;
            margin: 1.5rem 0;
        }

        footer {
            margin-top: 3rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border-color);
            text-align: center;
            color: #8b949e;
            font-size: 0.9rem;
        }

        @media (max-width: 600px) {
            .screenshot-grid { grid-template-columns: 1fr; }
            body { padding: 1rem; }
        }
    </style>
    <!-- اضافه کردن آیکون‌ها -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>

    <h1>🚀 PacketStreamer</h1>
    
    <div class="badges">
        <span class="badge"><i class="fas fa-balance-scale"></i> License: MIT</span>
        <span class="badge"><i class="fab fa-cuttlefish"></i> C++ 17</span>
        <span class="badge"><i class="fab fa-microsoft"></i> C# .NET 8</span>
        <span class="badge"><i class="fab fa-windows"></i> Platform: Windows</span>
    </div>

    <p><strong>A High-Performance Network Packet Analyzer and Streamer</strong></p>
    <p>PacketStreamer is a blazing-fast, real-time network monitoring tool built with a hybrid <strong>C++ (Npcap)</strong> and <strong>C# (WPF)</strong> architecture. It captures, parses, filters, and visualizes network traffic with enterprise-grade performance, designed to handle high-throughput environments without dropping packets.</p>

    <h2>✨ Key Features</h2>
    <ul>
        <li>⚡ <strong>High-Performance Engine:</strong> C++ core with Npcap for zero-overhead packet capture.</li>
        <li>🔄 <strong>Ring Buffer Architecture:</strong> Custom memory-efficient ring buffer to handle millions of packets without GC pressure or memory leaks.</li>
        <li>📊 <strong>Real-Time Dashboard:</strong> Live Pie Charts and Time Series (PPS & BPS) using LiveCharts.</li>
        <li>🔍 <strong>Advanced Filtering:</strong> Multi-layer filtering by IP, Port, Protocol, Length, and deep payload inspection (Hex/ASCII).</li>
        <li>👑 <strong>Top Talkers Analysis:</strong> Real-time identification of the most active Source and Destination IPs.</li>
        <li>📁 <strong>Protocol Detection:</strong> Automatic detection of HTTP (URLs), DNS (Domains), and TLS (SNI) traffic.</li>
        <li>💾 <strong>File Extraction:</strong> Automatically extracts and saves HTTP files (HTML, CSS, JS, Images) locally for offline analysis.</li>
        <li>📤 <strong>Export Capabilities:</strong> Export filtered or full captures to standard <strong>PCAP</strong> (Wireshark compatible) and <strong>CSV</strong> formats.</li>
        <li>🎨 <strong>Modern UI:</strong> Dark-themed, responsive WPF interface with detailed Hex/ASCII packet inspection.</li>
    </ul>

    <h2>🏗️ Architecture</h2>
    <pre><code>┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────────┐
│   Npcap Driver  │────▶│  C++ Core (DLL)      │────▶│  C# WPF Dashboard   │
│   (Kernel)      │     │  - Raw Capture       │     │  - Real-time Charts │
│                 │     │  - Header Parsing    │     │  - Ring Buffer Mgmt │
└─────────────────┘     │  - Background Queue  │     │  - Adv. Filtering   │
                        └──────────────────────┘     └─────────────────────┘</code></pre>

    <h2>📦 Prerequisites</h2>
    <ol>
        <li><strong>Windows 10/11</strong> (Administrator privileges required for packet capture).</li>
        <li><strong><a href="https://npcap.com/" target="_blank">Npcap</a></strong>: Install the latest version. <em>Make sure to check "Install Npcap in WinPcap API-compatible Mode" during installation.</em></li>
        <li><strong><a href="https://npcap.com/dist/npcap-sdk-1.13.zip" target="_blank">Npcap SDK</a></strong>: Required only if you want to recompile the C++ core.</li>
        <li><strong>Visual Studio 2022</strong> with C++ Desktop Development and .NET Desktop Development workloads.</li>
        <li><strong>.NET 8.0 SDK</strong>.</li>
    </ol>

    <h2>🛠️ How to Build</h2>
    <ol>
        <li>Clone the repository:
            <pre><code>git clone https://github.com/mrzakarya/PacketStreamer.git
cd PacketStreamer</code></pre>
        </li>
        <li>Open <code>PacketStreamer.sln</code> in Visual Studio.</li>
        <li><strong>Build the C++ Core:</strong>
            <ul>
                <li>Set <code>PacketStreamer_Core</code> as the Startup Project (or build it manually).</li>
                <li>Ensure the configuration is set to <code>x64</code> and <code>Debug</code> (or <code>Release</code>).</li>
                <li>Build the project.</li>
            </ul>
        </li>
        <li><strong>Copy the DLL:</strong> Copy <code>PacketStreamer_Core.dll</code> from <code>PacketStreamer_Core\x64\Debug\</code> to <code>PacketStreamer_Dashboard\bin\Debug\net8.0\</code>.</li>
        <li><strong>Run the Dashboard:</strong> Set <code>PacketStreamer_Dashboard</code> as the Startup Project, <strong>Run Visual Studio as Administrator</strong>, and press <code>F5</code>!</li>
    </ol>

    <h2>📸 Screenshots</h2>
    <div class="screenshot-grid">
        <div class="screenshot-box">
            <i class="fas fa-chart-pie fa-3x" style="margin-bottom: 10px;"></i><br>
            [ Real-time Dashboard Screenshot ]
        </div>
        <div class="screenshot-box">
            <i class="fas fa-filter fa-3x" style="margin-bottom: 10px;"></i><br>
            [ Advanced Packet Filtering Screenshot ]
        </div>
        <div class="screenshot-box">
            <i class="fas fa-users fa-3x" style="margin-bottom: 10px;"></i><br>
            [ Top Talkers & Time Series Screenshot ]
        </div>
        <div class="screenshot-box">
            <i class="fas fa-code fa-3x" style="margin-bottom: 10px;"></i><br>
            [ Hex/ASCII Packet Inspector Screenshot ]
        </div>
    </div>
    <p style="text-align: center; font-size: 0.9rem; color: #8b949e; margin-top: 10px;"><em>💡 Tip: Replace these placeholders with actual screenshots of your running application!</em></p>

    <div class="alert">
        <strong>⚠️ Important Notes:</strong><br>
        • <strong>HTTPS Encryption:</strong> Like all standard packet sniffers, PacketStreamer can only inspect the payload of unencrypted traffic (e.g., HTTP Port 80, DNS Port 53). HTTPS (Port 443) payload is encrypted, though TLS SNI (domain names) can still be extracted from the Client Hello handshake.<br>
        • <strong>Administrator Rights:</strong> The application must be run as Administrator to access the Npcap driver.
    </div>

    <h2>🤝 Contributing</h2>
    <p>Contributions, issues, and feature requests are welcome! Feel free to check the <a href="#">issues page</a>.</p>

    <h2>📜 License</h2>
    <p>This project is licensed under the <strong>MIT License</strong> - see the <a href="#">LICENSE</a> file for details.</p>

    <footer>
        Made with ❤️ by <strong>Mr Zakarya</strong>
    </footer>

</body>
</html>