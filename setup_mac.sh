#!/bin/bash
# VulnSentinel — One-click Mac Setup Script
# Run: chmod +x setup_mac.sh && ./setup_mac.sh

set -e

echo "========================================"
echo " VulnSentinel — Mac Setup"
echo "========================================"

# Check Homebrew
if ! command -v brew &>/dev/null; then
    echo "[!] Homebrew not found. Installing..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Check Python 3.11
if ! command -v python3.11 &>/dev/null; then
    echo "[→] Installing Python 3.11..."
    brew install python@3.11
fi

echo "[✓] Python: $(python3.11 --version)"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "[→] Creating virtual environment..."
    python3.11 -m venv venv
fi

source venv/bin/activate
echo "[✓] Virtual environment activated"

# Install dependencies
echo "[→] Installing Python dependencies..."
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
echo "[✓] Dependencies installed"

# Create .env if not exists
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "[!] Created .env file — please add your GEMINI_API_KEY to .env"
fi

# Create data directories
mkdir -p data/nvd data/chromadb data/reports
echo "[✓] Data directories created"

echo ""
echo "========================================"
echo " Setup Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "  1. Add your API key:  nano .env"
echo "  2. Download CVE data: python -m ingest.downloader"
echo "  3. Index CVEs:        python -m ingest.indexer"
echo "  4. Launch app:        streamlit run app.py"
echo ""
echo "For demo without full CVE dataset:"
echo "  streamlit run app.py   (CRUD and guardrail demos work without index)"
