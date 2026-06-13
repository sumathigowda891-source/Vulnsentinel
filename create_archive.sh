#!/bin/bash
# create_archive.sh
# Script to create a highly-compressed, upload-ready ZIP file of the VulnSentinel project.
# Excludes the machine-specific virtual environment (venv) and git history (.git).

ARCHIVE_NAME="vulnsentinel_submission.zip"

echo "========================================================="
echo "VulnSentinel — Archive Creator"
echo "========================================================="

# 1. Vacuum SQLite database to save space
if [ -f "data/chromadb/chroma.sqlite3" ]; then
    echo "🧹 Vacuuming ChromaDB SQLite database to reclaim space..."
    sqlite3 data/chromadb/chroma.sqlite3 "VACUUM;"
fi

# 2. Check if zip is installed
if ! command -v zip &> /dev/null; then
    echo "❌ Error: 'zip' command not found. Please install zip or compress manually."
    exit 1
fi

# 3. Clean up any existing archive to prevent self-inclusion
if [ -f "$ARCHIVE_NAME" ]; then
    rm "$ARCHIVE_NAME"
fi

echo "📦 Creating compressed ZIP file: $ARCHIVE_NAME..."
# Compress project, excluding venv, git, log files, caches, and test artifacts
zip -r -9 "$ARCHIVE_NAME" . \
    -x "venv/*" \
    -x ".git/*" \
    -x "logs/*" \
    -x ".pytest_cache/*" \
    -x "__pycache__/*" \
    -x "**/__pycache__/*" \
    -x ".DS_Store" \
    -x "**/ .DS_Store" \
    -x ".coverage" \
    -x "$ARCHIVE_NAME"

echo "========================================================="
echo "✅ Archive created successfully!"
echo "File: $ARCHIVE_NAME"
echo "Size: $(du -sh "$ARCHIVE_NAME" | cut -f1)"
echo "========================================================="
