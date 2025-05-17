#!/bin/bash
# Setup script for safe-mcp using UV

# Check if UV is installed
if ! command -v uv &> /dev/null; then
    echo "Error: UV is not installed on this system."
    echo "Please install UV package manager first by following the official instructions at:"
    echo "https://docs.astral.sh/uv/getting-started/installation/"
    echo ""
    echo "After installing UV, run this script again."
    exit 1
fi

# Create and activate virtual environment
echo "Creating virtual environment with UV..."
uv venv

# Determine the activation command based on shell
if [[ "$SHELL" == *"zsh"* ]]; then
    echo "source .venv/bin/activate" # ZSH
elif [[ "$SHELL" == *"bash"* ]]; then
    echo "source .venv/bin/activate" # Bash
elif [[ "$SHELL" == *"fish"* ]]; then
    echo "source .venv/bin/activate.fish" # Fish
else
    echo "Please activate the virtual environment manually."
fi

# Install dependencies
echo "Installing dependencies with UV..."
uv pip install -e .

# Install development dependencies
echo "Installing development dependencies..."
uv pip install -e ".[dev]"

# Instructions for next steps
echo ""
echo "Setup complete! You can now:"
echo "1. Activate your virtual environment"
echo "2. Run the example: python -m examples.mcp_server_example"
echo "3. Run tests: pytest tests/"
echo ""
echo "To install in another project:"
echo "uv pip install path/to/safe-mcp"