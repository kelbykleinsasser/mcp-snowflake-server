#!/usr/bin/env python3
import os
import sys
from pathlib import Path
import dotenv

def main():
    """CLI entry point that ensures environment variables are loaded before importing the main module."""
    # First, try to load environment variables from .env file
    dotenv_path = os.getenv('DOTENV_PATH', '.env')
    if os.path.exists(dotenv_path):
        dotenv.load_dotenv(dotenv_path)
    
    # Now import and run the main function
    from mcp_snowflake_server import main as snowflake_main
    snowflake_main()

if __name__ == "__main__":
    main() 