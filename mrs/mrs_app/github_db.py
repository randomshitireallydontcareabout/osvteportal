import os
import time
import requests
from github import Github

# Base URL to pull down public data instantly
RAW_DATA_URL = "https://githubusercontent.com"

# Repository configuration for writing data
REPO_NAME = "YOUR_USERNAME/YOUR_REPO"
FILE_PATH = "YOUR_FOLDER/data.json"

def read_database():
    """Fetches the latest data from your public GitHub repository."""
    try:
        # Appending a timestamp bypasses GitHub's 5-minute CDN cache
        cache_buster_url = f"{RAW_DATA_URL}?t={int(time.time())}"
        response = requests.get(cache_buster_url)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"❌ [GitHub DB Error] Could not read data: {e}")
        return None

def write_database(new_data_string, commit_message="Database auto-update"):
    """Overwrites the data file back into your GitHub repository."""
    # Pull the token out of the secure environment variable
    token = os.getenv("GITHUB_DB_TOKEN")
    
    if not token:
        print("❌ [GitHub DB Error] Missing GITHUB_DB_TOKEN environment variable. Write canceled.")
        return False
        
    try:
        g = Github(token)
        repo = g.get_repo(REPO_NAME)
        
        # Git needs the current file identifier (SHA) to securely overwrite it
        contents = repo.get_contents(FILE_PATH)
        
        repo.update_file(
            path=FILE_PATH,
            message=commit_message,
            content=new_data_string,
            sha=contents.sha,
            branch="main"
        )
        print("💾 [GitHub DB Success] Data pushed to repository!")
        return True
    except Exception as e:
        print(f"❌ [GitHub DB Error] Failed to write data: {e}")
        return False
