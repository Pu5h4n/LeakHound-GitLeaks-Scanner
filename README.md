# LeakHound – GitLeaks Scanner

![LeakHound Logo](Githound.jpg)

LeakHound – GitLeaks Scanner is a fast and simple tool that scans GitHub repositories for exposed secrets. It examines both current code and older commits for sensitive data such as API keys, tokens, and passwords. The tool generates an interactive HTML report with clickable links, theme toggles, and filters to help you quickly fix issues.

## Features

- **Fast & Asynchronous Scanning:**  
  LeakHound leverages Python’s `asyncio` and `aiohttp` libraries to scan repositories concurrently. This parallel approach dramatically speeds up the scanning process while carefully respecting GitHub’s API rate limits.

- **Multi-Version Secret Detection:**  
  The tool scans both the latest version (HEAD) and selected older commits. This ensures that secrets which were previously exposed—but later removed—are still detected, giving you a complete security history.

- **Deduplication of Results:**  
  To reduce clutter, LeakHound automatically filters out duplicate issues. If a secret is found in the HEAD scan, any repeats of the same secret in older commits are omitted, so your report remains clean and focused.

- **Interactive HTML Report:**  
  - **Theme Toggle:** Choose between a dark (hacker vibe) theme and a crisp white theme for a comfortable viewing experience.  
  - **Commit Selection Dropdown:** For each repository section, select between HEAD and specific commits to display only the relevant changes.  
  - **Clickable Line Numbers:** Each reported line is hyperlinked, allowing you to jump directly to the corresponding line in the GitHub file view.  
  - **Search & Filter Options:** Easily search for specific issues or hide recurring patterns, ensuring that only new and unique leaks are presented.

- **Customizable Secret Patterns:**  
  LeakHound utilizes a YAML configuration file (`git-leaks.yaml`) filled with regex patterns targeting common secret types—such as API keys, access tokens, and passwords. Modify or extend these patterns as your security needs evolve.

- **User-Friendly CLI:**  
  An interactive command-line interface guides you through selecting repository input methods and commit scanning options, making the tool accessible even if you’re new to secret scanning.

- **Efficient & Reliable:**  
  With built-in concurrency and rate limiting, LeakHound is designed to efficiently handle large projects while providing reliable, actionable insights.

## Requirements

- Python 3.8+
- Dependencies: `aiohttp`, `PyYAML`, `Jinja2`, `colorama`

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/yourusername/leakhound.git
cd leakhound
pip install aiohttp PyYAML Jinja2 colorama
python leakhound.py
