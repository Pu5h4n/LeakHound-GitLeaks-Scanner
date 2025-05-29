#!/usr/bin/env python
import os
import re
import sys
import yaml
import time
import asyncio
import aiohttp
import argparse
from jinja2 import Environment, FileSystemLoader
from colorama import init, Fore
from tqdm import tqdm
from markupsafe import escape, Markup
from datetime import datetime

# Initialize Colorama for colored terminal output.
init(autoreset=True)

def log(message):
    # Log everything via tqdm.write.
    tqdm.write(message)

def format_commit_date(date_str):
    """Convert ISO commit date into a friendlier format: e.g. 'May 06, 2025 02:00 PM'."""
    if date_str == "unknown":
        return date_str
    try:
        if date_str.endswith("Z"):
            dt = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")
        else:
            dt = datetime.fromisoformat(date_str)
        return dt.strftime("%B %d, %Y %I:%M %p")
    except Exception:
        return date_str

async def heartbeat():
    """
    Background task that every 30 seconds prints the names of currently active tasks.
    """
    while True:
        await asyncio.sleep(30)
        active_tasks = [t.get_name() for t in asyncio.all_tasks() if not t.done() and t.get_name() != "Heartbeat"]
        tqdm.write(Fore.MAGENTA + "Heartbeat: Active tasks: " + ", ".join(active_tasks))

async def wait_for_enter_or_status():
    """
    Non‑blocking wait function that:
      - On Windows: Checks for keypress every 0.1 sec. If the key pressed is 's' (case‑insensitive), prints
        the status (i.e. names of active tasks). If Enter is pressed, returns.
      - On UNIX: Reads from sys.stdin in a background executor. If the input is "s", prints the status and
        continues waiting; any other input (or just Enter) is considered as a signal to proceed.
    """
    if os.name == "nt":
        import msvcrt
        while True:
            await asyncio.sleep(0.1)
            if msvcrt.kbhit():
                ch = msvcrt.getch()
                if ch.lower() == b's':
                    active_tasks = [t.get_name() for t in asyncio.all_tasks() if not t.done() and t.get_name() != "Heartbeat"]
                    tqdm.write(Fore.MAGENTA + "Manual Status: Active tasks: " + ", ".join(active_tasks))
                elif ch in (b'\r', b'\n'):
                    while msvcrt.kbhit():
                        msvcrt.getch()
                    return True
    else:
        loop = asyncio.get_running_loop()
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if line.strip().lower() == "s":
            active_tasks = [t.get_name() for t in asyncio.all_tasks() if not t.done() and t.get_name() != "Heartbeat"]
            tqdm.write(Fore.MAGENTA + "Manual Status: Active tasks: " + ", ".join(active_tasks))
            return await wait_for_enter_or_status()
        else:
            return True

class GitLeaksAsyncScanner:
    def __init__(self, github_token, patterns_file='git-leaks.yaml', concurrency=10,
                 commit_scan_flag=False, commit_limit=0):
        self.github_token = github_token
        self.headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        self.semaphore = asyncio.Semaphore(concurrency)
        self.patterns = self.load_patterns(patterns_file)
        self.commit_scan_flag = commit_scan_flag
        self.commit_limit = commit_limit  # None means scan all commits.

    def load_patterns(self, patterns_file):
        try:
            with open(patterns_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
        except Exception as e:
            tqdm.write(Fore.RED + f"❌ Error loading patterns file: {e}")
            return []
        patterns = []
        for entry in data.get('patterns', []):
            pattern_block = entry.get('pattern', {})
            regex = pattern_block.get('regex')
            name  = pattern_block.get('name', 'Unknown')
            if regex:
                try:
                    compiled = re.compile(regex, re.IGNORECASE)
                    patterns.append({'name': name, 'regex': compiled})
                except re.error as err:
                    tqdm.write(Fore.YELLOW + f"⚠️ Invalid regex ({name}): {err}")
                    continue
        tqdm.write(Fore.GREEN + f"✅ Loaded {len(patterns)} patterns from {patterns_file}")
        return patterns

    async def _fetch_json(self, session, url, headers=None):
        headers = headers if headers is not None else self.headers
        while True:
            try:
                async with self.semaphore:
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 409:
                            tqdm.write(Fore.WHITE + f"∅ Conflict (409) for URL: {url}")
                            return {}
                        if resp.status == 403 and (
                            "X-RateLimit-Remaining" not in resp.headers or
                            int(resp.headers.get("X-RateLimit-Remaining", "0")) == 0):
                            tqdm.write(Fore.YELLOW + f"Rate limit reached for JSON at {url}, waiting 60 sec...")
                            await asyncio.sleep(60)
                            continue
                        if resp.status == 200:
                            return await resp.json()
                        else:
                            tqdm.write(Fore.RED + f"❌ Error fetching JSON from {url}: {resp.status}")
                            return {}
            except asyncio.CancelledError:
                raise
            except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                tqdm.write(Fore.YELLOW + f"⚠️ Error fetching JSON from {url}: {e}. Retrying in 60 sec...")
                await asyncio.sleep(60)
                continue

    async def _fetch_text(self, session, url, headers=None):
        headers = headers if headers is not None else {}
        while True:
            try:
                async with self.semaphore:
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 409:
                            tqdm.write(Fore.WHITE + f"∅ Conflict (409) for URL: {url}")
                            return None
                        if resp.status == 403 and (
                            "X-RateLimit-Remaining" not in resp.headers or
                            int(resp.headers.get("X-RateLimit-Remaining", "0")) == 0):
                            tqdm.write(Fore.YELLOW + f"Rate limit reached for text at {url}, waiting 60 sec...")
                            await asyncio.sleep(60)
                            continue
                        if resp.status == 200:
                            try:
                                return await resp.text()
                            except UnicodeDecodeError:
                                tqdm.write(Fore.YELLOW + f"⚠️ Skipping binary or non‑UTF8 file: {url}")
                                return None
                        else:
                            return None
            except asyncio.CancelledError:
                raise
            except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                tqdm.write(Fore.YELLOW + f"⚠️ Error fetching text from {url}: {e}. Retrying in 60 sec...")
                await asyncio.sleep(60)
                continue

    async def check_rate_limit(self, session):
        url = "https://api.github.com/rate_limit"
        data = await self._fetch_json(session, url, headers=self.headers)
        if data:
            remaining = data.get('rate', {}).get('remaining', 'unknown')
            tqdm.write(Fore.CYAN + f"🛡️ GitHub API Rate Limit Remaining: {remaining}")
            return remaining
        else:
            tqdm.write(Fore.RED + "❌ Failed to check rate limit.")
            return 0

    async def fetch_repos_of_user(self, session, username, include_forks=True):
        url = f"https://api.github.com/users/{username}/repos?per_page=100&type=all"
        data = await self._fetch_json(session, url, headers=self.headers)
        if data:
            if not include_forks:
                repos = [repo["full_name"] for repo in data if not repo.get("fork", False)]
                return repos
            else:
                return [repo["full_name"] for repo in data]
        else:
            tqdm.write(Fore.RED + f"❌ Failed to fetch repos for user {username}")
            return []

    async def fetch_file_list(self, session, repo_full_name, ref="HEAD"):
        url = f"https://api.github.com/repos/{repo_full_name}/git/trees/{ref}?recursive=1"
        data = await self._fetch_json(session, url, headers=self.headers)
        if data and "tree" in data:
            return [item["path"] for item in data.get("tree", []) if item["type"] == "blob"]
        else:
            tqdm.write(Fore.WHITE + f"∅ No files found for {repo_full_name} at {ref}")
            return []

    async def fetch_file_content(self, session, repo_full_name, file_path, ref="HEAD"):
        url = f"https://raw.githubusercontent.com/{repo_full_name}/{ref}/{file_path}"
        return await self._fetch_text(session, url)

    async def scan_file(self, session, repo_full_name, file_path, ref="HEAD"):
        content = await self.fetch_file_content(session, repo_full_name, file_path, ref)
        if content:
            matches = []
            for pattern in self.patterns:
                for match_obj in pattern["regex"].finditer(content):
                    snippet = self.create_advanced_snippet(content, match_obj, context=40)
                    matches.append({
                        "pattern_name": pattern["name"],
                        "match": match_obj.group(),
                        "line_number": content[:match_obj.start()].count("\n") + 1,
                        "snippet": snippet
                    })
            return {"file_path": file_path, "matches": matches} if matches else None
        return None

    async def scan_repository(self, repo_full_name, session, ref="HEAD"):
        files = await self.fetch_file_list(session, repo_full_name, ref=ref)
        tqdm.write(Fore.CYAN + f"📂 Found {len(files)} files in {repo_full_name} ({ref})")
        tasks = [self.scan_file(session, repo_full_name, fp, ref=ref) for fp in files]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        clean_results = [r for r in results if r and not isinstance(r, Exception)]
        return clean_results

    async def fetch_commit_list(self, session, repo_full_name, per_page=5):
        url = f"https://api.github.com/repos/{repo_full_name}/commits?per_page={per_page}"
        data = await self._fetch_json(session, url, headers=self.headers)
        if data:
            return data
        else:
            tqdm.write(Fore.RED + f"❌ Failed to fetch commits for {repo_full_name}")
            return []

    async def fetch_all_commits(self, session, repo_full_name):
        commits = []
        page = 1
        per_page = 100
        while True:
            url = f"https://api.github.com/repos/{repo_full_name}/commits?per_page={per_page}&page={page}"
            data = await self._fetch_json(session, url, headers=self.headers)
            if not data:
                break
            commits.extend(data)
            page += 1
        return commits

    async def fetch_commit_details(self, session, repo_full_name, commit_sha):
        url = f"https://api.github.com/repos/{repo_full_name}/commits/{commit_sha}"
        return await self._fetch_json(session, url, headers=self.headers)

    async def scan_file_commit(self, session, repo_full_name, file_path, commit_sha):
        content = await self.fetch_file_content(session, repo_full_name, file_path, ref=commit_sha)
        if content:
            matches = []
            for pattern in self.patterns:
                for match_obj in pattern["regex"].finditer(content):
                    snippet = self.create_advanced_snippet(content, match_obj, context=40)
                    matches.append({
                        "pattern_name": pattern["name"],
                        "match": match_obj.group(),
                        "line_number": content[:match_obj.start()].count("\n") + 1,
                        "snippet": snippet
                    })
            return {"file_path": file_path, "matches": matches} if matches else None
        return None

    async def scan_commit(self, session, repo_full_name, commit_sha, commit_url):
        commit_detail = await self.fetch_commit_details(session, repo_full_name, commit_sha)
        if not commit_detail:
            return None
        # Get commit date.
        commit_date = commit_detail.get("commit", {}).get("author", {}).get("date", "unknown")
        changed_files = commit_detail.get("files", [])
        if changed_files:
            file_list = [f["filename"] for f in changed_files if f.get("status") != "removed"]
            if not file_list:
                return None
        else:
            tree_sha = commit_detail.get("commit", {}).get("tree", {}).get("sha")
            if not tree_sha:
                tqdm.write(Fore.RED + f"❌ Could not get tree SHA for commit {commit_sha} in {repo_full_name}")
                return None
            tree_url = f"https://api.github.com/repos/{repo_full_name}/git/trees/{tree_sha}?recursive=1"
            data = await self._fetch_json(session, tree_url, headers=self.headers)
            if data:
                file_list = [item["path"] for item in data.get("tree", []) if item["type"] == "blob"]
            else:
                tqdm.write(Fore.RED + f"❌ Failed to fetch file list for {repo_full_name} at commit {commit_sha}")
                return None
        tasks = [self.scan_file_commit(session, repo_full_name, fp, commit_sha) for fp in file_list]
        file_results = await asyncio.gather(*tasks, return_exceptions=True)
        results = []
        for res in file_results:
            if isinstance(res, dict) and res:
                results.append(res)
        return {"commit_date": commit_date, "results": results}

    def create_advanced_snippet(self, content, match_obj, context=40):
        start = match_obj.start()
        end = match_obj.end()
        snippet_start = max(0, start - context)
        snippet_end = min(len(content), end + context)
        prefix = "..." if snippet_start > 0 else ""
        suffix = "..." if snippet_end < len(content) else ""
        snippet = (
            Markup(prefix) +
            escape(content[snippet_start:start]) +
            Markup("<mark class='highlight'>") +
            escape(content[start:end]) +
            Markup("</mark>") +
            escape(content[end:snippet_end]) +
            Markup(suffix)
        )
        return snippet

    def generate_unified_html_report(self, all_results, output_file=None):
        """
        Generates an HTML report with various filters and formatting.
        """
        if not output_file:
            output_file = f"unified_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

        # Deduplicate commit results and ensure types.
        for repo in all_results:
            baseline = set()
            if repo.get("results") and isinstance(repo.get("results"), list):
                new_results = []
                for file in repo.get("results"):
                    if isinstance(file, dict):
                        for match in file.get("matches", []):
                            baseline.add((file["file_path"], match["pattern_name"], match["match"]))
                        new_results.append(file)
                repo["results"] = new_results

            new_commit_results = []
            if repo.get("commit_results") and isinstance(repo.get("commit_results"), list):
                for commit in repo.get("commit_results", []):
                    new_commit_files = []
                    if not commit.get("results"):
                        continue
                    for file in commit["results"]:
                        if not isinstance(file, dict):
                            continue
                        new_matches = []
                        for match in file.get("matches", []):
                            signature = (file["file_path"], match["pattern_name"], match["match"])
                            if signature not in baseline:
                                new_matches.append(match)
                                baseline.add(signature)
                        if new_matches:
                            new_commit_files.append({"file_path": file["file_path"], "matches": new_matches})
                    if new_commit_files:
                        commit["results"] = new_commit_files
                        new_commit_results.append(commit)
            repo["commit_results"] = new_commit_results

            # Determine whether a repo has secrets.
            has_head = repo.get("results") and len(repo.get("results")) > 0
            has_commit = repo.get("commit_results") and any(commit.get("results") for commit in repo.get("commit_results"))
            repo["has_secrets"] = "true" if (has_head or has_commit) else "false"

            if "head_commit_date" not in repo:
                if repo.get("commit_results") and len(repo["commit_results"]) > 0:
                    repo["head_commit_date"] = repo["commit_results"][0].get("commit_date", "unknown")
                else:
                    repo["head_commit_date"] = "unknown"
            if not repo.get("is_local"):
                if repo.get("head_commit_date") and repo["head_commit_date"] != "unknown":
                    repo["head_commit_date"] = format_commit_date(repo["head_commit_date"])
                    try:
                        repo["commit_year"] = datetime.strptime(repo["head_commit_date"], "%B %d, %Y %I:%M %p").strftime("%Y")
                    except Exception:
                        repo["commit_year"] = "unknown"
                else:
                    repo["commit_year"] = "unknown"

            if repo.get("commit_results"):
                for commit in repo.get("commit_results"):
                    if commit.get("commit_date") and commit["commit_date"] != "unknown":
                        commit["commit_date"] = format_commit_date(commit["commit_date"])

        # Build repository index grouped by username (or local folder basename).
        repo_index = {}
        for repo in all_results:
            if repo.get("is_local"):
                username = os.path.basename(repo["repo_full_name"])
            else:
                username = repo["repo_full_name"].split("/")[0]
            repo_index.setdefault(username, []).append(repo["repo_full_name"])
        repo_index = dict(sorted(repo_index.items()))

        # Gather unique patterns.
        unique_patterns = set()
        for repo in all_results:
            if repo.get("results"):
                for file in repo.get("results", []):
                    if isinstance(file, dict):
                        for m in file.get("matches", []):
                            unique_patterns.add(m["pattern_name"])
            if repo.get("commit_results"):
                for commit in repo.get("commit_results"):
                    if commit.get("results"):
                        for file in commit.get("results", []):
                            if isinstance(file, dict):
                                for m in file.get("matches", []):
                                    unique_patterns.add(m["pattern_name"])
        unique_patterns = sorted(unique_patterns)

        # Gather unique years for the multi-select filter.
        years = set()
        for repo in all_results:
            if repo.get("commit_year") and repo["commit_year"] != "unknown":
                years.add(repo["commit_year"])
        unique_years = sorted(years)

        template_str = r'''
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>GitLeaks Secret Report</title>
          <style>
            :root {
              --bg-color: #121212;
              --text-color: #e0e0e0;
              --table-bg: #1e1e1e;
              --header-bg: #333;
              --header-text: #fff;
              --border-color: #444;
              --link-color: #66ccff;
              --panel-bg: #1e1e1e;
              --filter-bg: #1e1e1e;
              --filter-text: #e0e0e0;
            }
            body {
              background: var(--bg-color);
              color: var(--text-color);
              font-family: 'Courier New', monospace;
              margin: 20px;
              margin-left: 270px;
              transition: margin-left 0.3s ease;
            }
            body.panel-hidden { margin-left: 20px; }
            header {
              text-align: center;
              font-weight: bold;
              font-size: 1.8rem;
              padding: 10px 0;
              background: var(--header-bg);
              color: var(--header-text);
              position: relative;
            }
            #toggleButton {
              position: absolute;
              left: 10px;
              top: 10px;
              cursor: pointer;
              background: var(--header-bg);
              border: none;
              font-size: 1.8rem;
              color: var(--header-text);
              padding: 5px 10px;
              border-radius: 4px;
              z-index: 1000;
            }
            #mainSearchContainer {
              position: absolute;
              right: 10px;
              top: 10px;
            }
            #searchInput {
              width: 200px;
              padding: 5px;
              border: 1px solid var(--border-color);
              border-radius: 4px;
              background: var(--filter-bg);
              color: var(--filter-text);
            }
            #themeToggle {
              background: var(--filter-bg);
              color: var(--filter-text);
              border: 1px solid var(--border-color);
              border-radius: 4px;
              margin-left: 5px;
              padding: 2px;
            }
            #repo-index {
              position: fixed;
              top: 0;
              left: 0;
              width: 250px;
              height: 100%;
              overflow-y: auto;
              background: var(--panel-bg);
              border-right: 2px solid var(--border-color);
              padding: 15px;
              box-shadow: 2px 0 8px rgba(0,0,0,0.3);
              transition: transform 0.3s ease;
            }
            #repo-index.hidden { transform: translateX(-260px); }
            #repo-index h3 { border-bottom: 1px solid var(--border-color); padding-bottom: 8px; margin-bottom: 15px; }
            .user-block h4 {
              cursor: pointer;
              margin: 10px 0 5px;
              white-space: nowrap;
              overflow: hidden;
              text-overflow: ellipsis;
            }
            .user-block ul { list-style: none; padding-left: 15px; margin-bottom: 15px; }
            .user-block li {
              margin: 5px 0;
              white-space: nowrap;
              overflow: hidden;
              text-overflow: ellipsis;
            }
            #indexSearchContainer { margin-bottom: 20px; }
            #indexSearchInput {
              width: 100%;
              padding: 5px;
              border: 1px solid var(--border-color);
              border-radius: 4px;
              background: var(--filter-bg);
              color: var(--filter-text);
            }
            .filter-fieldset {
              display: block;
              margin-bottom: 20px;
              padding: 10px;
              border: 1px solid var(--border-color);
              border-radius: 5px;
              background-color: var(--table-bg);
            }
            .filter-fieldset legend { font-size: 1rem; color: var(--header-text); padding: 0 5px; }
            .filter-fieldset label {
              display: block;
              margin-bottom: 5px;
              white-space: nowrap;
              overflow: hidden;
              text-overflow: ellipsis;
            }
            table {
              width: 100%;
              border-collapse: collapse;
              margin-bottom: 40px;
              background: var(--table-bg);
            }
            th, td {
              border: 1px solid var(--border-color);
              padding: 8px;
              text-align: left;
            }
            th { background-color: var(--header-bg); color: var(--header-text); }
            tr:hover { background-color: #2a2a2a; }
            a { text-decoration: none; color: var(--link-color); }
            a:hover { text-decoration: underline; }
            .repository-section {
              border: 2px solid var(--border-color);
              padding: 15px;
              margin-bottom: 30px;
              border-radius: 8px;
            }
            .hidden { display: none; }
            mark.highlight {
              background-color: #FFD700;
              color: #000;
              font-weight: bold;
              padding: 0 2px;
              border-radius: 3px;
            }
            .old-commit-secrets { margin-bottom: 20px; }
            .warning-text {
              color: #FF0000;
            }
            body.white-theme {
              --bg-color: #ffffff;
              --text-color: #000000;
              --table-bg: #f9f9f9;
              --header-bg: #ccc;
              --header-text: #000000;
              --border-color: #bbb;
              --link-color: #0066cc;
              --panel-bg: #f1f1f1;
              --filter-bg: #eee;
              --filter-text: #000000;
            }
          </style>
          <script>
            function toggleRepoIndex() {
              var repoIndex = document.getElementById("repo-index");
              repoIndex.classList.toggle("hidden");
              document.body.classList.toggle("panel-hidden");
            }
            function toggleUserRepos(username) {
              var list = document.getElementById("repos_" + username);
              if (list.style.display === "none") {
                list.style.display = "block";
              } else {
                list.style.display = "none";
              }
            }
            function indexSearchKeyup() {
              var input = document.getElementById("indexSearchInput").value.toLowerCase();
              var userBlocks = document.getElementsByClassName("user-block");
              for (var i = 0; i < userBlocks.length; i++) {
                var username = userBlocks[i].getAttribute("data-username").toLowerCase();
                var repos = userBlocks[i].getElementsByTagName("li");
                var matchUser = username.indexOf(input) > -1;
                var hasMatch = matchUser;
                for (var j = 0; j < repos.length; j++) {
                  if (repos[j].textContent.toLowerCase().indexOf(input) > -1) {
                    repos[j].style.display = "list-item";
                    hasMatch = true;
                  } else {
                    repos[j].style.display = "none";
                  }
                }
                userBlocks[i].style.display = hasMatch ? "block" : "none";
              }
            }
            function updateFilters() {
              updateResultsFilters();
              updateRepositorySections();
            }
            function updatePatternCheckboxes(event) {
              if (event.target.id === "hideAllPatterns") {
                if (event.target.checked) {
                  var patternCheckboxes = document.querySelectorAll(".pattern-checkbox");
                  patternCheckboxes.forEach(function(cb) {
                    cb.checked = false;
                  });
                }
              } else {
                if (event.target.checked && document.getElementById("hideAllPatterns").checked) {
                  document.getElementById("hideAllPatterns").checked = false;
                }
              }
              updateFilters();
            }
            function updateResultsFilters() {
              var mainSearch = document.getElementById("searchInput").value.toLowerCase();
              var hideAll = document.getElementById("hideAllPatterns").checked;
              var patternCheckboxes = document.querySelectorAll(".pattern-checkbox");
              var activePatterns = [];
              for (var i = 0; i < patternCheckboxes.length; i++) {
                if (patternCheckboxes[i].checked) {
                  activePatterns.push(patternCheckboxes[i].value.toLowerCase());
                }
              }
              var rows = document.getElementsByClassName("dataRow");
              for (var j = 0; j < rows.length; j++) {
                var rowText = rows[j].textContent.toLowerCase();
                var pattern = rows[j].getAttribute("data-pattern").toLowerCase();
                var matchesSearch = (rowText.indexOf(mainSearch) !== -1);
                if (activePatterns.length > 0) {
                  if (activePatterns.indexOf(pattern) > -1 && matchesSearch) {
                    rows[j].style.display = "";
                  } else {
                    rows[j].style.display = "none";
                  }
                } else {
                  if (hideAll) {
                    rows[j].style.display = "none";
                  } else {
                    rows[j].style.display = matchesSearch ? "" : "none";
                  }
                }
              }
            }
            function updateRepositorySections() {
              var yearCheckboxes = document.querySelectorAll(".year-checkbox");
              var activeYears = [];
              for (var i = 0; i < yearCheckboxes.length; i++) {
                if (yearCheckboxes[i].checked) {
                  activeYears.push(yearCheckboxes[i].value);
                }
              }
              var hideNoSecrets = document.getElementById("hideNoSecrets").checked;
              var repoSections = document.getElementsByClassName("repository-section");
              for (var i = 0; i < repoSections.length; i++) {
                var repo = repoSections[i];
                var repoYear = repo.getAttribute("data-year");
                var yearMatch = activeYears.indexOf(repoYear) > -1;
                var secretRows = repo.querySelectorAll(".dataRow");
                var visibleSecretExists = false;
                for (var j = 0; j < secretRows.length; j++) {
                  if (secretRows[j].style.display !== "none") {
                    visibleSecretExists = true;
                    break;
                  }
                }
                var hasSecrets = repo.getAttribute("data-has-secrets") === "true";
                if (hasSecrets) {
                  if (yearMatch && visibleSecretExists) {
                    repo.style.display = "";
                  } else {
                    repo.style.display = "none";
                  }
                } else {
                  repo.style.display = hideNoSecrets ? "none" : "";
                }
              }
            }
            function switchCommit(repoId, version) {
              var containers = document.querySelectorAll("[id^='repoOutput_" + repoId + "_']");
              for (var i = 0; i < containers.length; i++) {
                containers[i].classList.add("hidden");
              }
              var selected = document.getElementById("repoOutput_" + repoId + "_" + version);
              if (selected) selected.classList.remove("hidden");
              var selectElem = document.getElementById("commitSelect_" + repoId);
              var selectedOption = selectElem.options[selectElem.selectedIndex];
              var commitDate = selectedOption.getAttribute("data-commit-date") || "unknown";
              document.getElementById("commitDate_" + repoId).textContent = commitDate;
            }
            function toggleTheme() {
              var select = document.getElementById("themeToggle");
              if (select.value === "white") {
                document.body.classList.add("white-theme");
              } else {
                document.body.classList.remove("white-theme");
              }
            }
            window.onload = function() {
              document.getElementById("searchInput").addEventListener("keyup", updateFilters);
              document.getElementById("indexSearchInput").addEventListener("keyup", indexSearchKeyup);
              var patternCbs = document.querySelectorAll(".pattern-checkbox, #hideAllPatterns");
              for (var i = 0; i < patternCbs.length; i++) {
                patternCbs[i].addEventListener("change", updatePatternCheckboxes);
              }
              var yearCbs = document.querySelectorAll(".year-checkbox");
              for (var i = 0; i < yearCbs.length; i++) {
                yearCbs[i].addEventListener("change", updateFilters);
              }
              document.getElementById("hideNoSecrets").addEventListener("change", updateFilters);
              updateFilters();
            };
          </script>
        </head>
        <body>
          <header>
            GitLeaks Secret Report
            <button id="toggleButton" onclick="toggleRepoIndex()">☰</button>
            <div id="mainSearchContainer">
              <input type="text" id="searchInput" placeholder="Search results...">
              <select id="themeToggle" onchange="toggleTheme()">
                <option value="dark" selected>Dark</option>
                <option value="white">White</option>
              </select>
            </div>
          </header>
          <div id="repo-index">
            <div id="indexSearchContainer">
              <input type="text" id="indexSearchInput" placeholder="Search index...">
            </div>
            <h3>Repository Index</h3>
            {% for username, repos in repo_index.items() %}
              <div class="user-block" data-username="{{ username }}">
                <h4 onclick="toggleUserRepos('{{ username|replace(' ', '_') }}')">
                  {{ username }} &#9660;
                </h4>
                <ul id="repos_{{ username|replace(' ', '_') }}">
                  {% for repo in repos %}
                    <li><a href="#{{ repo|replace('/', '_') }}" title="{{ repo }}">{{ repo }}</a></li>
                  {% endfor %}
                </ul>
              </div>
            {% endfor %}
            <fieldset class="filter-fieldset">
              <legend>Patterns</legend>
              <label><input type="checkbox" id="hideAllPatterns" checked> Hide All Patterns</label>
              {% for pattern in unique_patterns %}
                <label><input type="checkbox" class="pattern-checkbox" value="{{ pattern }}"> {{ pattern }}</label>
              {% endfor %}
            </fieldset>
            <fieldset class="filter-fieldset">
              <legend>Filter by Year</legend>
              {% for year in unique_years %}
                <label><input type="checkbox" class="year-checkbox" value="{{ year }}" checked> {{ year }}</label>
              {% endfor %}
            </fieldset>
            <fieldset class="filter-fieldset">
              <legend>Repository Filter</legend>
              <label><input type="checkbox" id="hideNoSecrets" checked onchange="updateFilters()"> Hide repositories with no secrets</label>
            </fieldset>
          </div>
          <div style="margin-top:20px;">
            {% for repo in repos %}
              {% set safe_repo = repo.repo_full_name|replace("/", "_") %}
              <div class="repository-section" id="{{ safe_repo }}" data-has-secrets="{{ repo.has_secrets }}" data-year="{{ repo.commit_year }}">
                <h2>
                  <span id="toggleRepo_{{ safe_repo }}" style="cursor:pointer;" onclick="toggleRepoDetails('{{ safe_repo }}')">[-]</span>
                  📁 <a href="{% if not repo.is_local %}https://github.com/{{ repo.repo_full_name }}{% endif %}" target="_blank" title="{{ repo.repo_full_name }}">
                    {{ repo.repo_full_name }}
                  </a>
                </h2>
                <div id="repoDetails_{{ safe_repo }}">
                  <div style="margin-bottom:10px;">
                    <label for="commitSelect_{{ safe_repo }}">Select Version:</label>
                    <select id="commitSelect_{{ safe_repo }}" onchange="switchCommit('{{ safe_repo }}', this.value)">
                      <option value="HEAD" data-commit-date="{{ repo.head_commit_date|default('unknown') }}">HEAD</option>
                      {% for commit in repo.commit_results %}
                        <option value="{{ commit.commit_id }}" data-commit-date="{{ commit.commit_date }}" {% if commit.results %} style="background-color: #FF0000; color: #FFFFFF;" {% endif %}>
                          {{ commit.commit_id }}{% if commit.results %} (Secrets in old commit){% endif %}
                        </option>
                      {% endfor %}
                    </select>
                  </div>
                  <p id="commitDateDisplay_{{ safe_repo }}">Commit Date: <span id="commitDate_{{ safe_repo }}">{{ repo.head_commit_date|default('unknown') }}</span></p>
                  {% if repo.commit_results and (repo.commit_results|selectattr("results")|list|length > 0) %}
                  <div class="old-commit-secrets">
                    <h3 class="warning-text">Secrets in old commits detected.</h3>
                  </div>
                  {% endif %}
                  <div id="repoOutput_{{ safe_repo }}_HEAD">
                    {% if repo.results %}
                      <table>
                        <tr>
                          <th>📄 File Path</th>
                          <th>🔢 Line Number</th>
                          <th>🎯 Pattern Name</th>
                          <th>🧩 Snippet</th>
                        </tr>
                        {% for file in repo.results %}
                          {% for match in file.matches %}
                            <tr class="dataRow" data-pattern="{{ match.pattern_name }}">
                              <td>
                                {% if repo.is_local %}
                                  {{ file.file_path }}
                                {% else %}
                                  <a href="https://github.com/{{ repo.repo_full_name }}/blob/HEAD/{{ file.file_path }}#L{{ match.line_number }}" target="_blank">
                                    {{ file.file_path }}
                                  </a>
                                {% endif %}
                              </td>
                              <td>{{ match.line_number }}</td>
                              <td>{{ match.pattern_name }}</td>
                              <td>{{ match.snippet | safe }}</td>
                            </tr>
                          {% endfor %}
                        {% endfor %}
                      </table>
                    {% else %}
                      <p>∅ No secrets found in the latest version.</p>
                    {% endif %}
                  </div>
                  {% for commit in repo.commit_results %}
                    <div id="repoOutput_{{ safe_repo }}_{{ commit.commit_id }}" class="hidden">
                      <h4>Commit: <a href="{% if not repo.is_local %}{{ commit.commit_url }}{% endif %}" target="_blank">{{ commit.commit_id }}</a></h4>
                      <p>Commit Date: {{ commit.commit_date }}</p>
                      {% if commit.results %}
                        <table>
                          <tr>
                            <th>📄 File Path</th>
                            <th>🔢 Line Number</th>
                            <th>🎯 Pattern Name</th>
                            <th>🧩 Snippet</th>
                          </tr>
                          {% for file in commit.results %}
                            {% for match in file.matches %}
                              <tr class="dataRow" data-pattern="{{ match.pattern_name }}">
                                <td>
                                  {% if repo.is_local %}
                                    {{ file.file_path }}
                                  {% else %}
                                    <a href="https://github.com/{{ repo.repo_full_name }}/blob/{{ commit.commit_id }}/{{ file.file_path }}#L{{ match.line_number }}" target="_blank">
                                      {{ file.file_path }}
                                    </a>
                                  {% endif %}
                                </td>
                                <td>{{ match.line_number }}</td>
                                <td>{{ match.pattern_name }}</td>
                                <td>{{ match.snippet | safe }}</td>
                              </tr>
                            {% endfor %}
                          {% endfor %}
                        </table>
                      {% else %}
                        <p>∅ No new secrets found in this commit.</p>
                      {% endif %}
                    </div>
                  {% endfor %}
                </div>
              </div>
            {% endfor %}
          </div>
          <script>
            function toggleRepoDetails(repoId) {
              var details = document.getElementById("repoDetails_" + repoId);
              var toggleIndicator = document.getElementById("toggleRepo_" + repoId);
              if (details.style.display === "none") {
                details.style.display = "block";
                toggleIndicator.textContent = "[-]";
              } else {
                details.style.display = "none";
                toggleIndicator.textContent = "[+]";
              }
            }
          </script>
        </body>
        </html>
        '''
        env = Environment(loader=FileSystemLoader('.'))
        template = env.from_string(template_str)
        html_content = template.render(
            repos=all_results,
            unique_patterns=unique_patterns,
            repo_index=repo_index,
            unique_years=unique_years
        )
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        tqdm.write(Fore.GREEN + f"✅ Unified HTML report saved: {output_file}")

async def process_local_folder(folder_path, scanner):
    """
    Recursively scans the local folder and applies regex matching.
    The folder's last modified time is used as the commit date.
    """
    results = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            full_path = os.path.join(root, file)
            try:
                with open(full_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except (UnicodeDecodeError, OSError):
                tqdm.write(Fore.YELLOW + f"⚠️ Skipping binary/non-UTF8 file: {full_path}")
                continue
            file_matches = []
            for pattern in scanner.patterns:
                for match_obj in pattern["regex"].finditer(content):
                    snippet = scanner.create_advanced_snippet(content, match_obj, context=40)
                    file_matches.append({
                        "pattern_name": pattern["name"],
                        "match": match_obj.group(),
                        "line_number": content[:match_obj.start()].count("\n") + 1,
                        "snippet": snippet
                    })
            if file_matches:
                results.append({
                    "file_path": os.path.relpath(full_path, folder_path),
                    "matches": file_matches
                })
    try:
        mtime = os.path.getmtime(folder_path)
        dt = datetime.fromtimestamp(mtime)
        commit_date = dt.isoformat()
        commit_year = dt.strftime("%Y")
    except Exception:
        commit_date = "unknown"
        commit_year = "unknown"
    repo_dict = {
        "repo_full_name": folder_path,
        "results": results,
        "commit_results": [],
        "has_secrets": "true" if results else "false",
        "head_commit_date": commit_date,
        "commit_year": commit_year,
        "is_local": True
    }
    if results:
        tqdm.write(Fore.GREEN + f"✅ Secrets found in local folder: {folder_path}")
    else:
        tqdm.write(Fore.CYAN + f"ℹ️ No secrets found in local folder: {folder_path}")
    return repo_dict

async def process_repo(repo_full_name, scanner, session, include_forks=True):
    """
    Scans a single GitHub repository.
    """
    repo_dict = {"repo_full_name": repo_full_name, "results": [], "commit_results": []}
    try:
        await scanner.check_rate_limit(session)
        head_results = await scanner.scan_repository(repo_full_name, session, ref="HEAD")
        repo_dict["results"] = head_results
        if head_results:
            tqdm.write(Fore.GREEN + f"✅ Secrets found in {repo_full_name} (HEAD)")
        else:
            tqdm.write(Fore.CYAN + f"ℹ️ {repo_full_name} is empty or has no secrets (HEAD)")
        commit_list = await scanner.fetch_commit_list(session, repo_full_name, per_page=1)
        if commit_list:
            head_commit_date = commit_list[0].get("commit", {}).get("author", {}).get("date", "unknown")
            repo_dict["head_commit_date"] = head_commit_date
        else:
            repo_dict["head_commit_date"] = "unknown"
        if scanner.commit_scan_flag:
            if scanner.commit_limit is None:
                commit_list = await scanner.fetch_all_commits(session, repo_full_name)
                tqdm.write(Fore.CYAN + f"Found {len(commit_list)} commits for {repo_full_name}")
            else:
                commit_list = await scanner.fetch_commit_list(session, repo_full_name, per_page=scanner.commit_limit)
            if commit_list:
                commit_results = []
                for commit in commit_list:
                    commit_sha = commit.get("sha")
                    commit_url = commit.get("html_url")
                    tqdm.write(Fore.CYAN + f"🔍 Scanning commit {commit_sha} of {repo_full_name}")
                    commit_scan_results = await scanner.scan_commit(session, repo_full_name, commit_sha, commit_url)
                    commit_results.append({
                        "commit_id": commit_sha,
                        "commit_url": commit_url,
                        "results": commit_scan_results.get("results") if commit_scan_results and isinstance(commit_scan_results, dict) else None,
                        "commit_date": commit_scan_results.get("commit_date") if commit_scan_results and isinstance(commit_scan_results, dict) else "unknown"
                    })
                repo_dict["commit_results"] = commit_results
        return repo_dict
    except asyncio.CancelledError:
        tqdm.write(Fore.WHITE + f"⏭️ Skipping repo: {repo_full_name}")
        raise

async def main():
    try:
        parser = argparse.ArgumentParser(description="GitLeaks Async Scanner")
        parser.add_argument("--log", action="store_true", help="Enable verbose logging")
        args = parser.parse_args()

        tqdm.write(Fore.CYAN + "\nChoose Input Method:")
        tqdm.write("1. Enter a single GitHub Repo (e.g., username/repo)")
        tqdm.write("2. Enter a username (scan all their repos)")
        tqdm.write("3. Provide a file (or directory) containing list of usernames")
        tqdm.write("4. Scan a local folder (recursive)")
        choice = input("Enter choice (1, 2, 3, or 4): ").strip()

        github_required = choice in ["1", "2", "3"]
        if github_required:
            github_token = os.getenv("GITHUB_TOKEN") or input("Enter your GitHub Token: ").strip()
        else:
            github_token = "dummy-token"

        include_forks = True
        if choice in ["2", "3"]:
            fork_input = input("Include forked repositories? (y/n): ").strip().lower()
            if fork_input.startswith("n"):
                include_forks = False

        patterns_file = 'git-leaks.yaml'
        scanner = GitLeaksAsyncScanner(github_token, patterns_file)

        heartbeat_task = asyncio.create_task(heartbeat(), name="Heartbeat")

        repos = []
        local_results = []
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=100)) as session:
            if choice == "1":
                repo_full_name = input("Enter GitHub Repo (e.g., username/repo): ").strip()
                repos.append(repo_full_name)
            elif choice == "2":
                username = input("Enter GitHub Username: ").strip()
                repos = await scanner.fetch_repos_of_user(session, username, include_forks=include_forks)
            elif choice == "3":
                path_input = input("Enter path to file/directory containing usernames: ").strip()
                if not os.path.exists(path_input):
                    tqdm.write(Fore.RED + "❌ File/Directory not found.")
                    return

                global_scan_commits_choice = input("Do you want to scan older git commits for all username files? (y/n): ").strip().lower()
                if global_scan_commits_choice.startswith("y"):
                    global_commit_scan_flag = True
                    global_commits_input = input("Enter number of commits to scan (or type 'all'): ").strip().lower()
                    if global_commits_input == "all":
                        global_commit_limit = None
                    else:
                        try:
                            global_commit_limit = int(global_commits_input)
                        except ValueError:
                            tqdm.write(Fore.RED + "❌ Invalid commit count. Skipping commit scanning.")
                            global_commit_scan_flag = False
                            global_commit_limit = 0
                else:
                    global_commit_scan_flag = False
                    global_commit_limit = 0

                if os.path.isdir(path_input):
                    for txt_file in sorted(os.listdir(path_input)):
                        if txt_file.endswith('.txt'):
                            file_path = os.path.join(path_input, txt_file)
                            tqdm.write(Fore.CYAN + f"🔍 Processing usernames file: {file_path}")
                            with open(file_path, 'r', encoding='utf-8') as f:
                                usernames = [line.strip() for line in f if line.strip()]
                            repos = []
                            tasks = [scanner.fetch_repos_of_user(session, user, include_forks=include_forks) for user in usernames]
                            results_ = await asyncio.gather(*tasks)
                            for user_repos in results_:
                                repos.extend(user_repos)
                            if not repos:
                                tqdm.write(Fore.RED + f"❌ No repositories found for file: {file_path}")
                                continue
                            scanner.commit_scan_flag = global_commit_scan_flag
                            scanner.commit_limit = global_commit_limit

                            tqdm.write(Fore.CYAN + f"🔎 Total repos to scan for file {txt_file}: {len(repos)}")
                            repo_tasks = []
                            for repo in repos:
                                task = asyncio.create_task(process_repo(repo, scanner, session, include_forks=include_forks))
                                task.set_name(repo)
                                repo_tasks.append(task)
                            skip_task = asyncio.create_task(wait_for_enter_or_status())
                            results = []
                            remaining_tasks = set(repo_tasks)
                            with tqdm(total=len(repo_tasks), bar_format="Progress: {n_fmt}/{total_fmt} | Elapsed: {elapsed}") as pbar:
                                while remaining_tasks:
                                    done, pending = await asyncio.wait(remaining_tasks, timeout=0.1, return_when=asyncio.FIRST_COMPLETED)
                                    for d in done:
                                        try:
                                            results.append(d.result())
                                        except asyncio.CancelledError:
                                            pass
                                    pbar.update(len(done))
                                    remaining_tasks = pending
                                    if skip_task.done() and pending:
                                        task_to_cancel = next(iter(pending))
                                        task_to_cancel.cancel()
                                        try:
                                            await task_to_cancel
                                        except asyncio.CancelledError:
                                            tqdm.write(Fore.WHITE + f"⏭️ Skipping repo: {task_to_cancel.get_name()}")
                                        pbar.update(1)
                                        remaining_tasks = remaining_tasks - {task_to_cancel}
                                        skip_task = asyncio.create_task(wait_for_enter_or_status())
                            unified_report_file = f"unified_report_{os.path.splitext(txt_file)[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                            scanner.generate_unified_html_report(results, output_file=unified_report_file)
                            tqdm.write(Fore.GREEN + f"✅ Scan completed for {txt_file}, report generated: {unified_report_file}")
                    return
                else:
                    with open(path_input, 'r', encoding='utf-8') as f:
                        usernames = [line.strip() for line in f if line.strip()]
                    tasks = [scanner.fetch_repos_of_user(session, user, include_forks=include_forks) for user in usernames]
                    results_ = await asyncio.gather(*tasks)
                    for user_repos in results_:
                        repos.extend(user_repos)
                    scanner.commit_scan_flag = global_commit_scan_flag
                    scanner.commit_limit = global_commit_limit
            elif choice == "4":
                folder_path = input("Enter local folder path: ").strip()
                repo_dict = await process_local_folder(folder_path, scanner)
                local_results.append(repo_dict)
            else:
                tqdm.write(Fore.RED + "❌ Invalid choice.")
                return

            all_repo_results = []
            if repos:
                commit_scan_flag = False
                commit_limit = 0
                scan_commits_choice = input("Do you want to scan older git commits as well? (y/n): ").strip().lower()
                if scan_commits_choice.startswith("y"):
                    commit_scan_flag = True
                    commits_input = input("Enter number of commits to scan (or type 'all'): ").strip().lower()
                    if commits_input == "all":
                        commit_limit = None
                    else:
                        try:
                            commit_limit = int(commits_input)
                        except ValueError:
                            tqdm.write(Fore.RED + "❌ Invalid commit count. Exiting.")
                            return
                scanner.commit_scan_flag = commit_scan_flag
                scanner.commit_limit = commit_limit

                tqdm.write(Fore.CYAN + f"🔎 Total repos to scan: {len(repos)}")
                repo_tasks = []
                for repo in repos:
                    task = asyncio.create_task(process_repo(repo, scanner, session, include_forks=include_forks))
                    task.set_name(repo)
                    repo_tasks.append(task)
                skip_task = asyncio.create_task(wait_for_enter_or_status())
                results = []
                remaining_tasks = set(repo_tasks)
                with tqdm(total=len(repo_tasks), bar_format="Progress: {n_fmt}/{total_fmt} | Elapsed: {elapsed}") as pbar:
                    while remaining_tasks:
                        done, pending = await asyncio.wait(remaining_tasks, timeout=0.1, return_when=asyncio.FIRST_COMPLETED)
                        for d in done:
                            try:
                                results.append(d.result())
                            except asyncio.CancelledError:
                                pass
                        pbar.update(len(done))
                        remaining_tasks = pending
                        if skip_task.done() and pending:
                            task_to_cancel = next(iter(pending))
                            task_to_cancel.cancel()
                            try:
                                await task_to_cancel
                            except asyncio.CancelledError:
                                tqdm.write(Fore.WHITE + f"⏭️ Skipping repo: {task_to_cancel.get_name()}")
                            pbar.update(1)
                            remaining_tasks = remaining_tasks - {task_to_cancel}
                            skip_task = asyncio.create_task(wait_for_enter_or_status())
                all_repo_results.extend(results)
            all_repo_results.extend(local_results)
            if not all_repo_results:
                tqdm.write(Fore.RED + "❌ No repositories or folders to scan.")
                return

            output_file = f"unified_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            scanner.generate_unified_html_report(all_repo_results, output_file=output_file)
            tqdm.write(Fore.GREEN + "✅ Scan completed.")
        heartbeat_task.cancel()
    except KeyboardInterrupt:
        tqdm.write(Fore.YELLOW + "\n⏹️ Received KeyboardInterrupt. Cancelling pending tasks...")
        for task in asyncio.all_tasks():
            task.cancel()
        await asyncio.sleep(0.1)
        tqdm.write(Fore.YELLOW + "✅ All tasks cancelled. Exiting.")

if __name__ == "__main__":
    asyncio.run(main())
