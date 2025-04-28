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

# Initialize Colorama for colored terminal output.
init(autoreset=True)

def log(message):
    # Log everything via tqdm.write.
    tqdm.write(message)

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
            name = pattern_block.get('name', 'Unknown')
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
            async with self.semaphore:
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 409:
                        # Log a neutral info message in white for empty/conflict repos.
                        tqdm.write(Fore.WHITE + f"∅ Empty or conflict (409) encountered for URL: {url}")
                        return {}
                    if resp.status == 403 and (
                        "X-RateLimit-Remaining" not in resp.headers or
                        int(resp.headers.get("X-RateLimit-Remaining", "0")) == 0):
                        tqdm.write(Fore.YELLOW + f"Rate limit reached for JSON fetch from {url}, waiting 60 seconds...")
                        await asyncio.sleep(60)
                        continue
                    if resp.status == 200:
                        return await resp.json()
                    else:
                        tqdm.write(Fore.RED + f"❌ Error fetching JSON from {url}: {resp.status}")
                        return {}

    async def _fetch_text(self, session, url, headers=None):
        headers = headers if headers is not None else {}
        while True:
            async with self.semaphore:
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 409:
                        tqdm.write(Fore.WHITE + f"∅ Empty or conflict (409) encountered for URL: {url}")
                        return None
                    if resp.status == 403 and (
                        "X-RateLimit-Remaining" not in resp.headers or
                        int(resp.headers.get("X-RateLimit-Remaining", "0")) == 0):
                        tqdm.write(Fore.YELLOW + f"Rate limit reached for text fetch from {url}, waiting 60 seconds...")
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

    async def fetch_repos_of_user(self, session, username):
        url = f"https://api.github.com/users/{username}/repos?per_page=100&type=all"
        data = await self._fetch_json(session, url, headers=self.headers)
        if data:
            return [repo['full_name'] for repo in data]
        else:
            tqdm.write(Fore.RED + f"❌ Failed to fetch repos for user {username}")
            return []

    async def fetch_file_list(self, session, repo_full_name, ref="HEAD"):
        url = f"https://api.github.com/repos/{repo_full_name}/git/trees/{ref}?recursive=1"
        data = await self._fetch_json(session, url, headers=self.headers)
        if data and "tree" in data:
            return [item['path'] for item in data.get('tree', []) if item['type'] == 'blob']
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
                for match_obj in pattern['regex'].finditer(content):
                    snippet = self.create_advanced_snippet(content, match_obj, context=40)
                    matches.append({
                        'pattern_name': pattern['name'],
                        'match': match_obj.group(),
                        'line_number': content[:match_obj.start()].count('\n') + 1,
                        'snippet': snippet
                    })
            return {'file_path': file_path, 'matches': matches} if matches else None
        return None

    async def scan_repository(self, repo_full_name, session, ref="HEAD"):
        files = await self.fetch_file_list(session, repo_full_name, ref=ref)
        tqdm.write(Fore.CYAN + f"📂 Found {len(files)} files in {repo_full_name} ({ref})")
        tasks = [self.scan_file(session, repo_full_name, file_path, ref=ref) for file_path in files]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        clean_results = [r for r in results if r and not isinstance(r, Exception)]
        return clean_results

    # ---- Commit Scanning Methods ----
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
                for match_obj in pattern['regex'].finditer(content):
                    snippet = self.create_advanced_snippet(content, match_obj, context=40)
                    matches.append({
                        'pattern_name': pattern['name'],
                        'match': match_obj.group(),
                        'line_number': content[:match_obj.start()].count('\n') + 1,
                        'snippet': snippet
                    })
            return {'file_path': file_path, 'matches': matches} if matches else None
        return None

    async def scan_commit(self, session, repo_full_name, commit_sha, commit_url):
        commit_detail = await self.fetch_commit_details(session, repo_full_name, commit_sha)
        if not commit_detail:
            return None
        changed_files = commit_detail.get("files", [])
        if changed_files:
            file_list = [f["filename"] for f in changed_files if f.get("status") != "removed"]
            if not file_list:
                return None
        else:
            tree_sha = commit_detail.get('commit', {}).get('tree', {}).get("sha")
            if not tree_sha:
                tqdm.write(Fore.RED + f"❌ Could not get tree SHA for commit {commit_sha} in {repo_full_name}")
                return None
            tree_url = f"https://api.github.com/repos/{repo_full_name}/git/trees/{tree_sha}?recursive=1"
            data = await self._fetch_json(session, tree_url, headers=self.headers)
            if data:
                file_list = [item['path'] for item in data.get('tree', []) if item['type'] == 'blob']
            else:
                tqdm.write(Fore.RED + f"❌ Failed to fetch file list for {repo_full_name} at commit {commit_sha}")
                return None
        tasks = [self.scan_file_commit(session, repo_full_name, file_path, commit_sha) for file_path in file_list]
        file_results = await asyncio.gather(*tasks, return_exceptions=True)
        results = [res for res in file_results if res and not isinstance(res, Exception)]
        return results

    def create_advanced_snippet(self, content, match_obj, context=40):
        start = match_obj.start()
        end = match_obj.end()
        snippet_start = max(0, start - context)
        snippet_end = min(len(content), end + context)
        prefix = "..." if snippet_start > 0 else ""
        suffix = "..." if snippet_end < len(content) else ""
        snippet = (
            prefix +
            content[snippet_start:start] +
            "<span style='background-color: #ffcc00; color: black; font-weight: bold;'>" +
            content[start:end] +
            "</span>" +
            content[end:snippet_end] +
            suffix
        )
        return snippet

    def generate_unified_html_report(self, all_results, output_file='unified_report.html'):
        """
        Generates a unified HTML report with the following features:
          - Centered, bold "GitLeaks Secret Report" in the header
          - Hamburger button at top-left
          - Index search box for user/repo filtering, automatically triggered on keyup
          - Hide Patterns / Show Only Patterns fieldsets that filter the results table
          - A main results search (top-right) that also filters
        """
        # Deduplicate commit results.
        for repo in all_results:
            baseline = set()
            if repo.get("results"):
                for file in repo["results"]:
                    for match in file.get("matches", []):
                        baseline.add((file["file_path"], match["pattern_name"], match["match"]))
            new_commit_results = []
            for commit in repo.get("commit_results", []):
                new_commit_files = []
                if not commit.get("results"):
                    continue
                for file in commit["results"]:
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

        # Build repository index grouped by username.
        repo_index = {}
        for repo in all_results:
            username = repo['repo_full_name'].split("/")[0]
            repo_index.setdefault(username, []).append(repo['repo_full_name'])
        repo_index = dict(sorted(repo_index.items()))

        # Gather unique patterns
        unique_patterns = set()
        for repo in all_results:
            if repo.get("results"):
                for file in repo["results"]:
                    for m in file.get("matches", []):
                        unique_patterns.add(m["pattern_name"])
            if repo.get("commit_results"):
                for commit in repo["commit_results"]:
                    if commit.get("results"):
                        for file in commit["results"]:
                            for m in file.get("matches", []):
                                unique_patterns.add(m["pattern_name"])
        unique_patterns = sorted(unique_patterns)

        # HTML template with final UI changes and working Hide/Show Patterns
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
            body.panel-hidden {
              margin-left: 20px;
            }
            header {
              text-align: center;
              font-weight: bold;
              font-size: 1.8rem;
              padding: 10px 0;
              background: var(--header-bg);
              color: var(--header-text);
              position: relative;
            }
            /* Hamburger stays at top-left */
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
            /* Main results search (top-right corner) */
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
            /* Repository index panel */
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
            #repo-index.hidden {
              transform: translateX(-260px);
            }
            #repo-index h3 {
              border-bottom: 1px solid var(--border-color);
              padding-bottom: 8px;
              margin-bottom: 15px;
            }
            .user-block h4 {
              cursor: pointer;
              margin: 10px 0 5px;
              white-space: nowrap;
              overflow: hidden;
              text-overflow: ellipsis;
            }
            .user-block ul {
              list-style: none;
              padding-left: 15px;
              margin-bottom: 15px;
            }
            .user-block li {
              margin: 5px 0;
              white-space: nowrap;
              overflow: hidden;
              text-overflow: ellipsis;
            }
            /* Repository index search (auto filter) */
            #indexSearchContainer {
              margin: 20px 0 20px 0;
            }
            #indexSearchInput {
              width: 100%;
              padding: 5px;
              border: 1px solid var(--border-color);
              border-radius: 4px;
              background: var(--filter-bg);
              color: var(--filter-text);
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
            th {
              background-color: var(--header-bg);
              color: var(--header-text);
            }
            tr:hover {
              background-color: #2a2a2a;
            }
            a {
              text-decoration: none;
              color: var(--link-color);
            }
            a:hover {
              text-decoration: underline;
            }
            .repository-section {
              border: 2px solid var(--border-color);
              padding: 15px;
              margin-bottom: 30px;
              border-radius: 8px;
            }
            .hidden {
              display: none;
            }
            .filter-fieldset {
              display: inline-block;
              vertical-align: top;
              margin-right: 15px;
              padding: 10px;
              border: 1px solid var(--border-color);
              border-radius: 5px;
              background-color: var(--table-bg);
              margin-top: 20px;
              width: 100%;
              box-sizing: border-box;
            }
            .filter-fieldset legend {
              font-size: 1rem;
              color: var(--header-text);
              padding: 0 5px;
            }
            .filter-fieldset label {
              display: block;
              margin-bottom: 5px;
              white-space: nowrap;
              overflow: hidden;
              text-overflow: ellipsis;
            }
            .dataRow {
              transition: background 0.2s ease;
            }
            /* Light theme overrides */
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
            /* =============== INDEX SEARCH (LEFT PANEL) =============== */
            function toggleRepoIndex() {
              var repoIndex = document.getElementById("repo-index");
              repoIndex.classList.toggle("hidden");
              document.body.classList.toggle("panel-hidden");
            }
            function toggleUserRepos(username) {
              var list = document.getElementById("repos_" + username);
              if(list.style.display === "none"){
                list.style.display = "block";
              } else {
                list.style.display = "none";
              }
            }
            function indexSearchKeyup() {
              // Called whenever user types in the left "Search index..."
              var input = document.getElementById("indexSearchInput").value.toLowerCase();
              var userBlocks = document.getElementsByClassName("user-block");
              for(var i=0; i<userBlocks.length; i++){
                var username = userBlocks[i].getAttribute("data-username").toLowerCase();
                var repos = userBlocks[i].getElementsByTagName("li");
                var matchUser = username.indexOf(input) > -1;
                var hasMatch = matchUser;
                for(var j=0; j<repos.length; j++){
                  if(repos[j].textContent.toLowerCase().indexOf(input) > -1){
                    repos[j].style.display = "list-item";
                    hasMatch = true;
                  } else {
                    repos[j].style.display = "none";
                  }
                }
                userBlocks[i].style.display = hasMatch ? "block" : "none";
              }
            }

            /* =============== MAIN RESULTS FILTERS (Hide/Show Patterns + searchInput) =============== */
            function updateResultsFilters() {
              // Grab the main search input
              var mainSearch = document.getElementById("searchInput").value.toLowerCase();

              // Grab checked hide patterns
              var hideCheck = document.querySelectorAll(".pattern-checkbox.hide:checked");
              var hidePatterns = [];
              for(var i=0; i<hideCheck.length; i++){
                hidePatterns.push(hideCheck[i].value.toLowerCase());
              }

              // Grab checked show patterns
              var showCheck = document.querySelectorAll(".pattern-checkbox.show:checked");
              var showPatterns = [];
              for(var i=0; i<showCheck.length; i++){
                showPatterns.push(showCheck[i].value.toLowerCase());
              }

              // Each row has a data-pattern attribute
              var rows = document.getElementsByClassName("dataRow");
              for(var j=0; j<rows.length; j++){
                var rowText = rows[j].textContent.toLowerCase();
                var pattern = rows[j].getAttribute("data-pattern").toLowerCase();
                // Filter logic:
                //   1) Row must match mainSearch
                //   2) pattern not in hidePatterns
                //   3) If showPatterns is non-empty, pattern must be in showPatterns
                var matchesSearch = (rowText.indexOf(mainSearch) !== -1);
                var hiddenByHideList = (hidePatterns.indexOf(pattern) !== -1);
                var forcedByShowList = (showPatterns.length === 0 || showPatterns.indexOf(pattern) !== -1);

                if(matchesSearch && !hiddenByHideList && forcedByShowList){
                  rows[j].style.display = "";
                } else {
                  rows[j].style.display = "none";
                }
              }
            }

            function toggleTheme() {
              var select = document.getElementById("themeToggle");
              if(select.value === "white") {
                document.body.classList.add("white-theme");
              } else {
                document.body.classList.remove("white-theme");
              }
            }

            function switchCommit(repoId, version) {
              var containers = document.querySelectorAll("[id^='repoOutput_" + repoId + "_']");
              for(var i=0; i<containers.length; i++){
                containers[i].classList.add("hidden");
              }
              var selected = document.getElementById("repoOutput_" + repoId + "_" + version);
              if(selected) selected.classList.remove("hidden");
            }

            window.onload = function() {
              // When user types in the main search box, update results
              document.getElementById("searchInput").addEventListener("keyup", updateResultsFilters);

              // When user types in the left "Search index" box, auto-filter the user/repo list
              document.getElementById("indexSearchInput").addEventListener("keyup", indexSearchKeyup);

              // When user toggles a hide or show checkbox, update results
              var hideCbs = document.querySelectorAll(".pattern-checkbox.hide");
              var showCbs = document.querySelectorAll(".pattern-checkbox.show");
              for(var i=0; i<hideCbs.length; i++){
                hideCbs[i].addEventListener("change", updateResultsFilters);
              }
              for(var i=0; i<showCbs.length; i++){
                showCbs[i].addEventListener("change", updateResultsFilters);
              }
            };
          </script>
        </head>
        <body>
          <!-- Header with center title & hamburger top-left -->
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

          <!-- Left panel: repository index + patterns fieldsets -->
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
                    <li>
                      <a href="#{{ repo|replace('/', '_') }}" title="{{ repo }}">
                        {{ repo }}
                      </a>
                    </li>
                  {% endfor %}
                </ul>
              </div>
            {% endfor %}
            <!-- Fieldsets for Hide/Show Patterns -->
            <fieldset class="filter-fieldset">
              <legend>Hide Patterns</legend>
              {% for pattern in unique_patterns %}
                <label>
                  <input type="checkbox" class="pattern-checkbox hide" value="{{ pattern }}"> {{ pattern }}
                </label>
              {% endfor %}
            </fieldset>
            <fieldset class="filter-fieldset">
              <legend>Show Only Patterns</legend>
              {% for pattern in unique_patterns %}
                <label>
                  <input type="checkbox" class="pattern-checkbox show" value="{{ pattern }}"> {{ pattern }}
                </label>
              {% endfor %}
            </fieldset>
          </div>

          <!-- Main content: repository results -->
          <div style="margin-top:20px;">
            {% for repo in repos %}
              {% set safe_repo = repo.repo_full_name|replace("/", "_") %}
              <div class="repository-section" id="{{ safe_repo }}">
                <h2>
                  📁 <a href="https://github.com/{{ repo.repo_full_name }}" target="_blank" title="{{ repo.repo_full_name }}">
                    {{ repo.repo_full_name }}
                  </a>
                </h2>
                <div style="margin-bottom:10px;">
                  <label for="commitSelect_{{ safe_repo }}">Select Version:</label>
                  <select id="commitSelect_{{ safe_repo }}" onchange="switchCommit('{{ safe_repo }}', this.value)">
                    <option value="HEAD" selected>HEAD</option>
                    {% for commit in repo.commit_results %}
                      <option value="{{ commit.commit_id }}">{{ commit.commit_id }}</option>
                    {% endfor %}
                  </select>
                </div>
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
                            <td>{{ file.file_path }}</td>
                            <td>
                              <a href="https://github.com/{{ repo.repo_full_name }}/blob/HEAD/{{ file.file_path }}#L{{ match.line_number }}" target="_blank">
                                {{ match.line_number }}
                              </a>
                            </td>
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
                    <h4>Commit: <a href="{{ commit.commit_url }}" target="_blank">{{ commit.commit_id }}</a></h4>
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
                              <td>{{ file.file_path }}</td>
                              <td>
                                <a href="https://github.com/{{ repo.repo_full_name }}/blob/{{ commit.commit_id }}/{{ file.file_path }}#L{{ match.line_number }}" target="_blank">
                                  {{ match.line_number }}
                                </a>
                              </td>
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
            {% endfor %}
          </div>
        </body>
        </html>
        '''

        # Build final HTML
        env = Environment(loader=FileSystemLoader('.'))
        template = env.from_string(template_str)
        html_content = template.render(
            repos=all_results,
            unique_patterns=unique_patterns,
            repo_index=repo_index
        )
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        tqdm.write(Fore.GREEN + f"✅ Unified HTML report saved: {output_file}")

async def wait_for_enter():
    """
    Asynchronously waits for the user to press Enter.
    Uses sys.stdin.readline on non-Windows.
    """
    if os.name == "nt":
        import msvcrt
        while True:
            await asyncio.sleep(0.1)
            if msvcrt.kbhit():
                ch = msvcrt.getch()
                if ch in (b'\r', b'\n'):
                    while msvcrt.kbhit():
                        msvcrt.getch()
                    return True
    else:
        loop = asyncio.get_running_loop()
        line = await loop.run_in_executor(None, sys.stdin.readline)
        return True if line.strip() == "" else False

async def process_repo(repo_full_name, scanner, session):
    """
    Scans a single repository concurrently (HEAD and optionally commits).
    If Enter is pressed during this repo's scan, cancel and skip only that repo.
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
                        "results": commit_scan_results
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

        github_token = os.getenv("GITHUB_TOKEN") or input("Enter your GitHub Token: ").strip()
        patterns_file = 'git-leaks.yaml'
        scanner = GitLeaksAsyncScanner(github_token, patterns_file)

        tqdm.write(Fore.CYAN + "\nChoose Input Method:")
        tqdm.write("1. Enter a single GitHub Repo (e.g., username/repo)")
        tqdm.write("2. Enter a username (scan all their repos)")
        tqdm.write("3. Provide a file containing list of usernames")
        choice = input("Enter choice (1, 2 or 3): ").strip()

        repos = []
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=100)) as session:
            if choice == "1":
                repo_full_name = input("Enter GitHub Repo (e.g., username/repo): ").strip()
                repos.append(repo_full_name)
            elif choice == "2":
                username = input("Enter GitHub Username: ").strip()
                repos = await scanner.fetch_repos_of_user(session, username)
            elif choice == "3":
                filepath = input("Enter path to file containing usernames: ").strip()
                if os.path.exists(filepath):
                    with open(filepath, 'r', encoding='utf-8') as f:
                        usernames = [line.strip() for line in f if line.strip()]
                    tasks = [scanner.fetch_repos_of_user(session, user) for user in usernames]
                    results_ = await asyncio.gather(*tasks)
                    for user_repos in results_:
                        repos.extend(user_repos)
                else:
                    tqdm.write(Fore.RED + "❌ File not found.")
                    return
            else:
                tqdm.write(Fore.RED + "❌ Invalid choice.")
                return

            if not repos:
                tqdm.write(Fore.RED + "❌ No repositories to scan.")
                return

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
            tqdm.write(Fore.CYAN + "Press Enter at any time to skip the *current* repo scanning.\n")

            repo_tasks = []
            for repo in repos:
                task = asyncio.create_task(process_repo(repo, scanner, session))
                task.set_name(repo)
                repo_tasks.append(task)
            skip_task = asyncio.create_task(wait_for_enter())
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
                        skip_task = asyncio.create_task(wait_for_enter())

            output_file = 'unified_report.html'
            scanner.generate_unified_html_report(results, output_file=output_file)
            tqdm.write(Fore.GREEN + "✅ Scan completed.")
    except KeyboardInterrupt:
        tqdm.write(Fore.YELLOW + "\n⏹️ Received KeyboardInterrupt. Cancelling pending tasks...")
        for task in asyncio.all_tasks():
            task.cancel()
        await asyncio.sleep(0.1)
        tqdm.write(Fore.YELLOW + "✅ All tasks cancelled. Exiting.")

if __name__ == "__main__":
    asyncio.run(main())
