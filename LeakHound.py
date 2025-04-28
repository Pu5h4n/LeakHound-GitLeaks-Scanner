import os
import re
import yaml
import asyncio
import aiohttp
from jinja2 import Environment, FileSystemLoader
from colorama import init, Fore, Style

init(autoreset=True)

class GitLeaksAsyncScanner:
    def __init__(self, github_token, patterns_file='git-leaks.yaml', concurrency=10):
        self.github_token = github_token
        self.headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        self.semaphore = asyncio.Semaphore(concurrency)
        self.patterns = self.load_patterns(patterns_file)

    def load_patterns(self, patterns_file):
        try:
            with open(patterns_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
        except Exception as e:
            print(Fore.RED + f"❌ Error loading patterns file: {e}")
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
                    print(Fore.YELLOW + f"⚠️ Invalid regex ({name}): {err}")
                    continue
        print(Fore.GREEN + f"✅ Loaded {len(patterns)} patterns from {patterns_file}")
        return patterns

    async def check_rate_limit(self, session):
        url = "https://api.github.com/rate_limit"
        async with self.semaphore:
            async with session.get(url, headers=self.headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    remaining = data['rate']['remaining']
                    print(Fore.CYAN + f"🛡️ GitHub API Rate Limit Remaining: {remaining}")
                    return remaining
                else:
                    print(Fore.RED + f"❌ Failed to check rate limit: {resp.status}")
                    return 0

    async def fetch_repos_of_user(self, session, username):
        url = f"https://api.github.com/users/{username}/repos?per_page=100&type=all"
        async with self.semaphore:
            async with session.get(url, headers=self.headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    repos = [repo['full_name'] for repo in data]
                    return repos
                else:
                    print(Fore.RED + f"❌ Failed to fetch repos for user {username}: {resp.status}")
                    return []

    async def fetch_file_list(self, session, repo_full_name, ref="HEAD"):
        url = f"https://api.github.com/repos/{repo_full_name}/git/trees/{ref}?recursive=1"
        async with self.semaphore:
            async with session.get(url, headers=self.headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return [item['path'] for item in data.get('tree', []) if item['type'] == 'blob']
                else:
                    print(Fore.RED + f"❌ Failed to fetch file list for {repo_full_name} at {ref}: {resp.status}")
                    return []

    async def fetch_file_content(self, session, repo_full_name, file_path, ref="HEAD"):
        url = f"https://raw.githubusercontent.com/{repo_full_name}/{ref}/{file_path}"
        async with self.semaphore:
            async with session.get(url) as resp:
                if resp.status == 200:
                    try:
                        return await resp.text()
                    except UnicodeDecodeError:
                        print(Fore.YELLOW + f"⚠️ Skipping binary or non-UTF-8 file: {file_path}")
                        return None
                else:
                    return None

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

    async def scan_repository(self, repo_full_name):
        async with aiohttp.ClientSession() as session:
            await self.check_rate_limit(session)
            file_list = await self.fetch_file_list(session, repo_full_name, ref="HEAD")
            print(Fore.CYAN + f"📂 Found {len(file_list)} files in {repo_full_name} (HEAD)")
            tasks = [self.scan_file(session, repo_full_name, file_path, ref="HEAD") for file_path in file_list]
            results = await asyncio.gather(*tasks)
            return [result for result in results if result]

    # ---- Commit Scanning Methods ----

    async def fetch_commit_list(self, session, repo_full_name, per_page=5):
        url = f"https://api.github.com/repos/{repo_full_name}/commits?per_page={per_page}"
        async with self.semaphore:
            async with session.get(url, headers=self.headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data  # List of commit objects
                else:
                    print(Fore.RED + f"❌ Failed to fetch commits for {repo_full_name}: {resp.status}")
                    return []

    async def fetch_all_commits(self, session, repo_full_name):
        commits = []
        page = 1
        per_page = 100
        while True:
            url = f"https://api.github.com/repos/{repo_full_name}/commits?per_page={per_page}&page={page}"
            async with self.semaphore:
                async with session.get(url, headers=self.headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if not data:
                            break
                        commits.extend(data)
                        page += 1
                    else:
                        print(Fore.RED + f"❌ Failed to fetch commits for {repo_full_name} on page {page}: {resp.status}")
                        break
        return commits

    async def fetch_commit_details(self, session, repo_full_name, commit_sha):
        url = f"https://api.github.com/repos/{repo_full_name}/commits/{commit_sha}"
        async with self.semaphore:
            async with session.get(url, headers=self.headers) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    print(Fore.RED + f"❌ Failed to fetch commit details for {commit_sha} in {repo_full_name}: {resp.status}")
                    return None

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
        # Only scan changed (non-removed) files if available
        changed_files = commit_detail.get("files", [])
        if changed_files:
            file_list = [f["filename"] for f in changed_files if f.get("status") != "removed"]
            if not file_list:
                return None
        else:
            # fallback: scan entire tree using tree SHA
            tree_sha = commit_detail.get('commit', {}).get('tree', {}).get("sha")
            if not tree_sha:
                print(Fore.RED + f"❌ Could not get tree SHA for commit {commit_sha} in {repo_full_name}")
                return None
            tree_url = f"https://api.github.com/repos/{repo_full_name}/git/trees/{tree_sha}?recursive=1"
            async with self.semaphore:
                async with session.get(tree_url, headers=self.headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        file_list = [item['path'] for item in data.get('tree', []) if item['type'] == 'blob']
                    else:
                        print(Fore.RED + f"❌ Failed to fetch file list for {repo_full_name} at commit {commit_sha}: {resp.status}")
                        return None
        tasks = [self.scan_file_commit(session, repo_full_name, file_path, commit_sha) for file_path in file_list]
        file_results = await asyncio.gather(*tasks)
        results = [res for res in file_results if res]
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
        Generates a dark/light-themed unified HTML report with:
         - A theme toggle at the top.
         - For each repository, a dropdown to select the version (HEAD or a commit).
         - Only the selected version’s table is shown.
         - Commit scan results are deduplicated against HEAD and more recent commits.
        """
        # ----------------------
        # Deduplicate commit results:
        #
        # For each repository, use HEAD issues (if any) as baseline.
        # Then, for each commit (assumed in descending order) filter out matches already seen.
        # A match is defined by (file_path, pattern_name, match_text).
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

        # ----------------------
        # HTML Template with theme toggle and commit selection dropdown:
        template_str = '''
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
              --border-color: #333;
              --link-color: #66ccff;
              --filter-bg: #333;
              --filter-text: #e0e0e0;
            }
            body {
              background: var(--bg-color);
              color: var(--text-color);
              font-family: 'Courier New', monospace;
              margin: 20px;
            }
            table {
              width: 100%;
              border-collapse: collapse;
              margin-bottom: 40px;
              background: var(--table-bg);
            }
            th, td { border: 1px solid var(--border-color); padding: 8px; text-align: left; }
            th { background-color: var(--header-bg); color: var(--header-text); }
            tr:hover { background-color: #2a2a2a; }
            .pattern-highlight { background-color: #ffcc00; color: black; font-weight: bold; }
            .filter-section input[type="text"] { background: var(--filter-bg); color: var(--filter-text); border: 1px solid #555; padding: 5px; width: 300px; }
            a { text-decoration: none; color: var(--link-color); }
            a:hover { text-decoration: underline; }
            .repository-section { border: 2px solid var(--border-color); padding: 15px; margin-bottom: 30px; border-radius: 8px; }
            .hidden { display: none; }
            /* White theme overrides */
            body.white-theme {
              --bg-color: #ffffff;
              --text-color: #000000;
              --table-bg: #f9f9f9;
              --header-bg: #ccc;
              --header-text: #000000;
              --border-color: #bbb;
              --link-color: #0066cc;
              --filter-bg: #eee;
              --filter-text: #000000;
            }
          </style>
          <script>
            function toggleTheme() {
              var select = document.getElementById("themeToggle");
              if(select.value === "white") {
                document.body.classList.add("white-theme");
              } else {
                document.body.classList.remove("white-theme");
              }
            }
            // Switch the commit container for a repository.
            function switchCommit(repoId, version) {
              var containers = document.querySelectorAll("[id^='repoOutput_" + repoId + "_']");
              for(var i = 0; i < containers.length; i++){
                containers[i].classList.add("hidden");
              }
              var selected = document.getElementById("repoOutput_" + repoId + "_" + version);
              if(selected) { selected.classList.remove("hidden"); }
            }
          </script>
        </head>
        <body>
          <div style="margin-bottom: 20px;">
            Theme: 
            <select id="themeToggle" onchange="toggleTheme()">
              <option value="dark" selected>Dark</option>
              <option value="white">White</option>
            </select>
          </div>
          <div class="filter-section">
            <input type="text" id="searchInput" placeholder="Search all results...">
            <div>
              <strong>Hide Patterns:</strong>
              {% for pattern in unique_patterns %}
                <label>
                  <input type="checkbox" class="pattern-checkbox" value="{{ pattern|e }}"> {{ pattern }}
                </label>
              {% endfor %}
            </div>
          </div>
          {% for repo in repos %}
            {% set safe_repo = repo.repo_full_name|replace("/", "_") %}
            <div class="repository-section">
              <h2>📁 <a href="https://github.com/{{ repo.repo_full_name }}" target="_blank">{{ repo.repo_full_name }}</a></h2>
              <div style="margin-bottom:10px;">
                <label for="commitSelect_{{ safe_repo }}">Select Version:</label>
                <select id="commitSelect_{{ safe_repo }}" onchange="switchCommit('{{ safe_repo }}', this.value)">
                  <option value="HEAD" selected>HEAD</option>
                  {% for commit in repo.commit_results %}
                    <option value="{{ commit.commit_id }}">{{ commit.commit_id }}</option>
                  {% endfor %}
                </select>
              </div>
              <!-- HEAD container -->
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
                  <p>No secrets found in the latest version.</p>
                {% endif %}
              </div>
              <!-- Commit containers -->
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
                    <p>No new secrets found in this commit.</p>
                  {% endif %}
                </div>
              {% endfor %}
            </div>
          {% endfor %}
          <script>
            // Filtering based on the search input and pattern checkboxes.
            function applyFilters() {
              var searchInput = document.getElementById("searchInput");
              var searchFilter = searchInput.value.toLowerCase();
              var hidePatterns = [];
              var checkboxes = document.getElementsByClassName("pattern-checkbox");
              for (var i = 0; i < checkboxes.length; i++) {
                  if (checkboxes[i].checked) {
                      hidePatterns.push(checkboxes[i].value.toLowerCase());
                  }
              }
              var rows = document.getElementsByClassName("dataRow");
              for (var i = 0; i < rows.length; i++) {
                  var rowText = rows[i].textContent.toLowerCase();
                  var pattern = rows[i].getAttribute("data-pattern").toLowerCase();
                  if (rowText.indexOf(searchFilter) > -1 && hidePatterns.indexOf(pattern) === -1) {
                      rows[i].style.display = "";
                  } else {
                      rows[i].style.display = "none";
                  }
              }
            }
            window.onload = function() {
              document.getElementById("searchInput").addEventListener("keyup", applyFilters);
              var checkboxes = document.getElementsByClassName("pattern-checkbox");
              for (var i = 0; i < checkboxes.length; i++) {
                  checkboxes[i].addEventListener("change", applyFilters);
              }
            };
          </script>
        </body>
        </html>
        '''
        # Collect unique pattern names from both HEAD and commit results
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
        env = Environment(loader=FileSystemLoader('.'))
        template = env.from_string(template_str)
        html_content = template.render(repos=all_results, unique_patterns=unique_patterns)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(Fore.GREEN + f"✅ Unified HTML report saved: {output_file}")

# ----------------- Runner -----------------

async def main():
    github_token = os.getenv("GITHUB_TOKEN") or input("Enter your GitHub Token: ").strip()
    patterns_file = 'git-leaks.yaml'
    scanner = GitLeaksAsyncScanner(github_token, patterns_file, concurrency=10)

    print(Fore.CYAN + "\nChoose Input Method:")
    print("1. Enter a single GitHub Repo (e.g., username/repo)")
    print("2. Enter a username (scan all their repos)")
    print("3. Provide a file containing list of usernames")
    choice = input("Enter choice (1, 2 or 3): ").strip()

    repos = []
    async with aiohttp.ClientSession() as session:
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
                for username in usernames:
                    user_repos = await scanner.fetch_repos_of_user(session, username)
                    repos.extend(user_repos)
            else:
                print(Fore.RED + "❌ File not found.")
                return
        else:
            print(Fore.RED + "❌ Invalid choice.")
            return

    if not repos:
        print(Fore.RED + "❌ No repositories to scan.")
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
                print(Fore.RED + "❌ Invalid commit count. Exiting.")
                return

    print(Fore.CYAN + f"🔎 Total repos to scan: {len(repos)}")
    all_results = []
    # Scan HEAD for each repository:
    for repo_full_name in repos:
        print(Fore.YELLOW + f"\n🔍 Scanning {repo_full_name} (HEAD)")
        head_results = await scanner.scan_repository(repo_full_name)
        repo_dict = {
            "repo_full_name": repo_full_name,
            "results": head_results,
            "commit_results": []  # Will hold commit scan results if enabled.
        }
        if head_results:
            print(Fore.GREEN + f"✅ Secrets found in {repo_full_name} (HEAD)")
        else:
            print(Fore.MAGENTA + f"❌ No secrets found in {repo_full_name} (HEAD)")

        # If commit scanning was chosen, scan commit versions.
        if commit_scan_flag:
            async with aiohttp.ClientSession() as commit_session:
                if commit_limit is None:
                    commit_list = await scanner.fetch_all_commits(commit_session, repo_full_name)
                else:
                    commit_list = await scanner.fetch_commit_list(commit_session, repo_full_name, per_page=commit_limit)
                commit_results = []
                for commit in commit_list:
                    commit_sha = commit.get("sha")
                    commit_url = commit.get("html_url")
                    print(Fore.YELLOW + f"🔍 Scanning commit {commit_sha} of {repo_full_name}")
                    commit_scan_results = await scanner.scan_commit(commit_session, repo_full_name, commit_sha, commit_url)
                    commit_results.append({
                        "commit_id": commit_sha,
                        "commit_url": commit_url,
                        "results": commit_scan_results
                    })
                    if commit_scan_results:
                        print(Fore.GREEN + f"✅ Secrets found in commit {commit_sha}")
                    else:
                        print(Fore.MAGENTA + f"❌ No secrets found in commit {commit_sha}")
                repo_dict["commit_results"] = commit_results
        all_results.append(repo_dict)

    output_file = 'unified_report.html'
    scanner.generate_unified_html_report(all_results, output_file=output_file)

if __name__ == "__main__":
    asyncio.run(main())
