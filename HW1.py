# Homework 1 solution, updated version
import os
import sys
import time
import argparse
import requests
from collections import Counter
import csv

API_BASE = "https://api.github.com"

def get_session(token=None):
    s = requests.Session()
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "top100-github-authors-script"
    }
    if token:
        headers["Authorization"] = f"token {token}"
    s.headers.update(headers)
    return s

def check_rate_limit_from_response(resp):
    limit = resp.headers.get("X-RateLimit-Limit")
    remaining = resp.headers.get("X-RateLimit-Remaining")
    reset = resp.headers.get("X-RateLimit-Reset")
    return {
        "limit": int(limit) if limit else None,
        "remaining": int(remaining) if remaining else None,
        "reset": int(reset) if reset else None
    }

def wait_if_needed(rate):
    if rate["remaining"] is not None and rate["remaining"] <= 5:
        reset_ts = rate["reset"]
        if reset_ts:
            wait = max(0, reset_ts - int(time.time()) + 2)
            print(f"[RATE] Осталось {rate['remaining']} запросов; жду {wait}s до сброса...")
            time.sleep(wait)

def iter_pages(session, url, params=None):
    page = 1
    params = params.copy() if params else {}
    params.setdefault("per_page", 100)
    while True:
        params["page"] = page
        resp = session.get(url, params=params)
        if resp.status_code == 202:
            print(f"[INFO] 202 Accepted for {url} page {page}. retrying after 1s...")
            time.sleep(1)
            continue
        if resp.status_code == 409:
            return
        if resp.status_code != 200:
            print(f"[ERROR] HTTP {resp.status_code} for {url} page {page}: {resp.text[:200]}", file=sys.stderr)
            return
        data = resp.json()
        if not isinstance(data, list):
            return
        if not data:
            break
        yield from data
        if len(data) < params["per_page"]:
            break
        page += 1

def fetch_org_repos(session, org, max_repos=None):
    url = f"{API_BASE}/orgs/{org}/repos"
    repos = []
    for r in iter_pages(session, url, params={"type": "all", "per_page": 100}):
        repos.append(r)
        if max_repos and len(repos) >= max_repos:
            break
    return repos

def normalize_email_from_commit(commit_obj):
    commit = commit_obj.get("commit") or {}
    author_info = commit.get("author") or {}
    email = author_info.get("email")
    if email:
        return email.lower()
    gh_author = commit_obj.get("author")
    if gh_author and gh_author.get("login"):
        return f"{gh_author['login']}@users.noreply.github.com".lower()
    committer = commit.get("committer") or {}
    email2 = committer.get("email")
    if email2:
        return email2.lower()
    return None

def is_merge_commit(commit_obj):
    msg = (commit_obj.get("commit") or {}).get("message") or ""
    return msg.startswith("Merge pull request #")

def count_commits_for_repo(session, owner, repo_name, counter):
    url = f"{API_BASE}/repos/{owner}/{repo_name}/commits"
    params = {"per_page": 100}
    count = 0
    for commit in iter_pages(session, url, params=params):
        if is_merge_commit(commit):
            continue
        email = normalize_email_from_commit(commit)
        if email:
            counter[email] += 1
            count += 1
        else:
            counter["<unknown>"] += 1
            count += 1
    return count

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--org", required=True, help="GitHub organization (e.g. netflix)")
    p.add_argument("--out", default="top100.csv", help="CSV output filename")
    p.add_argument("--token", default=None, help="GitHub token (or set GITHUB_TOKEN env var)")
    p.add_argument("--max-repos", type=int, default=None, help="Limit number of repos (for testing)")
    p.add_argument("--skip-forks", action="store_true", help="Skip forked repos")
    args = p.parse_args()

    token = args.token or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("[WARN] Токен не задан. Без токена у вас будет 60 запросов/час. Рекомендуется задать GITHUB_TOKEN.", file=sys.stderr)

    session = get_session(token)
    print(f"[INFO] Получаю список репозиториев организации '{args.org}' ...")
    repos = fetch_org_repos(session, args.org, max_repos=args.max_repos)
    print(f"[INFO] Найдено репозиториев: {len(repos)}")
    counter = Counter()
    total_commits = 0
    repo_index = 0

    for repo in repos:
        repo_index += 1
        repo_name = repo.get("name")
        fork = repo.get("fork", False)
        if args.skip_forks and fork:
            print(f"[SKIP] {repo_name} (fork)")
            continue
        print(f"[{repo_index}/{len(repos)}] Обрабатываю репозиторий: {repo_name} ...")
        try:
            c = count_commits_for_repo(session, args.org, repo_name, counter)
            total_commits += c
            print(f"   commits counted (non-merge) in repo '{repo_name}': {c}  (cumulative {total_commits})")
        except Exception as e:
            print(f"[ERROR] Ошибка при обработке {repo_name}: {e}", file=sys.stderr)
        try:
            rl = session.get(f"{API_BASE}/rate_limit")
            if rl.status_code == 200:
                info = rl.json()
                remaining = info.get("rate", {}).get("remaining")
                limit = info.get("rate", {}).get("limit")
                reset = info.get("rate", {}).get("reset")
                print(f"   [RATE] remaining {remaining}/{limit}, reset at {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(reset))}")
                if remaining is not None and remaining <= 5:
                    wait_sec = max(0, reset - int(time.time()) + 2)
                    print(f"   [RATE] мало оставшихся запросов ({remaining}). Жду {wait_sec}s...")
                    time.sleep(wait_sec)
        except Exception:
            pass

    print(f"[DONE] Всего подсчитанных (non-merge) коммитов: {total_commits}")
    items = counter.most_common(200)
    top100 = items[:100]

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["rank", "email", "commits"])
        for i, (email, cnt) in enumerate(top100, start=1):
            writer.writerow([i, email, cnt])

    print(f"[RESULT] Топ-{len(top100)} сохранён в {args.out}")
    for i, (email, cnt) in enumerate(top100, start=1):
        print(f"{i:3}. {email:40} {cnt}")

if __name__ == "__main__":
    main()
