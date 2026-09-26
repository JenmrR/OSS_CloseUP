#!/usr/bin/env python3
"""
GitHub 유지보수 정보 원시 수집 스크립트 (체크포인트용)

package-lock.json 의 패키지마다
  1) npm registry 에서 repository 필드와 배포 이력을 가져오고
  2) repository 값을 GitHub owner/repo 로 파싱한 뒤
  3) GitHub API 로 저장소 상태(archived, 마지막 커밋, 최신 릴리스)를 조회해
원시 JSON 으로 저장한다.

- 판정(Active / Maintenance Low / Archived / Unknown)은 하지 않는다. 그건 위험도 규칙 엔진의 몫.
- 표준 라이브러리만 사용 (pip 설치 불필요, Python 3.8+).
- 토큰은 .env 의 GITHUB_TOKEN 에서 읽고, 화면·결과 파일 어디에도 출력하지 않는다.

사용 예:
  python3 scripts/github_probe.py --selftest
  python3 scripts/github_probe.py samples/poc77/package-lock.json                # 직접 의존성 10개
  python3 scripts/github_probe.py samples/poc77/package-lock.json --all          # 전체 76개
  python3 scripts/github_probe.py samples/poc77/package-lock.json -o results/github_raw.json
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

NPM_REGISTRY = "https://registry.npmjs.org/"
GITHUB_API = "https://api.github.com"
USER_AGENT = "oss-closeup-probe"


# ---------------------------------------------------------------- repository 파서

_HOST_SHORTCUTS = {"github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org", "gist": "gist.github.com"}


def parse_repository(repo):
    """npm repository 필드(dict 또는 str)를 {host, owner, repo, form, directory} 로 바꾼다.
    GitHub 가 아니거나 해석이 안 되면 owner/repo 는 None 이고 reason 에 이유를 적는다."""
    out = {"raw": repo, "host": None, "owner": None, "repo": None, "form": None, "directory": None, "reason": None}
    if repo is None:
        out["reason"] = "repository 필드 없음"
        return out
    if isinstance(repo, dict):
        url = (repo.get("url") or "").strip()
        out["directory"] = repo.get("directory")  # 모노레포 하위 경로
    elif isinstance(repo, str):
        url = repo.strip()
    else:
        out["reason"] = "알 수 없는 repository 타입: %s" % type(repo).__name__
        return out
    if not url:
        out["reason"] = "repository.url 비어 있음"
        return out

    host = path = None
    m = re.match(r"^(github|gitlab|bitbucket|gist):(.+)$", url)            # github:user/repo
    if m:
        out["form"] = m.group(1) + ":shorthand"
        host, path = _HOST_SHORTCUTS[m.group(1)], m.group(2)
    elif re.match(r"^[\w.-]+@[\w.-]+:", url):                                # git@github.com:user/repo.git
        out["form"] = "scp-ssh"
        host, path = re.match(r"^[\w.-]+@([\w.-]+):(.+)$", url).groups()
    elif re.match(r"^[a-z0-9+.-]+://", url, re.I):                           # git+https://, git://, https://, git+ssh://
        p = urllib.parse.urlparse(url)
        out["form"] = p.scheme.lower()
        host = (p.hostname or "").lower()
        path = p.path
    elif re.match(r"^[\w.-]+/[\w.-]+$", url):                                # user/repo (npm 규칙상 GitHub)
        out["form"] = "bare-shorthand"
        host, path = "github.com", url
    else:
        out["reason"] = "해석 불가 형식"
        return out

    out["host"] = host
    if host not in ("github.com", "www.github.com"):
        out["reason"] = "GitHub 아님 (%s)" % host
        return out

    parts = [x for x in path.split("#")[0].split("?")[0].split("/") if x]
    if len(parts) < 2:
        out["reason"] = "owner/repo 경로 부족"
        return out
    owner, name = parts[0], parts[1]
    if name.endswith(".git"):
        name = name[:-4]
    out["owner"], out["repo"] = owner, name
    if len(parts) > 2 and parts[2] == "tree" and not out["directory"]:      # github.com/o/r/tree/main/packages/x
        out["directory"] = "/".join(parts[4:]) or None
    return out


def selftest():
    cases = [
        ({"type": "git", "url": "git+https://github.com/jshttp/accepts.git"}, ("jshttp", "accepts")),
        ({"type": "git", "url": "git://github.com/blakeembrey/array-flatten.git"}, ("blakeembrey", "array-flatten")),
        ({"type": "git", "url": "https://github.com/jonathanong/ee-first"}, ("jonathanong", "ee-first")),
        ({"type": "git", "url": "git+ssh://git@github.com/follow-redirects/follow-redirects.git"}, ("follow-redirects", "follow-redirects")),
        ({"type": "git", "url": "github:moment/moment"}, ("moment", "moment")),
        ("git@github.com:user/repo.git", ("user", "repo")),
        ("user/repo", ("user", "repo")),
        ("https://github.com/org/mono/tree/main/packages/x", ("org", "mono")),
        ({"url": "git+https://github.com/babel/babel.git", "directory": "packages/babel-core"}, ("babel", "babel")),
        ({"url": "https://gitlab.com/a/b.git"}, (None, None)),
        ("bitbucket:a/b", (None, None)),
        (None, (None, None)),
        ({"url": ""}, (None, None)),
    ]
    bad = 0
    for raw, want in cases:
        r = parse_repository(raw)
        got = (r["owner"], r["repo"])
        ok = got == want
        bad += not ok
        print("%s %-70s -> %s %s" % ("OK " if ok else "BAD", json.dumps(raw, ensure_ascii=False)[:70], got, r["reason"] or r["form"]))
    print("\nselftest: %d/%d 통과" % (len(cases) - bad, len(cases)))
    return bad == 0


# ---------------------------------------------------------------- HTTP

def load_dotenv(path=".env"):
    if not os.path.exists(path):
        return
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


class Http:
    def __init__(self, token=None):
        self.token = token
        self.rate = {}

    def get(self, url, github=False):
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if github:
            headers["Accept"] = "application/vnd.github+json"
            headers["X-GitHub-Api-Version"] = "2022-11-28"
            if self.token:
                headers["Authorization"] = "Bearer " + self.token
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                if github:
                    self._rate(r.headers)
                return r.status, json.load(r), r.geturl()
        except urllib.error.HTTPError as e:
            if github:
                self._rate(e.headers)
            try:
                body = json.load(e)
            except Exception:
                body = None
            return e.code, body, url
        except Exception as e:  # 네트워크 차단, 타임아웃 등
            return None, {"error": str(e)}, url

    def _rate(self, h):
        if h and h.get("X-RateLimit-Limit"):
            self.rate = {k: h.get("X-RateLimit-" + k.title()) for k in ("limit", "remaining", "used", "reset")}


# ---------------------------------------------------------------- 수집

def targets_from_lock(lock_path, include_all):
    lock = json.load(open(lock_path, encoding="utf-8"))
    pkgs = lock.get("packages", {})
    root_deps = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        root_deps.update(pkgs.get("", {}).get(key, {}) or {})
    seen, out = set(), []
    for path, meta in pkgs.items():
        if not path:
            continue
        name = path.split("node_modules/")[-1]
        is_direct = path == "node_modules/" + name and name in root_deps
        if not include_all and not is_direct:
            continue
        key = (name, meta.get("version"))
        if key in seen:
            continue
        seen.add(key)
        out.append({"name": name, "installed_version": meta.get("version"), "is_direct": is_direct, "lock_path": path})
    return lock.get("lockfileVersion"), out


def probe_npm(http, name, version):
    status, doc, _ = http.get(NPM_REGISTRY + urllib.parse.quote(name, safe="@"))
    if status != 200 or not isinstance(doc, dict):
        return {"status": status, "error": (doc or {}).get("error") if isinstance(doc, dict) else None}, None
    times = doc.get("time", {}) or {}
    latest = (doc.get("dist-tags") or {}).get("latest")
    vmeta = (doc.get("versions") or {}).get(version, {}) or {}
    repo = doc.get("repository") or vmeta.get("repository")
    info = {
        "status": status,
        "latest_version": latest,
        "latest_published_at": times.get(latest),
        "installed_published_at": times.get(version),
        "registry_modified_at": times.get("modified"),
        "installed_deprecated": vmeta.get("deprecated"),   # 폐기(deprecated) 메시지. 없으면 null
        "repository_source": "package" if doc.get("repository") else ("version" if vmeta.get("repository") else None),
    }
    return info, repo


def probe_github(http, owner, repo):
    base = "%s/repos/%s/%s" % (GITHUB_API, urllib.parse.quote(owner), urllib.parse.quote(repo))
    status, r, final_url = http.get(base, github=True)
    if status != 200 or not isinstance(r, dict):
        return {"status": status, "error": (r or {}).get("message") if isinstance(r, dict) else None}
    out = {
        "status": status,
        "full_name": r.get("full_name"),
        "renamed_or_moved": (r.get("full_name") or "").lower() != ("%s/%s" % (owner, repo)).lower(),
        "html_url": r.get("html_url"),
        "archived": r.get("archived"),
        "disabled": r.get("disabled"),
        "fork": r.get("fork"),
        "default_branch": r.get("default_branch"),
        "pushed_at": r.get("pushed_at"),       # 어떤 브랜치든 마지막 push. 참고용
        "updated_at": r.get("updated_at"),
        "open_issues_count": r.get("open_issues_count"),
    }
    full = r.get("full_name") or "%s/%s" % (owner, repo)
    s2, commits, _ = http.get("%s/repos/%s/commits?per_page=1&sha=%s" % (GITHUB_API, full, urllib.parse.quote(r.get("default_branch") or "")), github=True)
    if s2 == 200 and isinstance(commits, list) and commits:
        c = commits[0].get("commit", {})
        out["last_commit"] = {"sha": commits[0].get("sha"), "date": (c.get("committer") or {}).get("date"), "branch": r.get("default_branch")}
    else:
        out["last_commit"] = {"status": s2}
    s3, rel, _ = http.get("%s/repos/%s/releases/latest" % (GITHUB_API, full), github=True)
    if s3 == 200 and isinstance(rel, dict):
        out["latest_release"] = {"tag": rel.get("tag_name"), "published_at": rel.get("published_at")}
    else:
        out["latest_release"] = {"status": s3}  # 404 = GitHub 릴리스를 안 쓰는 저장소(흔함). 유지보수 부족 뜻 아님
    return out


def main():
    ap = argparse.ArgumentParser(description="GitHub 유지보수 원시 정보 수집")
    ap.add_argument("lockfile", nargs="?")
    ap.add_argument("--all", action="store_true", help="간접 의존성 포함 전체 패키지")
    ap.add_argument("-o", "--output", default="results/github_raw.json")
    ap.add_argument("--env", default=".env")
    ap.add_argument("--selftest", action="store_true", help="repository 파서 테스트만 실행")
    a = ap.parse_args()

    if a.selftest:
        sys.exit(0 if selftest() else 1)
    if not a.lockfile:
        ap.error("lockfile 경로가 필요합니다")

    load_dotenv(a.env)
    token = os.environ.get("GITHUB_TOKEN") or None
    http = Http(token)
    if not token:
        print("⚠ GITHUB_TOKEN 없음 → 비인증(시간당 60회)으로 진행. --all 이면 한도에 걸릴 수 있음", file=sys.stderr)

    lock_bytes = open(a.lockfile, "rb").read()
    lock_version, targets = targets_from_lock(a.lockfile, a.all)
    started = dt.datetime.now(dt.timezone.utc)
    results = []
    for i, t in enumerate(targets, 1):
        npm, raw_repo = probe_npm(http, t["name"], t["installed_version"])
        parsed = parse_repository(raw_repo)
        gh = None
        if parsed["owner"]:
            gh = probe_github(http, parsed["owner"], parsed["repo"])
        results.append({**t, "npm": npm, "repository": parsed, "github": gh})
        tag = "GH %s" % (gh or {}).get("status") if gh else (parsed["reason"] or "-")
        print("[%2d/%d] %-22s %-10s %s" % (i, len(targets), t["name"], t["installed_version"], tag), file=sys.stderr)
        time.sleep(0.05)

    mapped = sum(1 for r in results if r["repository"]["owner"])
    gh_ok = sum(1 for r in results if r["github"] and r["github"].get("status") == 200)
    doc = {
        "generated_at": started.isoformat(),
        "tool": "scripts/github_probe.py",
        "input": {"lockfile": os.path.basename(a.lockfile), "sha256": hashlib.sha256(lock_bytes).hexdigest(), "lockfileVersion": lock_version},
        "scope": "all" if a.all else "direct",
        "authenticated": bool(token),               # 토큰 값은 저장하지 않음
        "rate_limit_after": http.rate,
        "summary": {"packages": len(results), "github_mapped": mapped, "github_fetched_ok": gh_ok},
        "packages": results,
    }
    os.makedirs(os.path.dirname(a.output) or ".", exist_ok=True)
    json.dump(doc, open(a.output, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("\n패키지 %d개 · GitHub 매핑 %d개 · GitHub 조회 성공 %d개 · 남은 한도 %s → %s"
          % (len(results), mapped, gh_ok, http.rate.get("remaining", "?"), a.output), file=sys.stderr)


if __name__ == "__main__":
    main()
