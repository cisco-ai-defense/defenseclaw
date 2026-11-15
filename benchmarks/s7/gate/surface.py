# tool-surface classifier shared by s7gate (scoring) and coverage; pure functions, stdlib only
import re, json

PKG_MANAGERS = {"npm", "npx", "pnpm", "yarn", "pip", "pip3", "pipx", "uv", "poetry", "conda", "mamba", "cargo", "gem", "bundle", "composer", "apt", "apt-get", "aptitude",
                "yum", "dnf", "rpm", "dpkg", "brew", "port", "choco", "winget", "scoop", "snap", "flatpak", "mvn", "gradle", "nuget", "dotnet", "bun", "deno", "go"}
GO_PKG = re.compile(r"^go\s+(?:get|install|mod|work)\b")
SUBAGENT = re.compile(r"(?i)^(?:task|agent|subagent|spawn_agent|task_?(?:create|update|list|get|output|stop)|delegate\w*|send_?message|todowrite|todo_?write|update_plan|task_tracker|mark_task_complete|finish|think)$")
FILE_READ = {"read", "read_file", "readfile", "view", "view_file", "open_file", "cat", "fs_read", "notebookread", "glob", "grep", "ls", "list_directory", "list_dir", "search_files", "find_files", "image_read", "open_image"}
FILE_WRITE = {"write", "write_file", "writefile", "create_file", "create", "file_write", "save_file", "fs_write", "fs_append", "create_directory", "move_file", "copy_file", "delete_file"}
FILE_EDIT = {"edit", "multiedit", "edit_file", "str_replace", "str_replace_editor", "str_replace_based_edit_tool", "text_editor", "replace_in_file", "apply_diff", "replace", "insert"}
WEB = {"webfetch", "web_fetch", "websearch", "web_search", "fetch", "fetch_url", "http_request", "curl", "browse", "search_web"}
SHELL = {"bash", "bash_command", "execute_command", "shell", "shell_command", "exec_command", "exec", "run_command", "terminal", "run_shell_command", "execute_bash", "execute_pwsh",
         "run_terminal_cmd", "sh", "zsh", "powershell", "pwsh", "local_shell", "shell_exec", "execute", "system.execute", "shell.run", "shell.exec", "terminal.execute", "async_shell_command", "python_interpreter", "execute_ipython_cell", "run_python"}
MCP_FAMILIES = [
    ("browser", re.compile(r"(?i)browser|navigate|click|screenshot|playwright|puppeteer|webpage|\bpage\b|scroll|fill_form")),
    ("cloud", re.compile(r"(?i)aws|\bs3\b|gcp|azure|lambda|ec2|kubernetes|k8s|docker|terraform|cloud|bucket|\biam\b|vm_")),
    ("issue-tracker", re.compile(r"(?i)github|gitlab|jira|linear|issue|ticket|pull_request|\bpr\b|bitbucket|asana|trello")),
    ("messaging-email", re.compile(r"(?i)email|mail|slack|message|inbox|chat|sms|send_|teams|discord|telegram|notification")),
    ("database", re.compile(r"(?i)sql|query|table|database|\bdb\b|postgres|mysql|sqlite|mongo|redis|\brows?\b|insert_|select_")),
    ("filesystem", re.compile(r"(?i)file|directory|folder|path|read_|write_|move_|list_")),
]


def first_word(command: str) -> str:
    c = command.strip()
    for _ in range(4):
        m = re.match(r"(?:cd\s+\S+\s*(?:&&|;)\s*|(?:\w+=\S*\s+)+|sudo(?:\s+-\S+)*\s+|env\s+(?:\w+=\S*\s+)*|time\s+|nohup\s+|\(\s*)", c)
        if not m: break
        c = c[m.end():]
    m = re.match(r"([A-Za-z0-9_./-]+)", c)
    return (m.group(1).rsplit("/", 1)[-1] if m else "").lower()


def event_surface(ev: dict, platform: str, dialect: str) -> str:
    name = (ev.get("tool_name") or "").strip(); lower = name.lower()
    cmd = ev.get("command") or ""
    if not cmd and isinstance(ev.get("args"), dict): cmd = str(ev["args"].get("command") or ev["args"].get("cmd") or "") if lower in SHELL else ""
    if lower.startswith("mcp__") or (lower not in SHELL and lower not in FILE_READ and lower not in FILE_WRITE and lower not in FILE_EDIT and lower not in WEB and lower not in ("apply_patch", "notebookedit", "applypatch")
                                       and not SUBAGENT.match(lower)):
        body = name + " " + (json.dumps(ev.get("args"))[:300] if ev.get("args") else "")
        if lower.startswith("mcp__") or "." in name or lower:
            for fam, rx in MCP_FAMILIES:
                if rx.search(name): return "mcp:" + fam
            if lower.startswith("mcp__"): return "mcp:other"
        return "other-tool"
    if SUBAGENT.match(lower): return "subagent-task"
    if lower in ("apply_patch", "applypatch"): return "patch"
    if lower == "notebookedit": return "notebook-edit"
    if lower in WEB: return "web"
    if lower in FILE_READ: return "file-read"
    if lower in FILE_WRITE: return "file-write"
    if lower in FILE_EDIT: return "file-edit"
    if lower in SHELL:
        fw = first_word(cmd)
        if fw == "git" or re.match(r"^\s*(?:cd\s+\S+\s*(?:&&|;)\s*)?git\s", cmd): return "git"
        if fw in PKG_MANAGERS and (fw != "go" or GO_PKG.match(cmd.strip().split("&&")[-1].strip() or cmd)): return "package-manager"
        if dialect == "powershell": return "shell:powershell"
        if dialect == "cmd": return "shell:cmd"
        if platform == "windows": return "shell:git-bash"
        return "shell:posix"
    return "other-tool"


def case_surface(case: dict) -> str:
    # guardrail surfaces other than the hook tool call (prompt, tool-result) are named by the corpus (strata.guardrail_surface)
    gs = (case.get("strata") or {}).get("guardrail_surface")
    if gs: return gs
    p = case["payload"]; evs = p.get("events") or [p]
    st = case.get("strata", {}); plat = st.get("platform", ""); 
    if len(evs) > 1:
        return "sequence-window"
    ev = evs[0]; dial = ev.get("dialect") or st.get("dialect") or ""
    return event_surface(ev, plat, dial)
