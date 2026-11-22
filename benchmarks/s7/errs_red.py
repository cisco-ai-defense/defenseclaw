import re
RX = [(re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b"), "<ip>"), (re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"), "<email>"),
      (re.compile(r"https?://[^\s'\"/]+"), "https://<host>"), (re.compile(r"\b[A-Fa-f0-9]{24,}\b"), "<hex>"),
      (re.compile(r"\b[A-Za-z0-9+/_-]{32,}={0,2}"), "<token>"), (re.compile(r"/home/[^/\s]+"), "/home/<user>"),
      (re.compile(r"(?i)(pass(word)?|pwd|secret|token|key)([=: ]+)\S+"), r"\1\3<redacted>"),
      (re.compile(r"(?i)\b[\w-]+\.(local|corp|lan|internal)\b"), "<domain>"),
      (re.compile(r"(?i)(-u|-p|--username|--password)\s+\S+"), r"\1 <redacted>"),
      (re.compile(r"[\w.-]+/[\w.-]+:[^@\s]+@"), "<user>:<redacted>@"), (re.compile(r"\b[\w.-]+/[\w.-]+:\S+"), "<realm>/<user>:<redacted>")]
def red(s, n=140):
    s = (s or "").replace("\n", " ")
    for rx, rep in RX: s = rx.sub(rep, s)
    return s[:n]
