#!/usr/bin/env python3

import argparse
import base64
import json
import ssl
import sys
import urllib.parse
import urllib.request


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a Splunk search export request over the local management API.")
    parser.add_argument("--scheme", default="https", help="Splunk management API scheme. Default: https")
    parser.add_argument("--host", default="127.0.0.1", help="Splunk management API host. Default: 127.0.0.1")
    parser.add_argument("--port", default="8089", help="Splunk management API port. Default: 8089")
    parser.add_argument("--username", required=True, help="Splunk username")
    parser.add_argument("--password", required=True, help="Splunk password")
    parser.add_argument("--services-owner", default="nobody", help="Splunk services owner namespace. Default: nobody")
    parser.add_argument("--services-app", default="defenseclaw_local_mode", help="Splunk services app namespace. Default: defenseclaw_local_mode")
    parser.add_argument("--query", required=True, help="SPL search string to run")
    parser.add_argument("--output-mode", default="json", help="Splunk export output mode. Default: json")
    parser.add_argument("--verify-tls", action="store_true", help="Verify TLS when connecting to the management API")
    return parser.parse_args()


def authorization_header(username: str, password: str) -> str:
    raw = f"{username}:{password}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def parse_export_lines(body: str) -> tuple[list[dict[str, object]], list[dict[str, object]], list[str]]:
    results: list[dict[str, object]] = []
    fragments: list[dict[str, object]] = []
    messages: list[str] = []

    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            fragments.append({"raw": raw_line})
            continue

        if isinstance(payload, dict):
            if isinstance(payload.get("messages"), list):
                for message in payload["messages"]:
                    if isinstance(message, dict):
                        text = message.get("text")
                        if isinstance(text, str):
                            messages.append(text)
            if isinstance(payload.get("result"), dict):
                results.append(payload["result"])
                continue
            if isinstance(payload.get("results"), list):
                results.extend(item for item in payload["results"] if isinstance(item, dict))
                continue
            fragments.append(payload)
            continue

        fragments.append({"value": payload})

    return results, fragments, messages


def normalize_value(value: object) -> object:
    if isinstance(value, list):
        normalized_items = [normalize_value(item) for item in value]
        if len(normalized_items) == 1:
            return normalized_items[0]
        if normalized_items and all(item == normalized_items[0] for item in normalized_items):
            return normalized_items[0]
        return normalized_items
    if isinstance(value, dict):
        return {key: normalize_value(item) for key, item in value.items()}
    return value


def main() -> int:
    args = parse_args()
    owner = urllib.parse.quote(args.services_owner, safe="")
    app = urllib.parse.quote(args.services_app, safe="")
    endpoint = f"{args.scheme}://{args.host}:{args.port}/servicesNS/{owner}/{app}/search/jobs/export"
    data = urllib.parse.urlencode(
        {
            "search": args.query,
            "output_mode": args.output_mode,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=data,
        method="POST",
        headers={
            "Authorization": authorization_header(args.username, args.password),
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    context = None
    if endpoint.startswith("https://") and not args.verify_tls:
        context = ssl._create_unverified_context()

    try:
        with urllib.request.urlopen(request, context=context, timeout=30) as response:
            body = response.read().decode("utf-8")
            status_code = response.status
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        error_payload = {
            "backend": "rest-export",
            "endpoint": endpoint,
            "query": args.query,
            "status_code": exc.code,
            "error": body,
        }
        print(json.dumps(error_payload, indent=2))
        return 1

    results, fragments, messages = parse_export_lines(body)
    payload = {
        "backend": "rest-export",
        "endpoint": endpoint,
        "query": args.query,
        "status_code": status_code,
        "result_count": len(results),
        "results": [normalize_value(result) for result in results],
        "messages": messages,
    }
    if fragments:
        payload["fragments"] = fragments
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
