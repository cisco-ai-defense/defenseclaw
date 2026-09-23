"""Serve a ZefanCai Open-Jev checkpoint under a display name that carries its base family.

Thin wrapper around the project's own `jev.serving.load_predictor` and
`jev.server.make_server` -- no Open-Jev code is modified or reimplemented. The
only change is the advertised model name, so that `open-jev-qwen-2b` /
`open-jev-qwen-9b` cannot be confused with our own unrelated self-hosted
"OpenJev" (revision 5ec9e5fd...). The canonical HuggingFace repo id, pinned base
revision and checkpoint digest all stay in the response metadata.
"""

import argparse
import json

from jev.server import make_server
from jev.serving import load_predictor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", required=True, help="path to package/checkpoint")
    parser.add_argument("--name", required=True, help="display name, e.g. open-jev-qwen-9b")
    parser.add_argument("--repo-id", required=True, help="canonical HuggingFace repo id")
    parser.add_argument("--device", default="cuda:0")
    parser.add_argument("--max-length", type=int)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--prefix-cache", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8791)
    args = parser.parse_args()

    predictor = load_predictor(checkpoint=args.checkpoint, device=args.device,
                               max_length=args.max_length, batch_size=args.batch_size,
                               prefix_cache=args.prefix_cache)
    canonical = predictor.model_name
    predictor.model_name = args.name
    # Keep provenance traceable to the source artifact alongside the display name.
    predictor.provenance.update(repo_id=args.repo_id, display_name=args.name,
                                canonical_base_model=canonical)
    server = make_server(predictor, args.host, args.port)
    print(json.dumps({"url": f"http://{args.host}:{server.server_port}",
                      "model": predictor.model_name, "method": predictor.method,
                      "temperature": predictor.temperature, **predictor.provenance}), flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
