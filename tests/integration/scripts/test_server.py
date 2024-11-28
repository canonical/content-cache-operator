#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""HTTP server for testing."""

import argparse
import json
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import IPv4Address
from typing import Type

# Script for testing only.
# flake8: noqa


@dataclass
class HTTPServerArgs:
    ip: IPv4Address
    port: int
    path: str
    status_code: int
    message: str


def get_args():
    parser = argparse.ArgumentParser("HTTP server for tests.")
    parser.add_argument("--ip", type=str, default="0.0.0.0", help="The IP address to listen on.")
    parser.add_argument("--port", type=int, default=80, help="The port to listen on.")
    parser.add_argument(
        "--path",
        type=str,
        default="/",
        help="The path to serve content.",
    )
    parser.add_argument(
        "--status", type=int, default=200, help="The status code for the response."
    )
    parser.add_argument(
        "--message", type=str, default="Test message", help="The body of the response."
    )
    args = parser.parse_args()

    return HTTPServerArgs(
        ip=args.ip,
        port=args.port,
        path=args.path,
        status_code=args.status,
        message=args.message,
    )


def create_request_handler(
    path: str, status_code: int, message: str
) -> Type[BaseHTTPRequestHandler]:
    class RequestHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != path:
                self.send_response(404)
                self.end_headers()
                return

            response = json.dumps({"message": message, "time": str(datetime.now())})
            self.send_response(status_code)
            self.send_header("Content-type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.send_header("Cache-control", "")
            self.end_headers()
            self.wfile.write(response.encode("utf8"))

    return RequestHandler


def main():
    args = get_args()
    request_handler = create_request_handler(args.path, args.status_code, args.message)
    HTTPServer((args.ip, args.port), request_handler).serve_forever()


if __name__ == "__main__":
    main()
