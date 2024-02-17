from mitmproxy import http, ctx
from mitmproxy.io import FlowWriter
import copy
import os
import urllib.parse
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor

class AlterResponse:
    def __init__(self):
        self.flow_dir_xss = "XSS_flows"
        os.makedirs(self.flow_dir_xss, exist_ok=True)
        self.alteration_indicators_xss = [
            "%22%3E%3Ch1%3Eakira1%3C%2Fh1%3E", 
            "'\"><h1>akira1</h1>",
            "%00'\"><h1>akira1</h1>"
            # Add more XSS payloads as necessary...
        ]
        self.altered_header_xss = "x-altered-xss"

    def response(self, flow: http.HTTPFlow) -> None:
        content_type = flow.response.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            return  # Skip non-HTML responses

        if self.altered_header_xss in flow.request.headers:
            self.check_altered_reflection_xss(flow)
            return

        if flow.request.method == "GET":
            self.process_parameters_xss(flow, flow.request.query)
        elif flow.request.method == "POST":
            self.process_post_request_xss(flow)

    def process_post_request_xss(self, flow):

        content_type = flow.request.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" in content_type:
            params = urllib.parse.parse_qs(flow.request.get_text())
            self.process_parameters_xss(flow, params)
        elif "application/json" in content_type:
            try:
                params = json.loads(flow.request.get_text())
                if isinstance(params, dict):
                    self.process_parameters_xss(flow, params)
            except json.JSONDecodeError:
                ctx.log.info("JSON decode error")

    def process_parameters_xss(self, flow, params):
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
                ctx.log.info(f"Unhandled value type for param '{param}': {type(value)}")
            
                # Define patterns to search for in the response body
            if self.escaped_value in flow.response.text:
                self.handle_reflection(flow, param, self.escaped_value)
            
        for param, value in params.items():

            process_value(param, value)
            

    def handle_reflection(self, flow, param, value):
        with ThreadPoolExecutor(max_workers=100) as executor:
            # Logic to handle the reflection, e.g., logging, altering, and replaying
            for indicator in self.alteration_indicators_xss:
                executor.submit(self.alter_and_replay_xss, flow, param, value, indicator)
    def alter_and_replay_xss(self, original_flow, param, original_value, indicator):
        altered_value = original_value + indicator
        altered_flow = self.alter_request_xss(original_flow, param, altered_value)
        if altered_flow:
            ctx.master.commands.call("replay.client", [altered_flow])

    def alter_request_xss(self, original_flow, param, altered_value):
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
        new_request.headers[self.altered_header_xss] = "true"
        altered_flow = http.HTTPFlow(original_flow.client_conn, original_flow.server_conn)
        altered_flow.request = new_request
        return altered_flow

    def check_altered_reflection_xss(self, flow):
        pattern = re.compile(r'<h1>akira1</h1>')  # Example pattern, adjust as needed
        if pattern.search(flow.response.text):
            self.save_flow_xss(flow)

    def save_flow_xss(self, flow):
        filename = os.path.join(self.flow_dir_xss, f"{flow.request.method}_captured_{int(time.time())}.mitm")
        try:
            with open(filename, "wb") as file:
                fw = FlowWriter(file)
                fw.add(flow)
            ctx.log.info(f"Saved XSS flow to {filename}")
        except OSError as e:
            ctx.log.error(f"Error saving .mitm file: {e}")

addons = [AlterResponse()]
