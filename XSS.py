from mitmproxy import http, ctx
from mitmproxy.io import FlowWriter
import copy
import os
import urllib.parse
import json
import re
import time

class AlterResponse:
    def __init__(self):
        self.flow_dir_xss = "XSS_flows"
        os.makedirs(self.flow_dir_xss, exist_ok=True)
        self.alteration_indicators_xss = ["%22%3E%3Ch1%3Eakira1%3C%2Fh1%3E", "'\"><h1>akira1</h1>", "Jz4iIDxoMT5ha2lyYTE8L2gxPg==", "273e22203c68313e616b697261313c2f68313e", "%00'\"><h1>akira1</h1>", "'\"><h1>akira1</h1>", "\x22\x3e\x3c\x68\x31\x3e\x61\x6b\x69\x72\x61\x31\x3c\x2f\x68\x31\x3e", "\x27\x22\x3e\x3c\x68\x31\x3e\x61\x6b\x69\x72\x61\x31\x3c\x2f\x68\x31\x3e", "%27%22%3E%3Ch1%3Eakira1%3C%2Fh1%3E", "\u0027\u0022\u003e\u003c\u0068\u0031\u003e\u0061\u006b\u0069\u0072\u0061\u0031\u003c\u002f\u0068\u0031\u003e", "0x27223e3c68313e616b697261313c2f68313e", "\0027\0022\003e\003c\0068\0031\003e\0061\006b\0069\0072\0061\0031\003c\002f\0068\0031\003e", "\047\042\076\074\150\061\076\141\153\151\162\141\061\074\057\150\061\076", "-..----..----.-..-.--...--..-.-.-..-.-.-..-.-..-.-.-....-.--...--.-..-.--....-..-."]
        self.altered_header_xss = "x-altered-xss"

    def response_xss(self, flow: http.HTTPFlow) -> None:
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
        for param, value in params.items():
            if isinstance(value, list):  # Handle lists for form data
                value = value[0]
            if isinstance(value, str) and value in flow.response.text:
                self.alter_and_replay_xss(flow, param, value)

    def alter_and_replay_xss(self, original_flow, param, original_value):
        for indicator in self.alteration_indicators_xss:
            altered_value_xss = original_value + indicator
            save_flow_xss = self.alter_request_xss(original_flow, param, altered_value_xss)
            if save_flow_xss:
                ctx.master.commands.call("replay.client", [save_flow_xss])

    def alter_request_xss(self, original_flow, param, altered_value_xss):
        altered_value_xss = copy.deepcopy(original_flow.request)
        if original_flow.request.method == "GET":
            altered_value_xss.query[param] = altered_value_xss
        else:
            content_type = altered_value_xss.headers.get("Content-Type", "")
            if "application/x-www-form-urlencoded" in content_type:
                params = urllib.parse.parse_qs(altered_value_xss.get_text())
                params[param] = [altered_value_xss]
                altered_value_xss.text = urllib.parse.urlencode(params, doseq=True)
            elif "application/json" in content_type:
                try:
                    body = json.loads(altered_value_xss.get_text())
                    if param in body and isinstance(body[param], str):
                        body[param] = altered_value_xss
                        altered_value_xss.text = json.dumps(body)
                except json.JSONDecodeError:
                    pass
        altered_value_xss.headers[self.altered_header_xss] = "true"
        save_flow_xss = http.HTTPFlow(original_flow.client_conn, original_flow.server_conn)
        save_flow_xss.request = altered_value_xss
        return save_flow_xss

    def check_altered_reflection_xss(self, flow):
        pattern = re.compile(r'<h1>akira1', re.IGNORECASE)  # Define the pattern to match specific keywords
        if pattern.search(flow.response.text):
            ctx.log.info(f"Altered parameter reflected in the response: {flow.request.url}")
            self.save_flow_xss(flow)

    def save_flow_xss(self, flow):
        filename = os.path.join(self.flow_dir_xss, f"{flow.request.method}_xss_request_{int(time.time())}.mitm")
        try:
            with open(filename, "wb") as file:
                fw = FlowWriter(file)
                fw.add(flow)
            ctx.log.info(f"Saved xss flow to {filename}")
        except OSError as e:
            ctx.log.error(f"Error saving .mitm file: {e}")

addons = [AlterResponse()]
