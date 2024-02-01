from mitmproxy import http, ctx
from mitmproxy.io import FlowWriter
import re
import os
import time

class CaptureSensitiveInfo:
    def __init__(self):
        self.flow_dir = "captured_flows"
        os.makedirs(self.flow_dir, exist_ok=True)

    def response(self, flow: http.HTTPFlow) -> None:
        # Convert the response content to a string
        response_text = flow.response.get_text()

        # Define your regex pattern here
        pattern = r'(password|pwd|passwd|dbpasswd|dbuser|dbname|dbhost|api_key|api-key|apikey|secret|api|token|urlapi|apiurl|aws_access_key_id|aws_secret_access_key|DB_CHARSET|NONCE_SALT|LOGGED_IN_SALT|AUTH_SALT|NONCE_KEY|DB_HOST|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|DB_NAME|DB_USER)(:|=|\":).{0,15}'

        # Check if the pattern is in the response content, making it case-insensitive
        if re.search(pattern, response_text, re.IGNORECASE):
            # Create a unique filename using the current timestamp
            filename = os.path.join(self.flow_dir, f"captured_request_{int(time.time())}.mitm")

            # Save the flow using FlowWriter
            try:
                with open(filename, "wb") as file:
                    fw = FlowWriter(file)
                    fw.add(flow)
                ctx.log.info(f"Saved captured flow to {filename}")
            except OSError as e:
                ctx.log.error(f"Error saving .mitm file: {e}")

# Add the class instance to mitmproxy addons
addons = [CaptureSensitiveInfo()]
