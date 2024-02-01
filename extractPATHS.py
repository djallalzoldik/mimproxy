from mitmproxy import http, ctx
import re
import os

class extractpath:
    def __init__(self):
        self.txt_file_path = "captured_urls_and_paths.txt"
        dir_path = os.path.dirname(self.txt_file_path)
        if dir_path:
            try:
                os.makedirs(dir_path, exist_ok=True)
                ctx.log.info("Directory created or already exists")
            except Exception as e:
                ctx.log.error(f"Error creating directory: {e}")
        else:
            ctx.log.info("No directory path specified, using current working directory")
        ctx.log.info("extractpath addon initialized")

    def response(self, flow: http.HTTPFlow) -> None:
        ctx.log.info("Intercepted an HTTP response")
        scheme = flow.request.scheme  # Get the request scheme (http or https)
        host = flow.request.host
        port = flow.request.port
        base_url = f"{scheme}://{host}:{port}"
        response_text = flow.response.text

        # Exclude paths with spaces and specific file extensions
        exclude_extensions = r'\.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg)'
        # Regular expression patterns
        url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+', re.IGNORECASE)
        html_path_pattern = re.compile(r'(src|href|data|action|srcset)="(\/[^\s<>"]*[^<>"\s' + exclude_extensions + '])"', re.IGNORECASE)
        js_path_pattern = re.compile(r'["\'](\/[^\s"\'<>]+[^<>"\'\s' + exclude_extensions + '])["\']', re.IGNORECASE)

        try:
            with open(self.txt_file_path, "a") as file:
                # Find and write all occurrences of URLs and paths
                for url in url_pattern.findall(response_text):
                    if not re.search(exclude_extensions, url, re.IGNORECASE):
                        # Prepend scheme if missing
                        if not url.startswith("http"):
                            url = f"{scheme}://{url}"
                        file.write(url + "\n")

                for _, path in html_path_pattern.findall(response_text):
                    complete_html_url = base_url + path
                    file.write(complete_html_url + "\n")

                for path in js_path_pattern.findall(response_text):
                    complete_js_url = base_url + path
                    file.write(complete_js_url + "\n")

        except Exception as e:
            ctx.log.error(f"Error writing to file: {e}")

addons = [extractpath()]
