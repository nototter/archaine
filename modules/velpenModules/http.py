import http.server
import socketserver


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.dir = "./activeInjects"
        super().__init__(*args, directory=self.dir, **kwargs)
    def log_message(self, format, *args):
        return


class HTTPServer:

    def __init__(self, port: int = 80, directory: str = "/injects/"):
        self.port = port
        self.dir = directory

    def forever(self):
        with socketserver.TCPServer(("", self.port), Handler) as httpd:
            self.serve = httpd
            httpd.serve_forever()

    def shutdown(self):
        self.serve.shutdown()
