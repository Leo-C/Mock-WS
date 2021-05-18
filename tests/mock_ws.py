import io
import os
import sys
import json
import glob
import time
import fnmatch
import urllib
import argparse
import datetime
import threading
import email.utils
import http.server
import http.client

from http import HTTPStatus
from typing import Tuple

import unittest

__version__ = "0.1"
__ws_name__ = "SimpleTracingFileServer"

DEFAULT_CONTENT_TYPE = "application/octet-stream"


class HttpMessage():
    """
    Store message components for HTTP Request and Response
    """
    def __init__(self,  *args, URL: str, headers: dict = {}, command: str, code: int = 0, data: any = None, protocol_version = 'HTTP/1.0', **kwargs):
        """
        :param URL: URL of this Message
        :type URL: str
        :param headers: headers (as name -> value)
        :type headers: dict
        :param command: HTTP verb
        :type command: str
        :param code: HTTP code
        :type code: int
        :param data: HTTP body
        :type data: bytes array or str
        :param protocol_version: HTTP version
        :type protocol_version: str
        """
        self._cmd = command
        self._uri_comp = urllib.parse.urlsplit(URL)
        self._headers = headers
        self._code = code
        self._data = data
        self._protocol_version = protocol_version
    
    @property
    def command(self) -> str:
        """
        :return: HTTP verb
        :rtype: str
        """
        return self._cmd
    
    @property
    def path(self) -> str:
        """
        :return:  path of URL (without host, parameters and anchor)
        :rtype: str
        """
        return self._uri_comp.path
    
    @property
    def query(self) -> str:
        """
        :return: query part of URL
        :rtype: str
        """
        return self._uri_comp.query
    
    @property
    def host(self) -> str:
        """
        :return: host component of URL
        :rtype: str
        """
        return self._uri_comp.netloc
    
    @property
    def protocol(self):
        """
        :return: HTTP version
        :rtype: str
        """
        return self._protocol_version
    
    @property
    def headers(self) -> dict:
        """
        :return: headers (as association name -> value)
        :rtype: dict
        """
        return self._headers
    
    @property
    def port(self) -> int:
        """
        :return: port component of URL
        :rtype: int
        """
        if self._uri_comp.port == None: #default if not specified
            if self.protocol.lower() == 'http':
                return 80 
            elif self.protocol.lower() == 'https':
                return 443
        else:
            return self._uri_comp.port
    
    @property
    def httpcode(self):
        """
        :return: HTTP response code
        :rtype: int
        """
        return self._code
    
    @property
    def data(self):
        """
        :return: body data
        :rtype: byte arra or string array
        """
        return self._data
    
    def __str__(self) -> str:
        obj = { 'timestamp': datetime.datetime.now().isoformat(),
                'command': self.command,
                'code': self.httpcode,
                'URL': urllib.parse.urlunsplit(self._uri_comp),
                'headers': self.headers,
                'protocol': self.protocol,
                'data': None if self.data == None else str(self.data) }
        
        return json.dumps(obj)
    

class ReqHandler(http.server.BaseHTTPRequestHandler):
    """
    Handler Class for HTTP Request
    """
    server_version = __ws_name__ + "/" + __version__
    extensions_map = _encodings_map_default = {
        '.gz': 'application/gzip',
        '.bz2': 'application/x-bzip2',
        '.json': 'application/json',
        '.txt': 'text/plain',
        '.text': 'text/plain',
        '.htm': 'text/html',
        '.html': 'text/html',
        '.css': 'text/css',
        '.js': 'text/javascript',
        '.gif': 'image/gif',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.svg': 'image/svg+xml',
        '.wav': 'audio/wave',
        '.webm': 'video/wemb', #can be audio-only ('audio/webm')
        '.ogg': 'audio/ogg', #can contains also video ('video/ogg')
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
    def do_HEAD(self) -> None: #TODO: registered response
        """Serve a HEAD request."""
        m = self.build_message()
        self.server.http_requests.append(m)
        self.server.log_message(m)
        
        if self.intercept_request():
            return
        
        req_range = self.get_range()
        if req_range == None:
            return
        f = self.send_head(req_range[0], req_range[1])
        if f:
            f.close()
        
        self.server._event.set()
    
    def do_GET(self) -> None: #TODO: registered response
        """Serve a GET request."""
        m = self.build_message()
        self.server.http_requests.append(m)
        self.server.log_message(m)
        
        if self.intercept_request():
            return
        
        req_range = self.get_range()
        if req_range == None:
            return
        f = self.send_head(req_range[0], req_range[1])
        if f:
            try:
                self.send_file(f, req_range[0], req_range[1])
            finally:
                f.close()
        
        self.server._event.set()
    
    def do_POST(self) -> None: #TODO: registered response
        """Serve a POST request."""
        m = self.build_message()
        self.server.http_requests.append(m)
        self.server.log_message(m)
        
        if self.intercept_request():
            return
        
        req_range = self.get_range()
        if req_range == None:
            return
        f = self.send_head(req_range[0], req_range[1])
        if f:
            try:
                self.send_file(f, req_range[0], req_range[1])
            finally:
                f.close()
        
        self.server._event.set()
    
    def send_head(self, start: int, end: int) -> 'stream':
        """
        Forge a Response with correct Headers.
        
        :param start: byte position of start of data to send
        :type start: int (if -1 start is not specified, then is considered 1st byte)
        :param end: byte position of start of data to send
        :type end: int (if -1, end is not specified, then is considered last byte)
        :return: a file descriptor if a file on filesystem is reffered by URL
        :rtype: stream
        """
        path = self.get_path(self.path)
        path = os.path.join(self.server.root_dir, path[1:])
        found_index = False
        if os.path.isdir(path):
            for file in os.listdir(path):
                if fnmatch.fnmatch(file, 'index.*'):
                    found_index = True
                    path = os.path.join(path, file)
            
            if not found_index:
                self.send_error(HTTPStatus.NOT_FOUND, "File not found")
                return None
        
        # check for trailing "/" which should return 404. See Issue17324
        # The test for this was added in test_httpserver.py
        # However, some OS platforms accept a trailingSlash as a filename
        # See discussion on python-dev and Issue34711 regarding
        # parseing and rejection of filenames with a trailing slash
        if path.endswith("/"):
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None
        try:
            f = open(path, 'rb')
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None
        
        ctype = self.get_ctype(path)
        try:
            fs = os.fstat(f.fileno())
            # Use browser cache if possible
            if ("If-Modified-Since" in self.headers
                    and "If-None-Match" not in self.headers):
                # compare If-Modified-Since and time of last file modification
                try:
                    ims = email.utils.parsedate_to_datetime(
                        self.headers["If-Modified-Since"])
                except (TypeError, IndexError, OverflowError, ValueError):
                    # ignore ill-formed values
                    pass
                else:
                    if ims.tzinfo is None:
                        # obsolete format with no timezone, cf.
                        # https://tools.ietf.org/html/rfc7231#section-7.1.1.1
                        ims = ims.replace(tzinfo=datetime.timezone.utc)
                    if ims.tzinfo is datetime.timezone.utc:
                        # compare to UTC datetime of last modification
                        last_modif = datetime.datetime.fromtimestamp(
                            fs.st_mtime, datetime.timezone.utc)
                        # remove microseconds, like in If-Modified-Since
                        last_modif = last_modif.replace(microsecond=0)

                        if last_modif <= ims:
                            self.send_response(HTTPStatus.NOT_MODIFIED)
                            self.end_headers()
                            f.close()
                            return None
            
            if (start > 0) or (end > 0):
                self.send_response(HTTPStatus.PARTIAL_CONTENT)
                self.send_header("Content-Range", "bytes " +
                    ('' if start < 0 else str(start)) + '-' +
                    ('' if end < 0 else str(end)) + '/' + str(fs[6]) )
            else:
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Length", str(fs[6]))
            
            self.send_header("Content-Type", ctype)
            self.send_header("Last-Modified",
                self.date_time_string(fs.st_mtime))
            self.end_headers()
            return f
        except:
            f.close()
            raise
    
    def intercept_request(self) -> bool:
        """
        Handle configured request COMMAND:URL
        
        :return: True if URL is intercepted
        :rtype: bool
        """
        uri_comp = urllib.parse.urlsplit(self.path)
        key = (self.command, uri_comp.path)
        if key in self.server.handlers:
            resp = self.server.handlers[key]
            if resp.httpcode > 0:
                self.send_response(resp.httpcode)
            else:
                self.send_response(HTTPStatus.OK)
            for hdr in resp.headers:
                self.send_header(hdr, resp.headers[hdr])
            if (resp.data != None) and (resp.data != ''):
                self.send_header("Content-Length", str(len(resp.data)))
            self.end_headers()
            if isinstance(resp.data, str):
                self.wfile.write(resp.data.encode("UTF-8"))
            else:
                self.wfile.write(resp.data)
            
            return True
        
        return False
    
    def send_file(self, stream, start: int, end: int) -> None:
        """
        Send file content to client
        
        :param stream: stream
        :type stream: file or stream
        :param start: byte position of start of data to send
        :type start: int (if -1 start is not specified, then is considered 1st byte)
        :param end: byte position of start of data to send
        :type end: int (if -1, end is not specified, then is considered last byte)
        """
        if isinstance(stream, str):
            txt = stream
            stream = io.StringIO()
            stream.write(txt)
        elif isinstance(stream, bytes):
            arr = stream
            stream = io.BytesIO()
            stream.write(arr)
        
        MAXBUF = 4096
        lenread = -1 #total bytes to read (-1 -> infinite)
        if start > 0:
            stream.seek(start, os.SEEK_SET)
            if end > 0:
                lenread = end - start + 1
        elif end > 0:
            stream.seek(-end, os.SEEK_END)
        
        buf = stream.read(min(MAXBUF, lenread))
        while len(buf) > 0:
            self.wfile.write(buf)
            
            if lenread == -1:
                break
            else:
                lenread -= len(buf)
            
            buf = stream.read(min(MAXBUF, lenread))
    
    def get_range(self) -> Tuple[int, int]:
        """
        Parse 'Range' header
        
        :return: (start, end) bytes of content to transmit
        :rtype: Tuple[int, int]
        """
        if "Range" not in self.headers:
            return (-1, -1)
        
        http_ranges = self.headers["Range"]
        pos = http_ranges.find(',')
        if pos > 0:
            self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
            self.send_header("Content-Range", "bytes "+http_ranges[pos+1:]) #accept only 1st range
            self.end_headers()
            return None
        
        str_ranges = http_ranges.split('=')[1]
        ranges = str_ranges.split('-')
        rng = (-1, -1)
        if ranges[0] != '':
            rng[0] = int(ranges[0])
        if ranges[1] != '':
            rng[1] = int(ranges[1])
        
        return rng
    
    def get_path(self, uri:str) -> str:
        """
        :return: path part of URL
        :rtype: str
        """
        uri_comp = urllib.parse.urlsplit(self.path)
        return uri_comp.path
    
    def get_ctype(self, uri: str) -> str:
        """
        Guess Content-Type by file extension
        
        :param uri: path component of URL
        :return: Content-Type
        :rtype: str
        """
        base, ext = os.path.splitext(uri)
        ext = ext.lower()
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        else:
            return DEFAULT_CONTENT_TYPE
    
    def read_headers(self) -> dict:
        """
        Transform http.server.BaseHTTPRequestHandler.headers in dictionary
        """
        headers = {}
        for name in self.headers:
            headers[name] = self.headers.get(name)
        
        return headers
    
    def build_message(self) -> HttpMessage:
        """
        Build a HttpMessage instance
        
        :return: message
        :rtype: HttpMessage
        """
        headers = self.read_headers()
        
        length = 0
        if 'Content-Length' in headers:
            length = int(self.headers["Content-Length"])
        
        data = b''
        if length > 0:
            data = self.rfile.read(length)
        
        m = HttpMessage(URL = self.path,
                headers = headers,
                command = self.command,
                code = -1,
                data = data,
                protocol_version = self.request_version)
        
        return m

class WebServer(threading.Thread):
    """
    Web Server class (contains an http.server instance)
    """
    def __init__(self, *args, bind: str = "0.0.0.0", port: int = 80, root_dir: str = "", logstream = None, **kwargs) -> None:
        """
        :param bind: listen IP interface (default: all interfaces)
        :type bind: str
        :param port: port to listen (default 80)
        :type port: int
        :param root_dir: root directory for web server (default: current directory)
        :type root_dir: str
        :param logstream: stream for logging
        :type logstream: stream
        """
        self._bind = bind
        self._port = port
        if root_dir == "":
            self._root_dir = os.getcwd()
        else:
            self._root_dir = root_dir
        self._logstream = logstream
        self._srv = None
        super().__init__()
    
    def startWS(self) -> None:
        """
        Start web server
        """
        server_address = (self._bind, self._port)
        self._srv = http.server.HTTPServer(server_address, ReqHandler)
        self._srv.http_requests = []
        self._srv.handlers = {}
        self._srv.root_dir = self._root_dir
        self._srv.log_message = self.log #link to log method
        self._srv._event = threading.Event()
        self.log("%s started ... " % __ws_name__)
        self.log("(address=%s; port=%d; dir=%s)" % (self._bind, self._port, self._root_dir))
        #self.setDaemon(True)
        self.start()
    
    def stopWS(self) -> None:
        """
        Stop web server
        """
        if self._srv != None:
            self._srv.shutdown()
            del self._srv
            self._srv = None
    
    def run(self):
        self._srv.serve_forever()
    
    def setLog(self, file_descriptor) -> None:
        """
        Set log stream
        
        :param file_descriptor: stream object where write logs
        :type file_descriptor: stream
        """
        self._log = file_descriptor
    
    def numRequests(self) -> int:
        """
        :return: number of buffered requests
        :rtype: int
        """
        return len(self._srv.http_requests)
    
    def nextRequest(self) -> HttpMessage:
        """
        Return a bufered request as object
        (if no Request is buffered, None is returned)
        
        :return: request as object
        :rtype: HttpMessage
        """
        req = None
        if len(self._srv.http_requests) > 0:
            req = self._srv.http_requests.pop(0)
        return req
    
    def setResponse(self, response: HttpMessage) -> None:
        """
        Set a Response as HttpMessage
        
        :param response: containers with all data of response
        :type response: HttpMessage
        """
        self._srv.handlers[(response.command, response.path)] = response
    
    def removeResponse(self, response: HttpMessage) -> None:
        """
        Remove a Response
        
        :param response: only command and path are used
        :type response: HttpMessage
        """
        key = (response.command, response.path)
        if key in self._srv.handlers:
            del self._srv.handlers[key]
    
    def wait(self) -> None:
        """
        Wait a request (lock until at least a request is processed)
        """
        self._srv._event.wait()
        self._srv._event.clear()
    
    def log(self, message: HttpMessage):
        if self._logstream != None:
            self._logstream.write(str(message))
            self._logstream.write(os.linesep)
            self._logstream.flush()


class WebClient:
    """
    A simple class to make HTTP requests (and get response)
    
    If a method do<Verb> is called, connection remain open and can be reused (without re-init object)
    At the end connection must be closed
    """
    def __init__(self, host: str, port: int = 80):
        self._host = host
        self._port = port
        self._conn = http.client.HTTPConnection(host, port)
    
    def _resp2msg(response: http.client.HTTPResponse, command: str, url: str) -> HttpMessage:
        """ convert a http.client.HttpResponse into HttpMessage (connection must be open)"""
        headers = {}
        for (name,value) in response.getheaders():
            headers[name] = value
        
        data = None
        if "Content-Length" in headers:
            length = int(headers["Content-Length"])
            data = response.read(length)
        if "Transfer-Encoding" in headers and headers["Transfer-Encoding"] == "chunked":
            data = response.read()
        
        proto = "HTTP/1.0" #default
        if response.version == 9:
            proto = "HTTP/0.9"
        elif response.version == 10:
            proto = "HTTP/1.0"
        elif response.version == 11:
            proto = "HTTP/1.1"
        
        resp_msg = HttpMessage(URL = url,
                                headers = headers,
                                command = command,
                                code = response.status,
                                data = data,
                                protocol_version = proto)
        return resp_msg
        
    @staticmethod
    def doRequest(request: HttpMessage) -> HttpMessage:
        """
        Make a Request and return a Response
        (close conection after request)
        
        :param request: all informations needed for a request as HttpMessage
        :type request: HttpMessage
        """
        host = request.host
        port = request.port
        conn = http.client.HTTPConnection(host, port)
        conn.request(request.command, request.path, body = request.data, headers = request.headers)
        resp = conn.getresponse()
        uri = urllib.parse.urlunsplit(request._uri_comp) #'friend' access
        resp_msg = WebClient._resp2msg(resp, request.command, uri)
        conn.close()
        return resp_msg
    
    def _doRequest(self, command: str, url: str, data: any = None, headers: dict = {}) -> HttpMessage:
        """
        Make a Request and return a Response
        (do NOT close conection after request)
        
        :param command: HTTP verb
        :type command: str
        :param url: URL to connect to
        :type url: str
        :param data: data sent to server
        :type data: any (optional)
        :param headers: headers (as dictionary name -> value)"
        :type headers: dict
        """
        self._conn.request(command, url, body=data, headers = headers)
        resp = self._conn.getresponse()
        resp_msg = WebClient._resp2msg(resp, command, url)
        return resp_msg
    
    def doPOST(self, url: str, data: any, headers: dict = {}) -> HttpMessage:
        return self._doRequest("POST", url, data = data, headers = headers)
    
    def doPUT(self, url: str, headers: dict = {}) -> HttpMessage:
        return self._doRequest("PUT", url, data = data, headers = headers)
    
    def doGET(self, url: str, headers: dict = {}) -> HttpMessage:
        return self._doRequest("GET", url, headers = headers)
    
    def doHEAD(self, url: str, headers: dict = {}) -> HttpMessage:
        return self._doRequest("HEAD", url, headers = headers)
    
    def close(self):
        self._conn.close()
    
    def __del__(self):
        self.close()
        

def do_tests() -> None:
    """
    Build a suite with all test cases (TestCase sub-classes) and execute them
    """
    test_cases = (WebClientTests, WebServerTests, ) #all test classes here
    
    suite = unittest.TestSuite()
    test_loader = unittest.TestLoader()
    
    for test_class in test_cases:
        tests = test_loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    runner = unittest.TextTestRunner(verbosity=2, failfast=False)
    runner.run(suite)

class WebClientTests(unittest.TestCase):
    def setUp(self):
        pass
    
    def test_GET(self):
        """
        Try to connect with a GET to google site
        (either maintaining connection or closing after a request)
        """
        site = "www.google.com"
        cl = WebClient(site)
        res = cl.doGET("/")
        self.assertEqual(res.httpcode, 200)
        self.assertGreater(len(res.data), 0)
        res = cl.doGET("/", {}) #again, without close connection
        cl.close()
        
        msg = HttpMessage(URL = "http://"+site, headers = {}, command = "GET")
        res = WebClient.doRequest(msg)
        self.assertGreater(len(res.data), 0)
   
    def test_POST(self):
        """
        post a JSON on a mock site
        (mock site jsonplaceholder.typicode.com is used);
        note that reading message posted is not is not the same, cause is mock!
        """
        site = "jsonplaceholder.typicode.com"
        URL = "/posts"
        postm_msg = '{"id": 100, "userId": 34, "title": "test", "body": "Hello World"}'
        cl = WebClient(site)
        res1 = cl.doPOST(URL, data = postm_msg, headers = {"Content-Type": "application/json"})
        self.assertEqual(res1.httpcode, 201)
        res2 = cl.doGET(URL+"/100")
        self.assertEqual(res2.httpcode, 200)
        msg = json.loads(res2.data)
        self.assertEqual(msg["id"], 100)
        cl.close()
    
    def tearDown(self):
        pass

class WebServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._ws = WebServer() #use default settings
        cls._ws.startWS()
    
    def setUp(self):
        pass
    
    def test_hello(self):
        """
        Read 'Hello.txt' in root
        (a file must be present)
        TEst also tracing by web server
        """
        msg = HttpMessage(URL = "http://127.0.0.1/Hello.txt", command = "GET")
        res = WebClient.doRequest(msg)
        self.assertEqual(res.data, b"Hello!")
        srv_req = self._ws.nextRequest() #get tracing server-side
        self.assertNotEqual(srv_req, None)
        self.assertEqual(srv_req.path, "/Hello.txt")
        self.assertEqual(srv_req.command, "GET")
    
    def test_index(self):
        """
        Read root dir
        (getting a JSON file named index.json)
        """
        msg = HttpMessage(URL = "http://127.0.0.1/", command = "GET")
        res = WebClient.doRequest(msg)
        self.assertEqual(res.httpcode, 200)
        self.assertTrue("Content-Type" in res.headers)
        self.assertEqual(res.headers["Content-Type"], "application/json")
        self.assertGreater(len(res.data), 0)
    
    def test_injection(self):
        """
        Test an inkected response
        """
        resp = HttpMessage(URL = "http://127.0.0.1/fakefile.txt",
                        command = "POST",
                        headers = {"Content-Type": "application/json"},
                        data = '{"response" = null}',
                        code = 201)
        self._ws.setResponse(resp)
        
        req1 = HttpMessage(URL = "http://127.0.0.1/fakefile.txt", command = "GET")
        res = WebClient.doRequest(req1)
        self.assertEqual(res.httpcode, 404)
        
        req2 = HttpMessage(URL = "http://127.0.0.1/fakefile.txt", command = "POST", data = '{"id": -1}')
        res = WebClient.doRequest(req2)
        self.assertEqual(res.httpcode, 201)
        self.assertTrue("Content-Type" in res.headers)
        self.assertEqual(res.headers["Content-Type"], "application/json")
        self.assertEqual(res.data, b'{"response" = null}') #note that server store bytes as data
        self.assertEqual(res.data.decode("UTF-8"), '{"response" = null}') #redundant assertion: example to convert bytes in string
    
    def tearDown(self):
        pass
    
    @classmethod
    def tearDownClass(cls):
        cls._ws.stopWS()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--bind", default = "0.0.0.0", type = str, nargs = 1, help="bind address - default: all interfaces")
    parser.add_argument("-p", "--port", type = int, nargs = 1, default = 80, help="listening port - default: 80")
    parser.add_argument("-d", "--root_dir", type = str, nargs = 1, default = os.getcwd(), help="root directory of web server - default: working dir")
    parser.add_argument("-t", "--test", action='store_true', help="do automated self test")
    args = parser.parse_args()
    
    if args.test:
        do_tests()
        sys.exit(0)
    
    #read values
    bind=args.bind
    port = args.port
    ws_root = args.root_dir
    
    ws = WebServer(bind = bind,
        port = port,
        root_dir = ws_root,
        logstream = sys.stdout)
    try:
        ws.startWS()
        while True:
            ch = sys.stdin.read(1) #IO-blocking operation that can be interrupted by CTRL-C
            if ch == 'q' or ch == 'Q': #accept 'Quit' (but ENTER pression is needed)
                break
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received, exiting.")
        ws.stopWS()
        sys.exit(0)
