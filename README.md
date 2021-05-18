# Mock Web Server


## Introduction

This is a _Real_ Mock Web Server, because is a real Web Server, but It can also be controlled programmatically


## Description

__**Mock Web Server**__ mainly offers file from FS, but can also offer pre-defined responses (injected programmatically).
Moreover it trace all requests, and all information are logged as `HttpMessage`

Main features are:
* works only for HTTP (not for HTTPS)
* serve static file from a specified directory
* guess _Content-Type_ from extension
* trace requests returning `HttpMessage`
* trace requests on file (or stdout or stderr)
* can serve pre-defined responses (associated to HTTP VERB / URL path)
* is mono-thread, but run in a different thread from caller
* can be executed as stand-alone web server from CLI 

The package (file `mock_ws.py`) contains also a Simple Http Client


## CLI Interface

To start stand-alone Web Server CLI syntax is following:
```
python3 mock_ws.py [-t] [-b <bind address>] [-p <port>] [-d <root directory>]
```
where:
* **-t** run internal tests
* **-b <bind address>** specifiy listening address (default: all interfaces)
* **-p <port>** specifiy listening port (default: 80)
* **-d <root directory>** specifiy root directory for web server (default: directory of python source)


## Python Interface

To start web server from python code:

```
import WebServer from mock_ws


fd = open("logfile.txt", "w")

ws = WebServer(bind = "127.0.0.1",
				port = 8080,
				root_dir = "/web/server/root/dir",
				logstream = fd)
ws.startWS()
...
ws.stopWS()
```

Also, a pre-defined response can be set (or overwritten) with method:
```
WebServer.setResponse(msg: HttpMessage)
```
(response is associated to tuple _(HTTP verb , URL path)_ )
and response can be removed with:
```
WebServer.removeResponse(msg: HttpMessage)
```

Moreover, because Web Server run in another thread respect to caller, if a client must lock waiting a response, following method can be used:
* `WebServer.wait()` to wait a request from a client (locking)
* `WebServer.numResquests()` to poll number of requests in queue
* `WebServer.nextRequest()` to enqueue 1 request received (or None if queue is empty)


## Appendix

### `HttpMessage`

`HttpMessage` is a container returned by WebServer with all information of calls
(is also used to forge message to send by Client - `WebClient`)

HttpMessage has following properties:
* **`command`**: HTTP verb (GET, POST, HEAD; ...)
* **`path`**: path part of URL
* **`query`**: query part of URL
* **`host`**: host part of URL
* **`port`**: port part of URL
* **`protocol`**: used protocol ("HTTP/1.0", "HTTP/1.1")
* **`headers`**: headers in form of dictionary (name -> value)
* **`httpcode`**: code of HTTP response (200, 404, etc.)
* **`data`**: HTTP body

Same values can be passed to constructor (URL contains host, port, path and query):
* **`URL`**: complete URL (with host, port, path and query)
* **`protocol_version`**: used protocol ("HTTP/1.0", "HTTP/1.1")
* **`headers`**: headers in form of dictionary (name -> value)
* **`code`**: code of HTTP response (200, 404, etc.)
* **`data`**: HTTP body


### Simple Http Client

A Simple Http client is provided.

It can be called in 2 ways:
```
import WebClient from mock_ws

cl = WebClient(host, port)
cl.doGET(path)
cl.close()
```

or

```
import WebClient from mock_ws

WebClient.doRequest(msg: HttpMessage)
```

1st form leave connection open to same site between different calls, and support unpacked parameters;  
2nd form open_and-close HTTP connectinand accept `HttpMessage` object as request
