# lerproxy

Command lerproxy implements https reverse proxy with automatic LetsEncrypt
usage for multiple hostnames/backends including a static filesystem directory, nostr 
[NIP-05](https://github.com/nostr-protocol/nips/blob/master/05.md) hosting ~~and URL rewriting (TODO)~~.

## Install

	go install lerproxy.mleku.dev@latest

## Run

	lerproxy -addr :https -map /path/to/mapping.txt -cacheDir /path/to/letsencrypt

`mapping.txt` contains host-to-backend mapping, where backend can be specified
as:

* http/https url for http(s) connections to backend *without* passing "Host"
  header from request;
* host:port for http over TCP connections to backend;
* absolute path for http over unix socket connections;
* @name for http over abstract unix socket connections (linux only);
* absolute path with a trailing slash to serve files from a given directory;
* path to a nostr.json file containing a
  [nip-05](https://github.com/nostr-protocol/nips/blob/master/05.md) and 
  hosting it at `https://example.com/.well-known/nostr.json`
* using the prefix `git+` and a full web address path after it, generate html 
  with the necessary meta tags that indicate to the `go` tool when fetching 
  dependencies from the address found after the `+`. You must have subdomain 
  wildcard 

## example mapping.txt

    nostr.example.com: /path/to/nostr.json
	subdomain1.example.com: 127.0.0.1:8080
	subdomain2.example.com: /var/run/http.socket
	subdomain3.example.com: @abstractUnixSocket
	uploads.example.com: https://uploads-bucket.s3.amazonaws.com
	# this is a comment, it can only start on a new line
	static.example.com: /var/www/
    awesome-go-project.example.com: git+https://github.com/crappy-name/crappy-go-project-name

Note that when `@name` backend is specified, connection to abstract unix socket
is made in a manner compatible with some other implementations like uWSGI, that
calculate addrlen including trailing zero byte despite [documentation not
requiring that](http://man7.org/linux/man-pages/man7/unix.7.html). It won't
work with other implementations that calculate addrlen differently (i.e. by
taking into account only `strlen(addr)` like Go, or even `UNIX_PATH_MAX`).

## systemd service file

```
[Unit]
Description=lerproxy

[Service]
ExecStart=/usr/local/bin/lerproxy -m /path/to/mapping.txt -l xxx.xxx.xxx.xxx:443 --http xxx.xxx.xxx.6:80
User=prox

[Install]
WantedBy=multi-user.target
```
