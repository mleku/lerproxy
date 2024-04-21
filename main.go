// Command lerproxy implements https reverse proxy with automatic LetsEncrypt
// usage for multiple hostnames/backends, and URL rewriting capability.
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	stdLog "log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/alexflint/go-arg"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sync/errgroup"
	"mleku.com/git/lerproxy/buf"
	"mleku.com/git/lerproxy/hsts"
	"mleku.com/git/lerproxy/reverse"
	"mleku.com/git/lerproxy/tcpkeepalive"
	"mleku.com/git/lerproxy/util"
	"mleku.com/git/slog"
)

type runArgs struct {
	Addr     string        `arg:"-l,--listen" default:":https" help:"address to listen at"`
	Conf     string        `arg:"-m,--map" default:"mapping.txt" help:"file with host/backend mapping"`
	Rewrites string        `arg:"-r,--rewrites" default:"rewrites.txt"`
	Cache    string        `arg:"-c,--cachedir" default:"/var/cache/letsencrypt" help:"path to directory to cache key and certificates"`
	HSTS     bool          `arg:"-h,--hsts" help:"add Strict-Transport-Security header"`
	Email    string        `arg:"-e,--email" help:"contact email address presented to letsencrypt CA"`
	HTTP     string        `arg:"--http" default:":http" help:"optional address to serve http-to-https redirects and ACME http-01 challenge responses"`
	RTO      time.Duration `arg:"-r,--rto" default:"1m" help:"maximum duration before timing out read of the request"`
	WTO      time.Duration `arg:"-w,--wto" default:"5m" help:"maximum duration before timing out write of the response"`
	Idle     time.Duration `arg:"-i,--idle" help:"how long idle connection is kept before closing (set rto, wto to 0 to use this)"`
}

var args runArgs

var (
	log, chk = slog.New(os.Stderr)
)

func main() {
	slog.SetLogLevel(slog.Trace)
	arg.MustParse(&args)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := run(ctx, args); err != nil {
		log.F.Ln(err)
	}
}

func run(ctx context.Context, args runArgs) (err error) {

	if args.Cache == "" {
		err = log.E.Err("no cache specified")
		return
	}

	var srv *http.Server
	var httpHandler http.Handler
	if srv, httpHandler, err = setupServer(args); chk.E(err) {
		return
	}
	srv.ReadHeaderTimeout = 5 * time.Second
	if args.RTO > 0 {
		srv.ReadTimeout = args.RTO
	}
	if args.WTO > 0 {
		srv.WriteTimeout = args.WTO
	}
	group, ctx := errgroup.WithContext(ctx)
	if args.HTTP != "" {
		httpServer := http.Server{
			Addr:         args.HTTP,
			Handler:      httpHandler,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}
		group.Go(func() (err error) {
			chk.E(httpServer.ListenAndServe())
			return
		})
		group.Go(func() error {
			<-ctx.Done()
			ctx, cancel := context.WithTimeout(context.Background(),
				time.Second)
			defer cancel()
			return httpServer.Shutdown(ctx)
		})
	}
	if srv.ReadTimeout != 0 || srv.WriteTimeout != 0 || args.Idle == 0 {
		group.Go(func() (err error) {
			chk.E(srv.ListenAndServeTLS("", ""))
			return
		})
	} else {
		group.Go(func() (err error) {
			var ln net.Listener
			if ln, err = net.Listen("tcp", srv.Addr); chk.E(err) {
				return
			}
			defer ln.Close()
			ln = tcpkeepalive.Listener{
				Duration:    args.Idle,
				TCPListener: ln.(*net.TCPListener),
			}
			err = srv.ServeTLS(ln, "", "")
			chk.E(err)
			return
		})
	}
	group.Go(func() error {
		<-ctx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	})
	return group.Wait()
}

func setupServer(a runArgs) (s *http.Server, h http.Handler, err error) {
	var mapping map[string]string
	if mapping, err = readMapping(a.Conf); chk.E(err) {
		return
	}
	var proxy http.Handler
	if proxy, err = setProxy(mapping); chk.E(err) {
		return
	}
	if a.HSTS {
		proxy = &hsts.Proxy{Handler: proxy}
	}
	if err = os.MkdirAll(a.Cache, 0700); chk.E(err) {
		err = fmt.Errorf("cannot create cache directory %q: %v",
			a.Cache, err)
		chk.E(err)
		return
	}
	m := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(a.Cache),
		HostPolicy: autocert.HostWhitelist(util.GetKeys(mapping)...),
		Email:      a.Email,
	}
	s = &http.Server{
		Handler:   proxy,
		Addr:      a.Addr,
		TLSConfig: m.TLSConfig(),
	}
	h = m.HTTPHandler(nil)
	return
}

func setProxy(mapping map[string]string) (h http.Handler, err error) {
	if len(mapping) == 0 {
		return nil, fmt.Errorf("empty mapping")
	}
	mux := http.NewServeMux()
	for hostname, backendAddr := range mapping {
		hn, ba := hostname, backendAddr
		if strings.ContainsRune(hn, os.PathSeparator) {
			err = log.E.Err("invalid hostname: %q", hn)
			return
		}
		network := "tcp"
		if ba != "" && ba[0] == '@' && runtime.GOOS == "linux" {
			// append \0 to address so addrlen for connect(2) is calculated in a
			// way compatible with some other implementations (i.e. uwsgi)
			network, ba = "unix", ba+string(byte(0))
		} else if filepath.IsAbs(ba) {
			network = "unix"
			switch {
			case strings.HasSuffix(ba, string(os.PathSeparator)):
				// path specified as directory with explicit trailing slash; add
				// this path as static site
				fs := http.FileServer(http.Dir(ba))
				mux.Handle(hn+"/", fs)
				continue
			case strings.HasSuffix(ba, "nostr.json"):
				var fb []byte
				if fb, err = os.ReadFile(ba); chk.E(err) {
					continue
				}
				mux.HandleFunc(hn+"/.well-known/nostr.json", func(writer http.ResponseWriter, request *http.Request) {
					log.I.Ln("serving nostr json to", hn)
					writer.Header().Set("Access-Control-Allow-Methods", "GET,HEAD,PUT,PATCH,POST,DELETE")
					writer.Header().Set("Access-Control-Allow-Origin", "*")
					fmt.Fprint(writer, string(fb))
				})
				continue
			}
		} else if u, err := url.Parse(ba); err == nil {
			switch u.Scheme {
			case "http", "https":
				rp := reverse.NewSingleHostReverseProxy(u)
				modifyCORSResponse := func(res *http.Response) error {
					res.Header.Set("Access-Control-Allow-Methods", "GET,HEAD,PUT,PATCH,POST,DELETE")
					// res.Header.Set("Access-Control-Allow-Credentials", "true")
					res.Header.Set("Access-Control-Allow-Origin", "*")
					return nil
				}
				rp.ModifyResponse = modifyCORSResponse
				rp.ErrorLog = stdLog.New(os.Stderr, "lerproxy", stdLog.Llongfile)
				rp.BufferPool = buf.Pool{}
				mux.Handle(hn+"/", rp)
				continue
			}
		}
		rp := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = "http"
				req.URL.Host = req.Host
				req.Header.Set("X-Forwarded-Proto", "https")
				req.Header.Set("X-Forwarded-For", req.RemoteAddr)
				req.Header.Set("Access-Control-Allow-Methods", "GET,HEAD,PUT,PATCH,POST,DELETE")
				// req.Header.Set("Access-Control-Allow-Credentials", "true")
				req.Header.Set("Access-Control-Allow-Origin", "*")
				log.D.Ln(req.URL, req.RemoteAddr)
			},
			Transport: &http.Transport{
				DialContext: func(ctx context.Context,
					n, addr string) (net.Conn, error) {

					return net.DialTimeout(network, ba, 5*time.Second)
				},
			},
			ErrorLog:   stdLog.New(io.Discard, "", 0),
			BufferPool: buf.Pool{},
		}
		mux.Handle(hn+"/", rp)
	}
	return mux, nil
}

func readMapping(file string) (m map[string]string, err error) {
	var f *os.File
	if f, err = os.Open(file); chk.E(err) {
		return
	}
	m = make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if b := sc.Bytes(); len(b) == 0 || b[0] == '#' {
			continue
		}
		s := strings.SplitN(sc.Text(), ":", 2)
		if len(s) != 2 {
			err = fmt.Errorf("invalid line: %q", sc.Text())
			log.E.Ln(err)
			chk.E(f.Close())
			return
		}
		m[strings.TrimSpace(s[0])] = strings.TrimSpace(s[1])
	}
	err = sc.Err()
	chk.E(err)
	chk.E(f.Close())
	return
}
