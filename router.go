package hockeypuck

import (
	"code.google.com/p/gorilla/mux"
	"flag"
	"go/build"
	"html/template"
	Errors "launchpad.net/hockeypuck/errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

const INSTALL_WEBROOT = "/var/lib/hockeypuck/www"
const HOCKEYPUCK_PKG = "launchpad.net/hockeypuck" // Any way to introspect?

// Path to Hockeypuck's installed www directory
func init() {
	flag.String("webroot", "",
		"Location of static web server files and templates")
}
func (s *Settings) Webroot() string {
	webroot := s.GetString("webroot")
	if webroot != "" {
		return webroot
	}
	if fi, err := os.Stat(INSTALL_WEBROOT); err == nil && fi.IsDir() {
		webroot = INSTALL_WEBROOT
	} else if p, err := build.Default.Import(HOCKEYPUCK_PKG, "", build.FindOnly); err == nil {
		try_webroot := filepath.Join(p.Dir, "instroot", INSTALL_WEBROOT)
		if fi, err := os.Stat(try_webroot); err == nil && fi.IsDir() {
			webroot = try_webroot
		}
	}
	s.Set("webroot", webroot)
	return webroot
}

type StaticRouter struct {
	*mux.Router
}

func NewStaticRouter(r *mux.Router) *StaticRouter {
	sr := &StaticRouter{Router: r}
	sr.HandleAll()
	return sr
}

func (sr *StaticRouter) HandleAll() {
	sr.HandleMainPage()
	sr.HandleFonts()
	sr.HandleCss()
}

var MainTemplate *template.Template

func InitTemplates() {
	var err error
	MainTemplate, err = newMainTemplate()
	if err != nil {
		log.Println(err)
		MainTemplate = nil
	}
}

func newMainTemplate() (*template.Template, error) {
	files, err := filepath.Glob(
		filepath.Join(Config().Webroot(), "templates", "*.tmpl"))
	// For now, default to OpenPGP search page.
	files = append(files, filepath.Join(
		Config().Webroot(), "templates", "hkp", "index", "search_form.tmpl"))
	if err != nil {
		return nil, err
	}
	return template.ParseFiles(files...)
}

func (sr *StaticRouter) HandleMainPage() {
	sr.HandleFunc("/",
		func(resp http.ResponseWriter, req *http.Request) {
			var err error
			if MainTemplate == nil {
				err = Errors.ErrTemplatePathNotFound
			} else {
				err = MainTemplate.ExecuteTemplate(resp, "layout", nil)
			}
			if err != nil {
				http.Error(resp, err.Error(), 500)
			}
		})
}

func (sr *StaticRouter) HandleFonts() {
	sr.HandleFunc(`/fonts/{filename:.*\.ttf}`,
		func(resp http.ResponseWriter, req *http.Request) {
			filename := mux.Vars(req)["filename"]
			path := filepath.Join(Config().Webroot(), "fonts", filename)
			if stat, err := os.Stat(path); err != nil || stat.IsDir() {
				http.NotFound(resp, req)
				return
			}
			http.ServeFile(resp, req, path)
		})
}

func (sr *StaticRouter) HandleCss() {
	sr.HandleFunc(`/css/{filename:.*\.css}`,
		func(resp http.ResponseWriter, req *http.Request) {
			filename := mux.Vars(req)["filename"]
			path := filepath.Join(Config().Webroot(), "css", filename)
			if stat, err := os.Stat(path); err != nil || stat.IsDir() {
				http.NotFound(resp, req)
				return
			}
			http.ServeFile(resp, req, path)
		})
}
