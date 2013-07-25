package hkp

import (
	"code.google.com/p/gorilla/mux"
)

type Service struct {
	Requests RequestChan
}

func NewService() *Service {
	return &Service{make(RequestChan)}
}

type Router struct {
	*mux.Router
	*Service
}

func NewRouter(r *mux.Router) *Handler {
	return &Handler{Router: r, Service: NewService()}
}

func (h *Handler) HandleAll() {
	h.HandlePksLookup()
	h.HandlePksAdd()
	h.HandlePksHashQuery()
}

func (h *Handler) Respond(req Request) {
	err := req.Parse()
	if err != nil {
		h.RespondError(w, err)
		return
	}
	h.Requests <- req
	return h.RespondWith(w, req)
}

func (h *Handler) RespondError(w http.ResponseWriter, err error) error {
	log.Println("Bad request:", err)
	w.WriteHeader(http.StatusBadRequest)
	return w.Write([]byte(err.Error()))
}

func (h *Handler) HandlePksLookup() {
	h.HandleFunc("/pks/lookup",
		func(w http.ResponseWriter, req *http.Request) {
			h.Respond(&Lookup{Request: req})
		})
}

func (h *Handler) HandlePksAdd() {
	h.HandleFunc("/pks/add",
		func(w http.ResponseWriter, req *http.Request) {
			h.Respond(&Add{Request: req})
		})
}

func (h *Handler) HandlePksHashQuery() {
	h.HandleFunc("/pks/hashquery",
		func(w http.ResponseWriter, req *http.Request) {
			h.Respond(&HashQuery{Request: req})
		})
}
