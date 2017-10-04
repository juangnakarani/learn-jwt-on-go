![Cara test dengan postman](./img/gotojwt.gif)

// New returns a new Negroni instance with no middleware preconfigured.
func New(handlers ...Handler) *Negroni {
	return &Negroni{
		handlers:   handlers,
		middleware: build(handlers),
	}
}