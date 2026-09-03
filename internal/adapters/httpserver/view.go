package httpserver

import (
	"embed"
	"fmt"
	"html/template"
	"io"
)

//go:embed templates/*.html static/*
var webFiles embed.FS

type renderer struct{}

func (renderer) render(writer io.Writer, page string, fragment bool, data any) error {
	tmpl, err := template.New("base.html").ParseFS(webFiles, "templates/base.html", "templates/"+page+".html")
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}
	name := "layout"
	if fragment {
		name = "card"
	}
	return tmpl.ExecuteTemplate(writer, name, data)
}
