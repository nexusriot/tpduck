package main

import (
	"fmt"
	"os"
	"time"

	"github.com/nexusriot/tpduck/internal/controller"
	"github.com/nexusriot/tpduck/internal/model"
	"github.com/nexusriot/tpduck/internal/view"
)

func main() {
	store, path, err := model.LoadStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load store: %v\n", err)
		os.Exit(1)
	}

	v := view.New()
	c := controller.New(store, path, v)
	c.Start(time.Millisecond * 250) // UI refresh period
}
