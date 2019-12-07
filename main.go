package access_control

import (
	"fmt"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	_, err := fmt.Fprintf(w, "hello casbin")
	if err != nil {
		log.Fatal(err.Error())
	}
}

func main() {
	fmt.Println("hello casbin")
	http.HandleFunc("/", handler)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err.Error())
	}
}
