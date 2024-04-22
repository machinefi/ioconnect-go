package main

//#cgo CFLAGS: -I./include
//#include <hello.h>
import "C"

func main() {
	C.SayHello(C.CString("Hello World!"))
}
