package ioconnect

//#cgo CFLAGS: -I./include
//#include <ioconnect.h>
import "C"

func init() {
	status := C.psa_crypto_init()
	if status != C.PSA_SUCCESS {
		panic("failed init psa crypto")
	}
}
