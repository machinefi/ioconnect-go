package ioconnect

//#cgo CFLAGS: -I./include
//#include <ioconnect.h>
import "C"
import "unsafe"

type EC struct {
	_ptr C.ECParams
}

func (v *EC) Crv() string {
	c := (*C.char)(unsafe.Pointer(&v._ptr.crv[0]))
	return C.GoString(c)
}

func (v *EC) X() string {
	c := (*C.char)(unsafe.Pointer(&v._ptr.x_coordinate[0]))
	return C.GoString(c)
}

func (v *EC) Y() string {
	c := (*C.char)(unsafe.Pointer(&v._ptr.y_coordinate[0]))
	return C.GoString(c)
}

func (v *EC) EccPrivateKey() string {
	c := (*C.char)(unsafe.Pointer(&v._ptr.ecc_private_key[0]))
	return C.GoString(c)
}

type RSA struct {
	_ptr C.RSAParams
}

type Symmetric struct {
	_ptr C.SymmetricParams
}

type Oct struct {
	_ptr C.OctetParams
}
