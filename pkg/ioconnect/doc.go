package ioconnect

//#cgo CFLAGS: -I./include
//#include <ioconnect.h>
//#include <string.h>
import "C"
import (
	"unsafe"

	"github.com/pkg/errors"
)

func NewDIDDoc(content []byte) (*DIDDoc, error) {
	doc := &DIDDoc{}

	c_content := C.CString(string(content))
	defer C.free(unsafe.Pointer(c_content))

	doc._ptr = C.iotex_diddoc_parse(c_content)
	if doc._ptr == nil {
		return nil, errors.New("failed to parse did doc")
	}
	return doc, nil
}

// DIDDoc wrap c-language did doc struct
type DIDDoc struct {
	_ptr *C.DIDDoc
}

func (doc *DIDDoc) parse(purpose VerificationMethodPurpose) (k *JWK, err error) {
	c_purpose := purpose.CEnum()
	num := C.iotex_diddoc_verification_method_get_num(doc._ptr, c_purpose)
	if num == 0 {
		return nil, errors.Errorf("verification method not exists")
	}

	vm := C.iotex_diddoc_verification_method_get(doc._ptr, c_purpose, num-1)
	if vm == nil {
		return nil, errors.Errorf("failed to get verification method by purpose: vm is nil")
	}
	defer C.iotex_verification_method_info_destroy(vm)

	_ptr := *(**C.JWK)(unsafe.Pointer(&vm.pk_u))
	if _ptr == nil {
		return nil, errors.Errorf("failed to get verification method by purpose: union pk_u is nil")
	}

	var struct_jwk C.JWK
	var size = (C.ulong)(unsafe.Sizeof(struct_jwk))

	ptr := C.malloc(size)
	C.memcpy(unsafe.Pointer(ptr), unsafe.Pointer(_ptr), size)

	k = &JWK{_ptr: (*C.JWK)(unsafe.Pointer(ptr))}

	if err = k.init(); err != nil {
		return nil, err
	}

	return k, nil
}

func (doc *DIDDoc) ParseJWK() (*JWK, error) {
	k, err := doc.parse(VerificationMethodPurpose_Authentication)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse master jwk from did doc")
	}
	ka, err := doc.parse(VerificationMethodPurpose_KeyAgreement)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse key agreement jwk from did doc")
	}
	k.ka = ka
	if err = k.register(); err != nil {
		return nil, err
	}
	return k, nil
}

func (doc *DIDDoc) Destroy() {
	if doc._ptr != nil {
		C.iotex_diddoc_destroy(doc._ptr)
		doc._ptr = nil
	}
}
