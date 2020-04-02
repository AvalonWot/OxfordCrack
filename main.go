package main

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
)

var (
	encryptKey = []byte("dicdc155d6741e79c8970be327c4a1c8caa")
	decryptKey = []byte("dicb0e1fee7b3c3b7142be3e20b760439c0")
)

func main() {
	decrypt_send("data/1.2.7_1583845718_send.bin", 1583845718)
	decrypt_recv("data/1.2.7_1583845718_recv.bin", 1583845718)
}

func decrypt_send(file string, t uint32) {
	cipher, err := ioutil.ReadFile(file)
	if err != nil {
		log.Panicf("读取加密文件失败: %v", err)
	}
	var key bytes.Buffer
	key.Write(encryptKey)
	key.Write([]byte(fmt.Sprintf("%d", t)))
	if err := decrypt(cipher, key.Bytes()); err != nil {
		log.Panicf("解密失败: %v", err)
	}
}

func decrypt_recv(file string, t uint32) {
	cipher, err := ioutil.ReadFile(file)
	if err != nil {
		log.Panicf("读取加密文件失败: %v", err)
	}
	var key bytes.Buffer
	key.Write(decryptKey)
	key.Write([]byte(fmt.Sprintf("%d", t)))
	if err := decrypt(cipher, key.Bytes()); err != nil {
		log.Panicf("解密失败: %v", err)
	}
}

func readu16(r io.Reader) uint16 {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		log.Panicf("读取失败: %v", err)
	}
	return n
}

func readubyte(r io.ByteReader) byte {
	n, err := r.ReadByte()
	if err != nil {
		log.Panicf("读取失败: %v", err)
	}
	return n
}

func decrypt(cipher []byte, key []byte) error {
	mix1, mix2, mix3 := int32(0xBF80A), int32(0x23), int32(0xD)
	buf := bytes.NewReader(cipher)
	head1 := int32(readu16(buf))
	head2 := int32(readu16(buf))
	flags := readubyte(buf) ^ byte(head1) ^ byte(head2)
	fmt.Printf("flags: 0x%x\n", flags)
	compress := (flags>>7)&1 == 1
	log.Printf("compress: %v", compress)
	ext := int((flags >> 4) & 3)
	log.Printf("ext: %v", ext)
	ext *= 2
	var pbuf []byte
	var crx [24]byte
	if ((flags >> 6) & 1) == 1 {
		head1 = (mix2 + head1*mix3 + head2 + int32(key[3])) % mix1
		head2 = (mix3 + head2*mix2 + head1 + int32(key[4])) % mix1
		exc1, exc2 := readu16(buf), readu16(buf)
		clen := len(cipher) - 13
		log.Printf("(%04x, %04x), (%04x, %04x)",
			exc1^uint16(clen>>16), exc2^uint16(clen), uint16(head1), uint16(head2))
		if (exc1^uint16(clen>>16) == uint16(head1)) && (exc2^uint16(clen) == uint16(head2)) {
			log.Println("verify ok")
		} else {
			return errors.New("校验失败")
		}
		pbuf = cipher[9+ext:]
		copy(crx[:ext], cipher[9:9+ext])
	} else {
		pbuf = cipher[9:]
	}

	org := int32(0)
	out := make([]byte, len(pbuf))
	for i := 0; i < len(out); i++ {
		k := int32(key[i%len(key)])
		head1 = (mix2 + org + head1*mix3 + head2 + k) % mix1
		head2 = (mix3 + head2*mix2 + head1 + k) % mix1
		out[i] = byte(int32(pbuf[i]) ^ head2 ^ head1)
		org = int32(out[i])
		if ext != 0 {
			log.Printf("[%d] crt[%d]: %d, org: %d", i, i%ext, crx[i%ext], org)
			crx[i%ext] = crx[i%ext] ^ out[i]
		}
	}
	if ext != 0 {
		for i := 0; i < ext; i++ {
			if crx[i] != 0 {
				return errors.New("校验ext失败")
			}
		}
	}
	if compress {
		r, err := zlib.NewReader(bytes.NewReader(out))
		if err != nil {
			return err
		}
		out, err = ioutil.ReadAll(r)
		if err != nil {
			return err
		}
	}
	log.Println(string(out))
	return nil
}
