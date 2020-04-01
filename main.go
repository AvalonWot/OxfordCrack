package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
)

var (
	encryptKey = []byte("dicdc155d6741e79c8970be327c4a1c8caa")
	serverTime = 1583845718
)

func main() {
	fmt.Printf("%.0f\n", 1583845718.0)
	cipher, err := ioutil.ReadFile("data/send_enrypt.bin")
	if err != nil {
		log.Panicf("读取加密文件失败: %v", err)
	}
	var key bytes.Buffer
	key.Write(encryptKey)
	key.Write([]byte(fmt.Sprintf("%d", serverTime)))
	if err := d_dcalc1(cipher, key.Bytes()); err != nil {
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

func d_dcalc1(cipher []byte, key []byte) error {
	mix1, mix2, mix3 := int32(0xBF80A), int32(0x23), int32(0xD)
	buf := bytes.NewReader(cipher)
	head1 := int32(readu16(buf))
	head2 := int32(readu16(buf))
	flags := readubyte(buf) ^ byte(head1) ^ byte(head2)
	fmt.Printf("flags: 0x%x", flags)
	if ((flags >> 6) & 1) == 1 {
		head1 = (mix2 + head1*mix3 + head2 + int32(key[3])) % mix1
		head2 = (mix3 + head2*mix2 + head1 + int32(key[4])) % mix1
		exc1, exc2 := readu16(buf), readu16(buf)
		clen := len(cipher) - 13
		log.Printf("(%04x, %04x), (%04x, %04x)",
			exc1^uint16(clen>>16), exc2^uint16(clen), uint16(head1), uint16(head2))
		pbuf := cipher[13:]
		org := int32(0)
		out := make([]byte, len(pbuf))
		for i := 0; i < len(out); i++ {
			k := int32(key[i%len(key)])
			head1 = (mix2 + org + head1*mix3 + head2 + k) % mix1
			head2 = (mix3 + head2*mix2 + head1 + k) % mix1
			out[i] = byte(int32(pbuf[i]) ^ head2 ^ head1)
			org = int32(out[i])
		}
		log.Println(string(out))
	}
	return nil
}
