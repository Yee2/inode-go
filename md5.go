package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"fmt"
)

func h3c_md5(data []byte) {
	//data := [...]byte{
	//	0xcf, 0xfe, 0x64, 0x73, 0xd5, 0x73, 0x3b, 0x1f,
	//	0x9e, 0x9a, 0xee, 0x1a, 0x6b, 0x76, 0x47, 0xc8,
	//	0x9e, 0x27, 0xc8, 0x92, 0x25, 0x78, 0xc4, 0xc8,
	//	0x27, 0x03, 0x34, 0x50, 0xb6, 0x10, 0xb8, 0x35,
	//}
	if len(data) != 32{
		panic("error")
	}
	key := []byte{0xEC, 0xD4, 0x4F, 0x7B, 0xC6, 0xDD, 0x7D, 0xDE, 0x2B, 0x7B, 0x51, 0xAB, 0x4A, 0x6F, 0x5A, 0x22}
	IV1 := []byte{'a', '@', '4', 'd', 'e', '%', '#', '1', 'a', 's', 'd', 'f', 's', 'd', '2', '4'}
	IV2 := []byte{'a', '@', '4', 'd', 'e', '%', '#', '1', 'a', 's', 'd', 'f', 's', 'd', '2', '4'}

	// step 2
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	decrypter := cipher.NewCBCDecrypter(block, IV1)
	decrypter.CryptBlocks(data[:], data[:])

	// step 3
	index := binary.BigEndian.Uint32(data[0:4])
	offset := int(data[4])
	length := int(data[5])
	fmt.Printf("索引:0x%08x 偏移:%d 长度:%d \n",index,offset,length)
	md5data1 := make([]byte, length)
	if list, ok := table[index]; ok {
		copy(md5data1, list[offset:])
	} else if list, ok := table[0xCCF59F07]; ok {
		copy(md5data1, list[offset:])
		fmt.Printf("lookup dict failed.\n")
	}

	// step 4
	key2 := md5.Sum(md5data1)

	// step 5 && step 6
	block, err = aes.NewCipher(key2[:])
	if err != nil {
		panic(err)
	}
	decrypter = cipher.NewCBCDecrypter(block, IV2)
	decrypter.CryptBlocks(data[16:], data[16:])

	// step 7
	index = binary.BigEndian.Uint32(data[16+10 : 16+14])
	offset = int(data[16+14])
	length = int(data[16+15])
	fmt.Printf("索引:0x%08x 偏移:%d 长度:%d \n",index,offset,length)

	md5data2 := make([]byte, length)
	if list, ok := table[index]; ok {
		copy(md5data2, list[offset:])
	} else if list, ok := table[0xCCF59F07]; ok {
		fmt.Printf("lookup dict failed.\n")
		copy(md5data2, list[offset:])
	}

	// step 8 && step 9
	copy(data[:], append(md5data1, md5data2...))
	// step 10
	md5first := md5.Sum(data[:])
	md5second := md5.Sum(md5first[:])
	copy(data[:], md5first[:])
	copy(data[16:], md5second[:])
	fmt.Printf("md5 data:%x\n",data)
}
