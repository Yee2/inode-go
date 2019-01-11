/*

	sudo apt-get install libpcap-dev

 */
package main

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
	"math/rand"
	"net"
	"os"
	"time"
)

const (
	EAPTypeMD5 = 0x04

	// 在 njit-client 项目里面是 ALLOCATED 代码
	EAPTypeAllocated = 0x07
	EAPCodeH3CData   = 0x0A
)

/*
			E63018: The user does not exist or has not subscribed to this service
			E63034: Incorrect LDAP password, you will be added to the blacklist
			E63025: Failed to check MAC address binding
			E63013: User is already in the blacklist
			E63032: Incorrect password. The user will be added into blacklist
			E63100: The authentication client version is invalid
			E63635: The number of online endpoints reaches the maximum in the current scenario
 */
var (
	BroadcastAddr = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} // 广播MAC地址
	MultcastAddr  = []byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03} // 多播MAC地址
	H3CKeyOld     = []byte("Oly5D62FaE94W7")
	H3CkeyNew     = []byte("HuaWei3COM1X")
)

func New(device string, username, password string, version string) (*inode, error) {
	iface, err := net.InterfaceByName(device)
	if err != nil {
		return nil, err
	}
	handle, err := pcap.OpenLive(device, 65536, true, time.Second*2)
	if err != nil {
		return nil, err
	}

	// 设置过滤
	if err = handle.SetBPFFilter(
		fmt.Sprintf("(ether proto 0x888e) and (ether dst host %s)", iface.HardwareAddr),
	);
		err != nil {
		return nil, err
	}
	var v []byte
	if !bytes.HasPrefix([]byte(version), []byte("CHx11")) {
		v = append([]byte("CHx11"), []byte(version)...)
	} else {
		v = []byte(version)
	}
	vv := makeVersion(v)
	fmt.Printf("[  ] Version:%s\n", v)
	return &inode{
		device:   device,
		client:   []byte(iface.HardwareAddr),
		handle:   handle,
		source:   gopacket.NewPacketSource(handle, handle.LinkType()),
		username: username,
		password: password,
		version:  vv,
	}, nil
}

type inode struct {
	// 网卡名称
	device string
	// 本地MAC地址
	client []byte
	// 服务器MAC地址
	server             []byte
	handle             *pcap.Handle
	source             *gopacket.PacketSource
	username, password string
	EthernetHeader     gopacket.SerializableLayer
	version            []byte
	ip                 []byte

	// 发送IP地址，我们学校并不需要发送IP地址
	sendIP  bool
	md5data []byte
}

func (p *inode) Loop() (err error) {
	return nil
}
func (p *inode) Start() (err error) {
	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
		&layers.Ethernet{SrcMAC: p.client, DstMAC: BroadcastAddr, EthernetType: layers.EthernetTypeEAPOL},
		&layers.EAPOL{Version: 0x01, Type: layers.EAPOLTypeStart},
	)
	if err != nil {
		return err
	}
	fmt.Printf("[  ] Client: Start.\n")
	err = p.handle.WritePacketData(buffer.Bytes())
	if err != nil {
		return errors.Wrap(err, "Request failed")
	}

	var packet gopacket.Packet
	for i := 0; i < 10; i++ {
		fmt.Printf("[%02X] Waiting for server response\n", i)
		packet, err = p.source.NextPacket()
		if err != nil {
			continue
		}
		break
	}
	if err != nil {
		fmt.Printf("Server not responding:%s\n", err)
		os.Exit(0)
	}
	eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	resp := packet.Layer(layers.LayerTypeEAP).(*layers.EAP)
	if resp == nil || eth == nil {
		return errors.New("Wrong data")
	}

	p.server = eth.SrcMAC
	p.EthernetHeader = &layers.Ethernet{SrcMAC: p.client, DstMAC: p.server, EthernetType: layers.EthernetTypeEAPOL}

	fmt.Printf("[  ] Server MAC:%02x:%02x:%02x:%02x:%02x:%02x\n",
		p.server[0],
		p.server[1],
		p.server[2],
		p.server[3],
		p.server[4],
		p.server[5],
	)
	// 重设过滤器，只捕获华为802.1X认证设备发来的包（包括多播Request Identity / Request AVAILABLE）
	fmt.Printf("[  ] SetBPFFilter: (ether proto 0x888e) and (ether src host %02x:%02x:%02x:%02x:%02x:%02x)\n",
		p.server[0],
		p.server[1],
		p.server[2],
		p.server[3],
		p.server[4],
		p.server[5],
	)
	err = p.handle.SetBPFFilter(
		fmt.Sprintf("(ether proto 0x888e) and (ether src host %02x:%02x:%02x:%02x:%02x:%02x)",
			p.server[0],
			p.server[1],
			p.server[2],
			p.server[3],
			p.server[4],
			p.server[5],
		),
	)
	if err != nil {
		return errors.Wrap(err, "Reset filter failed")
	}

	for {
		switch resp.Code {
		case layers.EAPCodeRequest:
			switch resp.Type {
			case layers.EAPTypeIdentity:
				fmt.Printf("[%02X] Server: Request Identity!\n", resp.Id)
				p.ResponseIdentity(resp)
			case layers.EAPTypeNotification:
				fmt.Printf("[%02X] Server: Request Notification!\n", resp.Id)
				p.ResponseNotification(resp)
			case EAPTypeMD5:
				fmt.Printf("[%02X] Server: Request MD5-Challenge!\n", resp.Id)
				p.ResponseMD5(resp)
			case EAPTypeAllocated:
				// 明文回复用户名和密码
				fmt.Printf("[%02X] Server: Request Allocated!\n", resp.Id)
				p.ResponseH3C(resp)
			case 20:
				// AVAILABLE
				// 遇到AVAILABLE包时需要特殊处理
				// 中南财经政法大学目前使用的格式：
				// 收到第一个Request AVAILABLE时要回答Response Identity
				// TODO
				panic("Received AVAILABLE")
			}
		case layers.EAPCodeResponse:
			fmt.Printf("Unknown information:%s\n", resp.TypeData)
		case layers.EAPCodeFailure:
			message := make([]byte, int(resp.TypeData[0]))
			if int(resp.TypeData[0]) < 6 {
				return errors.New(fmt.Sprintf("Unknown information:%x\n", resp.TypeData))
			}
			n := copy(message, resp.TypeData[1:])
			message = message[0:n]
			switch string(message[0:6]) {
			case "E63018", "E63034", "E63025", "E63013", "E63032", "E63635":
				return errors.New(fmt.Sprintf("[  ] error:%s\n", message))
			case "E63100":
				// 提示版本错误，但是依旧可以正常上网
				fmt.Printf("[  ] E63100:The authentication client version is invalid\n")
			default:
				return fmt.Errorf("[  ] Unknown information:%s\n", message)
			}
		case layers.EAPCodeSuccess:
			fmt.Printf("[%02X] Server: Success.\n", resp.Id)
		case EAPCodeH3CData:
			// 这一部分服务器发送密钥过来，用于计算MD5
			fmt.Printf("[%02X] Server: (H3C data)\n", resp.Id)
			switch resp.TypeData[0] {
			case 0x17:
				length := int(resp.TypeData[1])
				fmt.Printf("[  ] Server data:%s\n", resp.TypeData[2:2+length])
			case 0x16:
				//if resp.TypeData[1] != 0x20 {
				//	break
				//}
				//var md5data [32]byte
				//for i := range resp.TypeData {
				//	if len(resp.TypeData)-i < 33 {
				//		break
				//	}
				//	if resp.TypeData[i] == 0x2b && resp.TypeData[i+1] == 0x35 {
				//		copy(md5data[:], resp.TypeData[i+2:])
				//		break
				//	}
				//}
				//h3c_md5(md5data)
				//p.md5data = md5data[:]
			}
			if resp.TypeData[3] == 0x35 {
				var md5data [32]byte
				n := copy(md5data[:], resp.TypeData[4:])
				if n == 32 {
					fmt.Printf("[  ] md5 data:%02x\n", md5data)
					h3c_md5(md5data[:])
					p.md5data = md5data[:]
				}
			}
		default:
			fmt.Printf("Unknown code:%d\n", resp.Code)
		}

		for {
			packet, err = p.source.NextPacket()
			if err != nil {
				continue
			}
			eapol := packet.Layer(layers.LayerTypeEAPOL).(*layers.EAPOL)
			if eapol == nil {
				continue
			}
			if eapol.Type == layers.EAPOLTypeLogOff {
				panic("回话结束")
			}
			break
		}
		resp = packet.Layer(layers.LayerTypeEAP).(*layers.EAP)
		if resp == nil {
			panic("error!")
		}
		//if eap != nil {
		//	fmt.Printf("EAP code:%02x EAP type:%02x \n", eap.Code, eap.Type)
		//}
	}
	return nil
}
func (p *inode) ResponseNotification(request *layers.EAP) (err error) {
	fmt.Printf("     Client: Response Notification.\n")
	panic("未实现部分")
	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
		p.EthernetHeader,
		&layers.EAPOL{
			Type:    layers.EAPOLTypeEAP,
			Version: 0x01,
		},
		&layers.EAP{
			Code:     layers.EAPCodeResponse,
			Type:     layers.EAPTypeNotification,
			Id:       request.Id,
			TypeData: append(append([]byte{byte(len(p.password))}, []byte(p.password)...), []byte(p.username)...),
		},
	)
	if err != nil {
		return err
	}
	return p.handle.WritePacketData(buffer.Bytes())
}

// 响应 ALLOCATED(0x07) 回复 密码长度(1 byte) + 密码 + 用户名
func (p *inode) ResponseH3C(request *layers.EAP) (err error) {
	fmt.Printf("[%02X] Client: Response Allocated.\n", request.Id)
	buffer := gopacket.NewSerializeBuffer()
	size := len(p.password) + len(p.username) + 1
	data := make([]byte, size)
	data[0] = byte(len(p.password))
	copy(data[1:1+len(p.password)], []byte(p.password))
	copy(data[1+len(p.password):], []byte(p.username))

	err = gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
		p.EthernetHeader,
		&layers.EAPOL{
			Type:    layers.EAPOLTypeEAP,
			Version: 0x01,
			Length:  uint16(size),
		},
		&layers.EAP{
			Code:     layers.EAPCodeResponse,
			Type:     EAPTypeAllocated,
			Id:       request.Id,
			Length:   uint16(size),
			TypeData: data,
		},
	)
	if err != nil {
		return err
	}
	return p.handle.WritePacketData(buffer.Bytes())
}

func (p *inode) ResponseMD5(request *layers.EAP) (err error) {
	fmt.Printf("[%02X] Client: Response MD5-Challenge.\n", request.Id)
	var data [128]byte
	length := int(request.TypeData[0])
	md5data := request.TypeData[1 : 1+length]
	data[0] = request.Id
	copy(data[1:], []byte(p.password))
	copy(data[1+len(p.password):], md5data)
	buffer := gopacket.NewSerializeBuffer()
	payload := md5.Sum(data[0 : 1+len(p.password)+16])
	err = gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
		p.EthernetHeader,
		&layers.EAPOL{
			Type:    layers.EAPOLTypeEAP,
			Version: 0x01,
		},
		&layers.EAP{
			Code:     layers.EAPCodeResponse,
			Type:     EAPTypeMD5,
			Id:       request.Id,
			TypeData: payload[:],
		},
	)
	if err != nil {
		return err
	}
	return p.handle.WritePacketData(buffer.Bytes())
}
func (p *inode) Logoff() (err error) {
	defer func() {
		p.handle.Close()
	}()
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
		p.EthernetHeader,
		&layers.EAPOL{
			Version: 0x01,
			Type:    layers.EAPOLTypeLogOff,
		},
	)
	return p.handle.WritePacketData(buffer.Bytes())
}

func (p *inode) ResponseIdentity(request *layers.EAP) (err error) {
	fmt.Printf("[%02X] Client: Response Identity.\n", request.Id)
	data := make([]byte, 128)
	i := 0

	if len(p.md5data) > 0 {
		// 发送 md5 data
		data[i] = 0x16
		i++
		data[i] = 0x20
		i++
		// md5data 长度 32
		copy(data[i:], p.md5data)
		i += 32
	}

	if p.sendIP {
		data[i] = 0x15
		i++
		data[i] = 0x05
		i++
		copy(data[36:], p.IP())
		i += 4
	}

	// 发送版本信息
	data[i] = 0x06
	i++
	data[i] = 0x07
	i++

	// 版本长度 28
	copy(data[i:], p.version)
	i += 28
	data[i] = ' '
	i++
	data[i] = ' '
	i++

	copy(data[i:], []byte(p.username))
	i += len(p.username)

	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
		p.EthernetHeader,
		&layers.EAPOL{
			Version: 0x01,
			Type:    layers.EAPOLTypeEAP,
			Length:  uint16(i + 5),
		},
		&layers.EAP{
			Code:     layers.EAPCodeResponse,
			Type:     layers.EAPTypeIdentity,
			Id:       request.Id,
			Length:   uint16(i + 5),
			TypeData: data[:i],
		},
	)
	if err != nil {
		return err
	}
	return p.handle.WritePacketData(buffer.Bytes())
}

func (p *inode) IP() ([]byte) {
	if p.ip != nil && len(p.ip) == 4 {
		return p.ip
	}
	iface, err := net.InterfaceByName(p.device)
	if err != nil {
		panic(err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		panic(err)
	}
	if v, ok := addrs[0].(*net.IPNet); ok {
		ip := v.IP.To4()
		if ip != nil {
			p.ip = ip
		}
		return ip
	}
	if v, ok := addrs[0].(*net.IPAddr); ok {
		ip := v.IP.To4()
		if ip != nil {
			p.ip = ip
		}
		return ip
	}
	panic("Failed to get IP address")
}

// 编码版本号
func makeVersion(v []byte) ([]byte) {
	r := rand.Uint32()
	var version, salt [20]byte
	key := []byte(fmt.Sprintf("%08x", r))
	h3ckey := []byte("HuaWei3COM1X")
	copy(version[:], v)
	copy(salt[:16], key)
	copy(salt[len(key):16], key)
	for i := range version {
		version[i] ^= salt[i]
	}
	reverse(salt[:16])
	for i := range version[:16] {
		version[i] ^= salt[i]
	}
	binary.BigEndian.PutUint32(version[16:20], r)
	copy(salt[:], h3ckey)
	copy(salt[len(h3ckey):], h3ckey)
	for i := range version {
		version[i] ^= salt[i]
	}
	reverse(salt[:])
	for i := range version {
		version[i] ^= salt[i]
	}
	fmt.Printf("[  ] Version Base64encode:%s\n", base64.StdEncoding.EncodeToString(version[:]))
	return []byte(base64.StdEncoding.EncodeToString(version[:]))
}
func decodeVersion(source []byte) {
	n, err := base64.StdEncoding.Decode(source, source)
	if err != nil {
		panic(err)
	}
	fmt.Printf("length %d\n", n)
	source = source[:n]
	//xor(source, []byte("HuaWei3COM1X"))
	xor(source, []byte("Oly5D62FaE94W7"))
	random := binary.BigEndian.Uint32(source[16:20])
	salt := fmt.Sprintf("%08x", random)
	xor(source[:16], []byte(salt))
	fmt.Printf("%s\n", source[:16])
}
func xor(data, key []byte) {
	if key == nil || len(key) == 0 {
		panic("key is null")
	}
	data2 := make([]byte, len(data))
	length := len(key)
	for i := 0; i*length < len(data); i ++ {
		copy(data2[i*length:], key)
	}
	for i := range data {
		data[i] ^= data2[i]
	}
	reverse(data2)
	for i := range data {
		data[i] ^= data2[i]
	}
}
func reverse(data []byte) {
	length := len(data)
	n := make([]byte, length)
	for i := 0; i < length; i++ {
		n[length-1-i] = data[i]
	}
	copy(data, n)
}
