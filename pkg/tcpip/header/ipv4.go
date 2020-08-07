// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package header

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// RFC 971 defines the fields of the IPv4 header on page 11 using the following
// diagram: ("Figure 4")
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |Version|  IHL  |Type of Service|          Total Length         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         Identification        |Flags|      Fragment Offset    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  Time to Live |    Protocol   |         Header Checksum       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                       Source Address                          |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Destination Address                        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Options                    |    Padding    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
const (
	versIHL = 0
	tos     = 1
	// IPv4TotalLenOffset is the offset of the total length field in the
	// IPv4 header.
	IPv4TotalLenOffset = 2
	id                 = 4
	flagsFO            = 6
	ttl                = 8
	protocol           = 9
	checksum           = 10
	srcAddr            = 12
	dstAddr            = 16
	options            = 20
)

// IPv4Fields contains the fields of an IPv4 packet. It is used to describe the
// fields of a packet that needs to be encoded.
type IPv4Fields struct {
	// IHL is the "internet header length" field of an IPv4 packet. The value
	// is in bytes.
	IHL uint8

	// TOS is the "type of service" field of an IPv4 packet.
	TOS uint8

	// TotalLength is the "total length" field of an IPv4 packet.
	TotalLength uint16

	// ID is the "identification" field of an IPv4 packet.
	ID uint16

	// Flags is the "flags" field of an IPv4 packet.
	Flags uint8

	// FragmentOffset is the "fragment offset" field of an IPv4 packet.
	FragmentOffset uint16

	// TTL is the "time to live" field of an IPv4 packet.
	TTL uint8

	// Protocol is the "protocol" field of an IPv4 packet.
	Protocol uint8

	// Checksum is the "checksum" field of an IPv4 packet.
	Checksum uint16

	// SrcAddr is the "source ip address" of an IPv4 packet.
	SrcAddr tcpip.Address

	// DstAddr is the "destination ip address" of an IPv4 packet.
	DstAddr tcpip.Address
}

// IPv4 represents an IPv4 header stored in a byte array.
// Most of the methods of IPv4 access to the underlying slice without
// checking the boundaries and could panic because of 'index out of range'.
// Always call IsValid() to validate an instance of IPv4 before using other
// methods.
type IPv4 []byte

const (
	// IPv4MinimumSize is the minimum size of a valid IPv4 packet;
	// i.e. a packet header with no options.
	IPv4MinimumSize = 20

	// IPv4MaximumHeaderSize is the maximum size of an IPv4 header. Given
	// that there are only 4 bits to represents the header length in 32-bit
	// units, the header cannot exceed 15*4 = 60 bytes.
	IPv4MaximumHeaderSize = 60

	// IPv4MaximumOptionSize is the largest size the IPv4 options can be.
	IPv4MaximumOptionSize = IPv4MaximumHeaderSize - IPv4MinimumSize

	// IPv4MaximumPayloadSize is the maximum size of a valid IPv4 payload.
	//
	// Linux limits this to 65,515 octets (the max IP datagram size - the IPv4
	// header size). But RFC 791 section 3.2 discusses the design of the IPv4
	// fragment "allows 2**13 = 8192 fragments of 8 octets each for a total of
	// 65,536 octets. Note that this is consistent with the the datagram total
	// length field (of course, the header is counted in the total length and not
	// in the fragments)."
	IPv4MaximumPayloadSize = 65536

	// MinIPFragmentPayloadSize is the minimum number of payload bytes that
	// the first fragment must carry when an IPv4 packet is fragmented.
	MinIPFragmentPayloadSize = 8

	// IPv4AddressSize is the size, in bytes, of an IPv4 address.
	IPv4AddressSize = 4

	// IPv4ProtocolNumber is IPv4's network protocol number.
	IPv4ProtocolNumber tcpip.NetworkProtocolNumber = 0x0800

	// IPv4Version is the version of the IPv4 protocol.
	IPv4Version = 4

	// IPv4AllSystems is the all systems IPv4 multicast address as per
	// IANA's IPv4 Multicast Address Space Registry. See
	// https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml.
	IPv4AllSystems tcpip.Address = "\xe0\x00\x00\x01"

	// IPv4Broadcast is the broadcast address of the IPv4 procotol.
	IPv4Broadcast tcpip.Address = "\xff\xff\xff\xff"

	// IPv4Any is the non-routable IPv4 "any" meta address.
	IPv4Any tcpip.Address = "\x00\x00\x00\x00"

	// IPv4MinimumProcessableDatagramSize is the minimum size of an IP
	// packet that every IPv4 capable host must be able to
	// process/reassemble.
	IPv4MinimumProcessableDatagramSize = 576
)

// Flags that may be set in an IPv4 packet.
const (
	IPv4FlagMoreFragments = 1 << iota
	IPv4FlagDontFragment
)

// IPv4EmptySubnet is the empty IPv4 subnet.
var IPv4EmptySubnet = func() tcpip.Subnet {
	subnet, err := tcpip.NewSubnet(IPv4Any, tcpip.AddressMask(IPv4Any))
	if err != nil {
		panic(err)
	}
	return subnet
}()

// IPVersion returns the version of IP used in the given packet. It returns -1
// if the packet is not large enough to contain the version field.
func IPVersion(b []byte) int {
	// Length must be at least offset+length of version field.
	if len(b) < versIHL+1 {
		return -1
	}
	return int(b[versIHL] >> ipVersionShift)
}

// RFC 791 page 11 shows the header length (IHL) is in the lower 4 bits
// of the first byte, and is counted in multiples of 4 bytes.
//
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |Version|  IHL  |Type of Service|          Total Length         |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      (...)
//     Version:  4 bits
//       The Version field indicates the format of the internet header.  This
//       document describes version 4.
//
//     IHL:  4 bits
//       Internet Header Length is the length of the internet header in 32
//       bit words, and thus points to the beginning of the data.  Note that
//       the minimum value for a correct header is 5.
//
const (
	ipVersionShift = 4
	ipIHLMask      = 0x0f
	IPv4IHLStride  = 4
)

// HeaderLength returns the value of the "header length" field of the IPv4
// header. The length returned is in bytes.
func (b IPv4) HeaderLength() uint8 {
	return (b[versIHL] & ipIHLMask) * IPv4IHLStride
}

// SetHeaderLength sets the value of the "Internet Header Length" field.
func (b IPv4) SetHeaderLength(hdrLen uint8) {
	if hdrLen > IPv4MaximumHeaderSize {
		panic(fmt.Sprintf("got IPv4 Header size = %d, want <= %d", hdrLen, IPv4MaximumHeaderSize))
	}
	b[versIHL] = (IPv4Version << ipVersionShift) | ((hdrLen / IPv4IHLStride) & ipIHLMask)
}

// ID returns the value of the identifier field of the IPv4 header.
func (b IPv4) ID() uint16 {
	return binary.BigEndian.Uint16(b[id:])
}

// Protocol returns the value of the protocol field of the IPv4 header.
func (b IPv4) Protocol() uint8 {
	return b[protocol]
}

// Flags returns the "flags" field of the IPv4 header.
func (b IPv4) Flags() uint8 {
	return uint8(binary.BigEndian.Uint16(b[flagsFO:]) >> 13)
}

// More returns whether the more fragments flag is set.
func (b IPv4) More() bool {
	return b.Flags()&IPv4FlagMoreFragments != 0
}

// TTL returns the "TTL" field of the IPv4 header.
func (b IPv4) TTL() uint8 {
	return b[ttl]
}

// FragmentOffset returns the "fragment offset" field of the IPv4 header.
func (b IPv4) FragmentOffset() uint16 {
	return binary.BigEndian.Uint16(b[flagsFO:]) << 3
}

// TotalLength returns the "total length" field of the IPv4 header.
func (b IPv4) TotalLength() uint16 {
	return binary.BigEndian.Uint16(b[IPv4TotalLenOffset:])
}

// Checksum returns the checksum field of the IPv4 header.
func (b IPv4) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[checksum:])
}

// SourceAddress returns the "source address" field of the IPv4 header.
func (b IPv4) SourceAddress() tcpip.Address {
	return tcpip.Address(b[srcAddr : srcAddr+IPv4AddressSize])
}

// DestinationAddress returns the "destination address" field of the IPv4
// header.
func (b IPv4) DestinationAddress() tcpip.Address {
	return tcpip.Address(b[dstAddr : dstAddr+IPv4AddressSize])
}

// IPv4OptionsBuffer is a buffer that holds all the raw IP options.
// Effectively a part of a packet in wire format.
type IPv4OptionsBuffer []byte

// Options returns a a buffer holding the options.
func (b IPv4) Options() IPv4OptionsBuffer {
	hdrLen := b.HeaderLength()
	return IPv4OptionsBuffer(b[options:hdrLen:hdrLen])
}

// TransportProtocol implements Network.TransportProtocol.
func (b IPv4) TransportProtocol() tcpip.TransportProtocolNumber {
	return tcpip.TransportProtocolNumber(b.Protocol())
}

// Payload implements Network.Payload.
func (b IPv4) Payload() []byte {
	return b[b.HeaderLength():][:b.PayloadLength()]
}

// PayloadLength returns the length of the payload portion of the IPv4 packet.
func (b IPv4) PayloadLength() uint16 {
	return b.TotalLength() - uint16(b.HeaderLength())
}

// TOS returns the "type of service" field of the IPv4 header.
func (b IPv4) TOS() (uint8, uint32) {
	return b[tos], 0
}

// SetTOS sets the "type of service" field of the IPv4 header.
func (b IPv4) SetTOS(v uint8, _ uint32) {
	b[tos] = v
}

// SetTTL sets the "Time to Live" field of the IPv4 header.
func (b IPv4) SetTTL(v byte) {
	b[ttl] = v
}

// SetTotalLength sets the "total length" field of the IPv4 header.
func (b IPv4) SetTotalLength(totalLength uint16) {
	binary.BigEndian.PutUint16(b[IPv4TotalLenOffset:], totalLength)
}

// SetChecksum sets the checksum field of the IPv4 header.
func (b IPv4) SetChecksum(v uint16) {
	binary.BigEndian.PutUint16(b[checksum:], v)
}

// SetFlagsFragmentOffset sets the "flags" and "fragment offset" fields of the
// IPv4 header.
func (b IPv4) SetFlagsFragmentOffset(flags uint8, offset uint16) {
	v := (uint16(flags) << 13) | (offset >> 3)
	binary.BigEndian.PutUint16(b[flagsFO:], v)
}

// SetID sets the identification field.
func (b IPv4) SetID(v uint16) {
	binary.BigEndian.PutUint16(b[id:], v)
}

// SetSourceAddress sets the "source address" field of the IPv4 header.
func (b IPv4) SetSourceAddress(addr tcpip.Address) {
	copy(b[srcAddr:srcAddr+IPv4AddressSize], addr)
}

// SetDestinationAddress sets the "destination address" field of the IPv4
// header.
func (b IPv4) SetDestinationAddress(addr tcpip.Address) {
	copy(b[dstAddr:dstAddr+IPv4AddressSize], addr)
}

// CalculateChecksum calculates the checksum of the IPv4 header.
func (b IPv4) CalculateChecksum() uint16 {
	return Checksum(b[:b.HeaderLength()], 0)
}

// Encode encodes all the fields of the IPv4 header.
func (b IPv4) Encode(i *IPv4Fields) {
	b.SetHeaderLength(i.IHL)
	b[tos] = i.TOS
	b.SetTotalLength(i.TotalLength)
	binary.BigEndian.PutUint16(b[id:], i.ID)
	b.SetFlagsFragmentOffset(i.Flags, i.FragmentOffset)
	b[ttl] = i.TTL
	b[protocol] = i.Protocol
	b.SetChecksum(i.Checksum)
	copy(b[srcAddr:srcAddr+IPv4AddressSize], i.SrcAddr)
	copy(b[dstAddr:dstAddr+IPv4AddressSize], i.DstAddr)
}

// EncodePartial updates the total length and checksum fields of IPv4 header,
// taking in the partial checksum, which is the checksum of the header without
// the total length and checksum fields. It is useful in cases when similar
// packets are produced.
func (b IPv4) EncodePartial(partialChecksum, totalLength uint16) {
	b.SetTotalLength(totalLength)
	checksum := Checksum(b[IPv4TotalLenOffset:IPv4TotalLenOffset+2], partialChecksum)
	b.SetChecksum(^checksum)
}

// IsValid performs basic validation on the packet.
func (b IPv4) IsValid(pktSize int) bool {
	if len(b) < IPv4MinimumSize {
		return false
	}

	hlen := int(b.HeaderLength())
	tlen := int(b.TotalLength())
	if hlen < IPv4MinimumSize || hlen > tlen || tlen > pktSize {
		return false
	}

	if IPVersion(b) != IPv4Version {
		return false
	}

	return true
}

// IsV4MulticastAddress determines if the provided address is an IPv4 multicast
// address (range 224.0.0.0 to 239.255.255.255). The four most significant bits
// will be 1110 = 0xe0.
func IsV4MulticastAddress(addr tcpip.Address) bool {
	if len(addr) != IPv4AddressSize {
		return false
	}
	return (addr[0] & 0xf0) == 0xe0
}

// IsV4LoopbackAddress determines if the provided address is an IPv4 loopback
// address (belongs to 127.0.0.0/8 subnet). See RFC 1122 section 3.2.1.3.
func IsV4LoopbackAddress(addr tcpip.Address) bool {
	if len(addr) != IPv4AddressSize {
		return false
	}
	return addr[0] == 0x7f
}

// ========================= Options ==========================
/*
      Example options layout. Adapted from RFC 791

   |                      destination address                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Opt. Code = w | Opt.  Len.= 3 | option value  | Opt. Code = x |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Opt. Len. = 4 |           option value        | Opt. Code = 1 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Opt. Code = y | Opt. Len. = 3 |  option value | Opt. Code = z |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Opt. Len = 2  | Opt. Code = 0 |  Ignored      |  Ignored      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                              data                             |

   Options types:
      End of Option List
        +--------+
        |00000000| Type=0
        +--------+

      No Operation
        +--------+
        |00000001| Type=1
        +--------+

      Security
        +--------+--------+---//---+---//---+---//---+---//---+
        |10000010|00001011|SSS  SSS|CCC  CCC|HHH  HHH|  TCC   |
        +--------+--------+---//---+---//---+---//---+---//---+
          Type=130 Length=11

      Loose Source and Record Route
        +--------+--------+--------+---------//--------+
        |10000011| length | pointer|     route data    | Type=131
        +--------+--------+--------+---------//--------+

      Strict Source and Record Route
        +--------+--------+--------+---------//--------+
        |10001001| length | pointer|     route data    | Type=137
        +--------+--------+--------+---------//--------+

      Record Route
        +--------+--------+--------+---------//--------+
        |00000111| length | pointer|     route data    | Type=7
        +--------+--------+--------+---------//--------+

      Stream Identifier
        +--------+--------+--------+--------+
        |10001000|00000010|    Stream ID    | Type=136 Length=4
        +--------+--------+--------+--------+

      Router Alert
        +--------+--------+--------+--------+
        |10010100|00000100|  2 octet value  | Type=140 Length=4
        +--------+--------+--------+--------+

      Internet Timestamp
        +--------+--------+--------+--------+
        |01000100| length | pointer|oflw|flg| Type=68
        +--------+--------+--------+--------+
        |         internet address          |
        +--------+--------+--------+--------+
        |             timestamp             |
        +--------+--------+--------+--------+
        |                 .                 |
                          .


  Option code 0: End of options. Anything following is ignored.
  Option code 1: NOP/spacer. Can go anywhere and appear multiple times.
  Only codes 0 and 1 have no length field.
  Options may be on any byte boundary, however the complete options area ends
  on a multiple of 4 bytes as specified by the IP header length field.
*/
const (
	// IPv4OptionListEndType is the option type for the End Of Option List
	// option.
	IPv4OptionListEndType = 0

	// IPv4EOptionNopType is the No-Operation option. May appear between other
	// options and may appear multiple times.
	IPv4OptionNopType = 1

	// IPv4OptionTimestampType is the option type for the Timestamp option.
	IPv4OptionTimestampType = 68

	// Options we don't fully implement yet except for statistics.
	IPv4OptionRecordRouteType            = 7
	IPv4OptionLooseSourceRecordRouteType = 131
	IPv4OptionStrictSourceRouteType      = 137

	// IPv4OptionMaxLength is the largest space we can use for options.
	// With 20 bytes used up of the maximum of 60, only 40 bytes may be used for
	// options.
	IPv4OptionMaxLength = IPv4MaximumHeaderSize - IPv4MinimumSize

	// IPv4OptionTypeOffset is the offset in an option of it's type field.
	IPv4OptionTypeOffset = 0
	// IPv4OptionLengthOffset is the offset in an option of it's length field.
	IPv4OptionLengthOffset = 1
)

// Potential errors when parsing IP options.
var (
	ErrIPv4OptZeroLength   = errors.New("zero length")
	ErrIPv4OptInvalid      = errors.New("invalid option")
	ErrIPv4OptMalformed    = errors.New("malformed option")
	ErrIPv4OptionTruncated = errors.New("option truncated")
)

// Options can need to be looked at in a number of contexts. In each case the
// work that needs to be done is a bit different.
const (
	IPv4OptionUsageReceive = iota
	IPv4OptionUsageForward
	IPv4OptionUsageEcho
	IPv4OptionUsageFrag1
	IPv4OptionUsageFragN
)

// IPv4Option is an interface representing various option types
type IPv4Option interface {
	Type() uint8
	Size() uint8
	Contents() []byte
}

// IPv4OptionGeneric represents an IPv4 Option of unknown type stored
// in a byte array. Should be an implementation of IPv4Option interface.
type IPv4OptionGeneric []byte

// Type returns the type for the given IPv4 Option.
func (o IPv4OptionGeneric) Type() uint8 { return o[IPv4OptionTypeOffset] }

// Size implements IPv4Option.Size()
func (o IPv4OptionGeneric) Size() uint8 { return uint8(len(o)) }

// Contents implements IPv4Option.Contents()
func (o IPv4OptionGeneric) Contents() []byte { return []byte(o) }

// IPv4OptionIterator represents an iterator pointing to a specific IP option
// at any point of time.
type IPv4OptionIterator struct {
	options IPv4OptionsBuffer
	// While parsing options we need to keep track of where we are as the
	// resulting ICMP packet is supposed to have a pointer to the byte within
	// the IP packet where the error was detected.
	ErrCursor     byte
	nextErrCursor byte
	newOptions    []byte
	writePoint    int
}

// NewIterator sets up and returns an iterator of options. It also controls the
// building of a new option set
func (o IPv4OptionsBuffer) NewIterator() IPv4OptionIterator {
	return IPv4OptionIterator{
		options:       o,
		nextErrCursor: IPv4MinimumSize,
		newOptions:    make([]byte, IPv4MaximumOptionSize, IPv4MaximumOptionSize),
	}
}

// WriteBuffer returns the remaining (unused) part of the new option buffer.
func (i *IPv4OptionIterator) WriteBuffer() IPv4OptionsBuffer {
	return IPv4OptionsBuffer(i.newOptions[i.writePoint:])
}

// NewOptions returns the completed replacement options buffer.
func (i *IPv4OptionIterator) NewOptions() IPv4OptionsBuffer {
	return IPv4OptionsBuffer(i.newOptions[:i.writePoint])
}

// ConsumeBuffer marks a portion of the new buffer as used.
func (i *IPv4OptionIterator) ConsumeBuffer(size int) {
	i.writePoint += size
}

// PushByte puts one of the single byte options onto the new options.
func (i *IPv4OptionIterator) PushByte(val byte) {
	if i.writePoint < IPv4MaximumOptionSize {
		i.newOptions[i.writePoint] = val
		i.writePoint++
	}
}

// CloseBuffer ensures that the new options buffer is padded to a legal
// size, ready to add to an IP header.
// XXX do we need to request a particular size?
func (i *IPv4OptionIterator) CloseBuffer() {
	target := (i.writePoint + 3) & ^0x3
	var p = i.writePoint
	for p < target {
		i.newOptions[p] = IPv4OptionListEndType
		p++
	}
	i.writePoint = p
}

// Next returns the next IP option in the buffer/list of IP options.
// It returns
// - A slice or bytes holding the next option or nil if there is error.
// - A boolean which is true if parsing of all the options is complete.
// - An error which is non-nil if an error condition was encountered.
func (i *IPv4OptionIterator) Next() (IPv4Option, bool, error) {
	// The opts slice gets shorter as we process the options. When we have no
	// bytes left we are done.
	if len(i.options) == 0 {
		return nil, true, nil
	}

	i.ErrCursor = i.nextErrCursor

	optType := i.options[IPv4OptionTypeOffset]

	if optType == IPv4OptionNopType || optType == IPv4OptionListEndType {
		returnOption := i.options[:1]
		i.options = i.options[1:]
		i.nextErrCursor = i.ErrCursor + 1
		return IPv4OptionGeneric(returnOption), false, nil
	}

	// There are no more single byte options defined.
	// All the rest have a length field.
	if len(i.options) == 1 {
		return nil, true, ErrIPv4OptMalformed
	}

	optLen := i.options[IPv4OptionLengthOffset]

	if optLen == 0 {
		i.ErrCursor++
		return nil, true, ErrIPv4OptZeroLength
	}

	if optLen < 2 { // i.e. 1.
		i.ErrCursor++
		return nil, true, ErrIPv4OptMalformed
	}

	if optLen > byte(len(i.options)) {
		i.ErrCursor++
		return nil, true, ErrIPv4OptionTruncated
	}

	optionBody := i.options[:optLen]
	i.nextErrCursor = i.ErrCursor + optLen
	i.options = i.options[optLen:]

	// We will check the length of some option types that we know.
	switch optType {
	case IPv4OptionTimestampType:
		if optLen < 4 {
			i.ErrCursor++
			return nil, true, ErrIPv4OptMalformed
		}
		return IPv4OptionTimestamp(optionBody), false, nil

	case IPv4OptionRecordRouteType:
	case IPv4OptionLooseSourceRecordRouteType:
	case IPv4OptionStrictSourceRouteType:
		/*
			case IPv4OptionSecurityType:
			case IPv4OptionStreamIDType:
			case IPv4OptionExtendedSecurityType:
			case IPv4OptionCommercialSecurityType:
			case IPv4OptionRouterAlertType:
		*/
	default:
		return nil, true, ErrIPv4OptInvalid
	}
	return IPv4OptionGeneric(optionBody), false, nil
}

/* ========================================================================
IP Timestamp option - RFC 791
+--------+--------+--------+--------+
|01000100| length | pointer|oflw|flg|
+--------+--------+--------+--------+
|         internet address          |
+--------+--------+--------+--------+
|             timestamp             |
+--------+--------+--------+--------+
|                ...                |

Type = 68

The Option Length is the number of octets in the option counting
the type, length, pointer, and overflow/flag octets (maximum
length 40).

The Pointer is the number of octets from the beginning of this
option to the end of timestamps plus one (i.e., it points to the
octet beginning the space for next timestamp).  The smallest
legal value is 5.  The timestamp area is full when the pointer
is greater than the length.

The Overflow (oflw) [4 bits] is the number of IP modules that
cannot register timestamps due to lack of space.

The Flag (flg) [4 bits] values are

  0 -- time stamps only, stored in consecutive 32-bit words,

  1 -- each timestamp is preceded with internet address of the
       registering entity,

  3 -- the internet address fields are prespecified.  An IP
       module only registers its timestamp if it matches its own
       address with the next specified internet address.
*/

// Timestamps are defined in RFC791 page 22 as milliseconds since midnight UTC.
//
//        The Timestamp is a right-justified, 32-bit timestamp in
//        milliseconds since midnight UT.  If the time is not available in
//        milliseconds or cannot be provided with respect to midnight UT
//        then any time may be inserted as a timestamp provided the high
//        order bit of the timestamp field is set to one to indicate the
//        use of a non-standard value.
//
// In Go we can get nSecs since then using UnixNano() (an int64)
// and get rid of parts > 1 day while converting to milliseconds.
const millisecondsPerDay = 24 * 3600 * 1000

type milliSecTime uint32

// ipv4TimestampTime provides the current time as specified in RFC 791.
func ipv4TimestampTime() milliSecTime {
	return milliSecTime((time.Now().UnixNano() / 1000000) % (millisecondsPerDay))
}

// Timestamp option specific related constants.
const (
	// IPv4OptionTimestampHdrLength is the length of the timestamp option header
	IPv4OptionTimestampHdrLength = 4

	// IPv4OptionTimestampSize is the size of an IP timestamp.
	IPv4OptionTimestampSize = 4

	// IPv4OptionTimestampWithAddrSize is the size of an IP timestamp + Address.
	IPv4OptionTimestampWithAddrSize = IPv4AddressSize + IPv4OptionTimestampSize

	// IPv4OptionTimestampOnlyMinSize is the minimum length of a Timestamp option
	// containing only timestamps.
	IPv4OptionTimestampOnlyMinSize = IPv4OptionTimestampHdrLength + IPv4OptionTimestampSize

	// IPv4OptionTimestampWithIPMinSize is the minimum length of a Timestamp option
	// containing both IP address and timestamp.
	IPv4OptionTimestampWithIPMinSize = IPv4OptionTimestampOnlyMinSize + IPv4AddressSize

	// IPv4OptionTimestampMaxSize is limited by space for options
	IPv4OptionTimestampMaxSize = IPv4OptionMaxLength

	// IPv4OptionTimestampOnlyFlag is a flag indicating that only timestamp is present.
	IPv4OptionTimestampOnlyFlag = 0

	// IPv4OptionTimestampWithIPFlag is a flag indicating that both timestamps and
	// IP are present.
	IPv4OptionTimestampWithIPFlag = 1

	// IPv4OptionTimestampWithPredefinedIPFlag is a flag indicating that predefined
	// IP is present.
	IPv4OptionTimestampWithPredefinedIPFlag = 3
)

// IP Timestamp option fields.
const (
	IPv4OptionTimestampStart        = 0
	IPv4OptionTimestampLength       = 1
	IPv4OptionTimestampPointer      = 2
	IPv4OptionTimestampOFLWAndFLG   = 3
	IPv4OptionTimestampData         = 4
	IPv4OptionTimestampOverflowMask = 0xf0
	IPv4OptionTimestampFlagsMask    = 0x0f
)

var (
	// ErrIPv4TimestampOptInvalidLength indicates a timestamp option had an
	// inconsitency to do with its length.
	ErrIPv4TimestampOptInvalidLength = errors.New("invalid length")

	// ErrIPv4TimestampOptInvalidPointer is used when the pointer in a timestamp
	// does not point within the option.
	ErrIPv4TimestampOptInvalidPointer = errors.New("invalid pointer")

	// ErrIPv4TimestampOptOverflow is used when the number of overflowed
	// timestamps exceeds 15.
	ErrIPv4TimestampOptOverflow = errors.New("timestamp overflow")

	// ErrIPv4TimestampOptInvalidFlags is used when the flags of a timestamp
	// option do not result in a valid combination.
	ErrIPv4TimestampOptInvalidFlags = errors.New("invalid flags")
)

// IPv4OptTimestampEntry represents an IPv4 Timestamp Option entry stored in a
// byte array. It may be 4 or 8 bytes long depending on the flags.
type IPv4OptTimestampEntry []byte

// Address returns the IP address field in the IP Timestamp entry.
// Only call on the entries that have an address.
func (b IPv4OptTimestampEntry) Address() tcpip.Address {
	return tcpip.Address(b[:IPv4AddressSize])
}

// SetIPAddress sets the IP address field in the IP Timestamp Entry.
// Only call on the entries that have an address.
func (b IPv4OptTimestampEntry) SetIPAddress(addr tcpip.Address) {
	copy(b[:IPv4AddressSize], addr)
}

// XXX unused

// timestamp returns the contents of the timestamp field of the
// current stamp.
func (b IPv4OptTimestampEntry) timestamp() uint32 {
	if len(b) == IPv4OptionTimestampSize {
		return binary.BigEndian.Uint32(b[:IPv4OptionTimestampSize])
	}
	return binary.BigEndian.Uint32(b[IPv4AddressSize:])
}

// SetTimestamp sets the timestamp field of the current stamp.
func (b IPv4OptTimestampEntry) SetTimestamp() {
	if len(b) == IPv4OptionTimestampSize {
		binary.BigEndian.PutUint32(b[0:], uint32(ipv4TimestampTime()))
	} else { // must be 8 bytes
		binary.BigEndian.PutUint32(b[IPv4AddressSize:], uint32(ipv4TimestampTime()))
	}
}

// IPv4OptionTimestamp represents an IPv4 Timestamp Option stored
// in a byte array. It is an instance of the option interface.
type IPv4OptionTimestamp []byte

// Type implements IPv4Option.Type(). Returns 68
func (ts IPv4OptionTimestamp) Type() uint8 { return IPv4OptionTimestampType }

// Size implements IPv4Option.Size().
func (ts IPv4OptionTimestamp) Size() uint8 { return uint8(len(ts)) }

// Contents implements IPv4Option.Contents().
func (ts IPv4OptionTimestamp) Contents() []byte { return []byte(ts) }

// Pointer returns the pointer field in the IP Timestamp option.
func (ts IPv4OptionTimestamp) Pointer() uint8 {
	return ts[IPv4OptionTimestampPointer]
}

// IncPointer increments the pointer field by the given size.
func (ts IPv4OptionTimestamp) IncPointer(size uint8) uint8 {
	ts[IPv4OptionTimestampPointer] += size
	return ts[IPv4OptionTimestampPointer]
}

// Flags returns the flags field in the IP Timestamp option.
func (ts IPv4OptionTimestamp) Flags() uint8 {
	return ts[IPv4OptionTimestampOFLWAndFLG] & IPv4OptionTimestampFlagsMask
}

// Overflow returns the Overflow field in the IP Timestamp option.
func (ts IPv4OptionTimestamp) Overflow() uint8 {
	return (ts[IPv4OptionTimestampOFLWAndFLG] & IPv4OptionTimestampOverflowMask) >> 4
}

// IncOverflow increments the Overflow field in the IP Timestamp
// option. If it returns 0 it overflowed.
func (ts IPv4OptionTimestamp) IncOverflow() uint8 {
	ts[IPv4OptionTimestampOFLWAndFLG] += byte(1 << 4)
	return (ts[IPv4OptionTimestampOFLWAndFLG] & IPv4OptionTimestampOverflowMask) >> 4
}

// ===

// IPv4OptionRecordRoute represents an IPv4 Record Route option.
type IPv4OptionRecordRoute []byte

// Type implements IPv4Option.Type().
func (rr IPv4OptionRecordRoute) Type() uint8 { return IPv4OptionRecordRouteType }

// Size implements IPv4Option.Size().
func (rr IPv4OptionRecordRoute) Size() uint8 { return uint8(len(rr)) }

// Contents implements IPv4Option.Contents().
func (rr IPv4OptionRecordRoute) Contents() []byte { return []byte(rr) }
