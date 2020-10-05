// Copyright 2020 The gVisor Authors.
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

package ipv6_fragment_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"net"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.RegisterFlags(flag.CommandLine)
}

func TestIPv6Fragment(t *testing.T) {
	const (
		data       = "IPV6_PROTOCOL_TESTER_FOR_FRAGMENT"
		fragmentID = 1
	)

	type expectError struct {
		typ                header.ICMPv6Type
		code               header.ICMPv6Code
		typeSpecificIsUsed bool
		typeSpecific       uint32
	}

	tests := []struct {
		name                 string
		firstPayloadLength   uint16
		payload              []byte
		noSecondFragment     bool
		secondFragmentOffset uint16
		expectFrameTimeout   time.Duration
		expectError          *expectError
	}{
		{
			name:                 "reasseble two fragments",
			firstPayloadLength:   8,
			payload:              []byte(data)[:20],
			secondFragmentOffset: (header.ICMPv6EchoMinimumSize + 8) / 8,
			expectFrameTimeout:   time.Second,
			expectError:          nil,
		},
		{
			name:               "reassebly timeout",
			firstPayloadLength: 8,
			payload:            []byte(data)[:20],
			noSecondFragment:   true,
			expectFrameTimeout: 70 * time.Second,
			expectError: &expectError{
				typ:  header.ICMPv6TimeExceeded,
				code: header.ICMPv6ReassemblyTimeout,
			},
		},
		{
			name:               "payload size not a multiple of 8",
			firstPayloadLength: 9,
			payload:            []byte(data)[:20],
			noSecondFragment:   true,
			expectFrameTimeout: time.Second,
			expectError: &expectError{
				typ:                header.ICMPv6ParamProblem,
				code:               header.ICMPv6ErroneousHeader,
				typeSpecificIsUsed: true,
				typeSpecific:       4,
			},
		},
		{
			name:                 "payload length error",
			firstPayloadLength:   16,
			payload:              []byte(data)[:33],
			secondFragmentOffset: 65520 / 8,
			expectFrameTimeout:   time.Second,
			expectError: &expectError{
				typ:                header.ICMPv6ParamProblem,
				code:               header.ICMPv6ErroneousHeader,
				typeSpecificIsUsed: true,
				typeSpecific:       42,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dut := testbench.NewDUT(t)
			defer dut.TearDown()
			ipv6Conn := testbench.NewIPv6Conn(t, testbench.IPv6{}, testbench.IPv6{})
			conn := (*testbench.Connection)(&ipv6Conn)
			defer ipv6Conn.Close(t)

			firstPayloadToSend := test.payload[:test.firstPayloadLength]
			secondPayloadToSend := test.payload[test.firstPayloadLength:]

			icmpv6EchoPayload := make([]byte, 4)
			binary.BigEndian.PutUint16(icmpv6EchoPayload[0:], 0)
			binary.BigEndian.PutUint16(icmpv6EchoPayload[2:], 0)
			icmpv6EchoPayload = append(icmpv6EchoPayload, firstPayloadToSend...)

			lIP := tcpip.Address(net.ParseIP(testbench.LocalIPv6).To16())
			rIP := tcpip.Address(net.ParseIP(testbench.RemoteIPv6).To16())
			icmpv6 := testbench.ICMPv6{
				Type:    testbench.ICMPv6Type(header.ICMPv6EchoRequest),
				Code:    testbench.ICMPv6Code(header.ICMPv6UnusedCode),
				Payload: icmpv6EchoPayload,
			}
			icmpv6Bytes, err := icmpv6.ToBytes()
			if err != nil {
				t.Fatalf("failed to serialize ICMPv6: %s", err)
			}
			cksum := header.ICMPv6Checksum(
				header.ICMPv6(icmpv6Bytes),
				lIP,
				rIP,
				buffer.NewVectorisedView(len(secondPayloadToSend), []buffer.View{secondPayloadToSend}),
			)

			firstFragment := conn.CreateFrame(t, testbench.Layers{&testbench.IPv6{}},
				&testbench.IPv6FragmentExtHdr{
					FragmentOffset: testbench.Uint16(0),
					MoreFragments:  testbench.Bool(true),
					Identification: testbench.Uint32(fragmentID),
				},
				&testbench.ICMPv6{
					Type:     testbench.ICMPv6Type(header.ICMPv6EchoRequest),
					Code:     testbench.ICMPv6Code(header.ICMPv6UnusedCode),
					Payload:  icmpv6EchoPayload,
					Checksum: &cksum,
				},
			)
			conn.SendFrame(t, firstFragment)

			firstIPv6Sent := firstFragment[1:]
			firstIPv6Bytes, err := firstIPv6Sent.ToBytes()
			if err != nil {
				t.Fatalf("can't convert first %s to bytes: %s", firstIPv6Sent, err)
			}

			var secondIPv6Bytes []byte
			if !test.noSecondFragment {
				icmpv6ProtoNum := header.IPv6ExtensionHeaderIdentifier(header.ICMPv6ProtocolNumber)

				secondFragment := conn.CreateFrame(t, testbench.Layers{&testbench.IPv6{}},
					&testbench.IPv6FragmentExtHdr{
						NextHeader:     &icmpv6ProtoNum,
						FragmentOffset: testbench.Uint16(test.secondFragmentOffset),
						MoreFragments:  testbench.Bool(false),
						Identification: testbench.Uint32(fragmentID),
					},
					&testbench.Payload{
						Bytes: secondPayloadToSend,
					},
				)
				conn.SendFrame(t, secondFragment)

				secondIPv6Sent := secondFragment[1:]
				secondIPv6Bytes, err = secondIPv6Sent.ToBytes()
				if err != nil {
					t.Fatalf("can't convert %s to bytes: %s", secondIPv6Sent, err)
				}
			}

			if test.expectError != nil {
				gotErrorMessage, err := ipv6Conn.ExpectFrame(t, testbench.Layers{
					&testbench.Ether{},
					&testbench.IPv6{},
					&testbench.ICMPv6{
						Type: testbench.ICMPv6Type(test.expectError.typ),
						Code: testbench.ICMPv6Code(test.expectError.code),
					},
				}, test.expectFrameTimeout)
				if err != nil {
					t.Fatalf("expected an ICMPv6 Error Message, but got none: %s", err)
				}
				gotPayload, err := gotErrorMessage[len(gotErrorMessage)-1].ToBytes()
				if err != nil {
					t.Fatalf("failed to serialize ICMPv6: %s", err)
				}
				if test.expectError.typeSpecificIsUsed {
					gotTypeSpecific := header.ICMPv6(gotPayload).TypeSpecific()
					wantTypeSpecific := test.expectError.typeSpecific
					if gotTypeSpecific != wantTypeSpecific {
						t.Fatalf("received unexpected type specific value, got: %s, want: %s", gotTypeSpecific, wantTypeSpecific)
					}
				}
				icmpPayload := gotPayload[header.ICMPv6ErrorHeaderSize:]
				var wantPayload []byte
				if test.noSecondFragment {
					wantPayload = firstIPv6Bytes
				} else {
					wantPayload = secondIPv6Bytes
				}
				if !bytes.Equal(icmpPayload, wantPayload) {
					t.Fatalf("received unexpected payload, got: %s, want: %s",
						hex.Dump(icmpPayload),
						hex.Dump(wantPayload))
				}
			} else {
				gotEchoReply, err := ipv6Conn.ExpectFrame(t, testbench.Layers{
					&testbench.Ether{},
					&testbench.IPv6{},
					&testbench.ICMPv6{
						Type: testbench.ICMPv6Type(header.ICMPv6EchoReply),
						Code: testbench.ICMPv6Code(header.ICMPv6UnusedCode),
					},
				}, test.expectFrameTimeout)
				if err != nil {
					t.Fatalf("expected an ICMPv6 Echo Reply, but got none: %s", err)
				}
				gotPayload, err := gotEchoReply[len(gotEchoReply)-1].ToBytes()
				if err != nil {
					t.Fatalf("failed to serialize ICMPv6: %s", err)
				}
				icmpPayload := gotPayload[header.ICMPv6EchoMinimumSize:]
				wantPayload := test.payload
				if !bytes.Equal(icmpPayload, wantPayload) {
					t.Fatalf("received unexpected payload, got: %s, want: %s",
						hex.Dump(icmpPayload),
						hex.Dump(wantPayload))
				}
			}
		})
	}
}
