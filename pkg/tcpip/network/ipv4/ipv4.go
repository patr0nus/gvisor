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

// Package ipv4 contains the implementation of the ipv4 network protocol.
package ipv4

import (
	"fmt"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/header/parse"
	"gvisor.dev/gvisor/pkg/tcpip/network/fragmentation"
	"gvisor.dev/gvisor/pkg/tcpip/network/hash"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// As per RFC 791 section 3.2:
	//   The current recommendation for the initial timer setting is 15 seconds.
	//   This may be changed as experience with this protocol accumulates.
	//
	// Considering that it is an old recommendation, we use the same reassembly
	// timeout that linux defines, which is 30 seconds:
	// https://github.com/torvalds/linux/blob/47ec5303d73ea344e84f46660fff693c57641386/include/net/ip.h#L138
	reassembleTimeout = 30 * time.Second

	// ProtocolNumber is the ipv4 protocol number.
	ProtocolNumber = header.IPv4ProtocolNumber

	// MaxTotalSize is maximum size that can be encoded in the 16-bit
	// TotalLength field of the ipv4 header.
	MaxTotalSize = 0xffff

	// DefaultTTL is the default time-to-live value for this endpoint.
	DefaultTTL = 64

	// buckets is the number of identifier buckets.
	buckets = 2048

	// The size of a fragment block, in bytes, as per RFC 791 section 3.1,
	// page 14.
	fragmentblockSize = 8
)

var ipv4BroadcastAddr = header.IPv4Broadcast.WithPrefix()

var _ stack.GroupAddressableEndpoint = (*endpoint)(nil)
var _ stack.AddressableEndpoint = (*endpoint)(nil)
var _ stack.NetworkEndpoint = (*endpoint)(nil)

type endpoint struct {
	nic        stack.NetworkInterface
	dispatcher stack.TransportDispatcher
	protocol   *protocol

	// enabled is set to 1 when the enpoint is enabled and 0 when it is
	// disabled.
	//
	// Must be accessed using atomic operations.
	enabled uint32

	mu struct {
		sync.RWMutex

		addressableEndpointState stack.AddressableEndpointState
	}
}

// NewEndpoint creates a new ipv4 endpoint.
func (p *protocol) NewEndpoint(nic stack.NetworkInterface, _ stack.LinkAddressCache, _ stack.NUDHandler, dispatcher stack.TransportDispatcher) stack.NetworkEndpoint {
	e := &endpoint{
		nic:        nic,
		dispatcher: dispatcher,
		protocol:   p,
	}
	e.mu.addressableEndpointState.Init(e)
	return e
}

// Enable implements stack.NetworkEndpoint.
func (e *endpoint) Enable() *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// If the NIC is not enabled, the endpoint can't do anything meaningful so
	// don't enable the endpoint.
	if !e.nic.Enabled() {
		return tcpip.ErrNotPermitted
	}

	// If the endpoint is already enabled, there is nothing for it to do.
	if !e.setEnabled(true) {
		return nil
	}

	// Create an endpoint to receive broadcast packets on this interface.
	ep, err := e.mu.addressableEndpointState.AddAndAcquirePermanentAddress(ipv4BroadcastAddr, stack.NeverPrimaryEndpoint, stack.AddressConfigStatic, false /* deprecated */)
	if err != nil {
		return err
	}
	// We have no need for the address endpoint.
	ep.DecRef()

	// As per RFC 1122 section 3.3.7, all hosts should join the all-hosts
	// multicast group. Note, the IANA calls the all-hosts multicast group the
	// all-systems multicast group.
	_, err = e.mu.addressableEndpointState.JoinGroup(header.IPv4AllSystems)
	return err
}

// Enabled implements stack.NetworkEndpoint.
func (e *endpoint) Enabled() bool {
	return e.nic.Enabled() && e.isEnabled()
}

// isEnabled returns true if the endpoint is enabled, regardless of the
// enabled status of the NIC.
func (e *endpoint) isEnabled() bool {
	return atomic.LoadUint32(&e.enabled) == 1
}

// setEnabled sets the enabled status for the endpoint.
//
// Returns true if the enabled status was updated.
func (e *endpoint) setEnabled(v bool) bool {
	if v {
		return atomic.SwapUint32(&e.enabled, 1) == 0
	}
	return atomic.SwapUint32(&e.enabled, 0) == 1
}

// Disable implements stack.NetworkEndpoint.
func (e *endpoint) Disable() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.disableLocked()
}

func (e *endpoint) disableLocked() {
	if !e.setEnabled(false) {
		return
	}

	// The endpoint may have already left the multicast group.
	if _, err := e.mu.addressableEndpointState.LeaveGroup(header.IPv4AllSystems); err != nil && err != tcpip.ErrBadLocalAddress {
		panic(fmt.Sprintf("unexpected error when leaving group = %s: %s", header.IPv4AllSystems, err))
	}

	// The address may have already been removed.
	if err := e.mu.addressableEndpointState.RemovePermanentAddress(ipv4BroadcastAddr.Address); err != nil && err != tcpip.ErrBadLocalAddress {
		panic(fmt.Sprintf("unexpected error when removing address = %s: %s", ipv4BroadcastAddr.Address, err))
	}
}

// DefaultTTL is the default time-to-live value for this endpoint.
func (e *endpoint) DefaultTTL() uint8 {
	return e.protocol.DefaultTTL()
}

// MTU implements stack.NetworkEndpoint.MTU. It returns the link-layer MTU minus
// the network layer max header length.
func (e *endpoint) MTU() uint32 {
	return calculateMTU(e.nic.MTU())
}

// MaxHeaderLength returns the maximum length needed by ipv4 headers (and
// underlying protocols).
func (e *endpoint) MaxHeaderLength() uint16 {
	return e.nic.MaxHeaderLength() + header.IPv4MaximumHeaderSize
}

// NetworkProtocolNumber implements stack.NetworkEndpoint.NetworkProtocolNumber.
func (e *endpoint) NetworkProtocolNumber() tcpip.NetworkProtocolNumber {
	return e.protocol.Number()
}

// writePacketFragments fragments pkt and writes the results on the link
// endpoint. The IP header must already present in the original packet. The mtu
// is the maximum size of the packets.
func (e *endpoint) writePacketFragments(r *stack.Route, gso *stack.GSO, mtu uint32, pkt *stack.PacketBuffer) *tcpip.Error {
	networkHeader := header.IPv4(pkt.NetworkHeader().View())
	fragMTU := int(calculateFragmentInnerMTU(mtu, pkt))
	pf := fragmentation.MakePacketFragmenter(pkt, fragMTU, pkt.AvailableHeaderBytes()+len(networkHeader))

	for {
		fragPkt, more := buildNextFragment(&pf, networkHeader)
		if err := e.nic.WritePacket(r, gso, ProtocolNumber, fragPkt); err != nil {
			r.Stats().IP.OutgoingPacketErrors.IncrementBy(uint64(pf.RemainingFragmentCount() + 1))
			return err
		}
		r.Stats().IP.PacketsSent.Increment()
		if !more {
			break
		}
	}

	return nil
}

func (e *endpoint) addIPHeader(r *stack.Route, pkt *stack.PacketBuffer, params stack.NetworkHeaderParams) {
	ip := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
	length := uint16(pkt.Size())
	// RFC 6864 section 4.3 mandates uniqueness of ID values for non-atomic
	// datagrams. Since the DF bit is never being set here, all datagrams
	// are non-atomic and need an ID.
	id := atomic.AddUint32(&e.protocol.ids[hashRoute(r, params.Protocol, e.protocol.hashIV)%buckets], 1)
	ip.Encode(&header.IPv4Fields{
		IHL:         header.IPv4MinimumSize,
		TotalLength: length,
		ID:          uint16(id),
		TTL:         params.TTL,
		TOS:         params.TOS,
		Protocol:    uint8(params.Protocol),
		SrcAddr:     r.LocalAddress,
		DstAddr:     r.RemoteAddress,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	pkt.NetworkProtocolNumber = ProtocolNumber
}

// WritePacket writes a packet to the given destination address and protocol.
func (e *endpoint) WritePacket(r *stack.Route, gso *stack.GSO, params stack.NetworkHeaderParams, pkt *stack.PacketBuffer) *tcpip.Error {
	e.addIPHeader(r, pkt, params)

	// iptables filtering. All packets that reach here are locally
	// generated.
	nicName := e.protocol.stack.FindNICNameFromID(e.nic.ID())
	ipt := e.protocol.stack.IPTables()
	if ok := ipt.Check(stack.Output, pkt, gso, r, "", nicName); !ok {
		// iptables is telling us to drop the packet.
		r.Stats().IP.IPTablesOutputDropped.Increment()
		return nil
	}

	// If the packet is manipulated as per NAT Output rules, handle packet
	// based on destination address and do not send the packet to link
	// layer.
	//
	// TODO(gvisor.dev/issue/170): We should do this for every
	// packet, rather than only NATted packets, but removing this check
	// short circuits broadcasts before they are sent out to other hosts.
	if pkt.NatDone {
		netHeader := header.IPv4(pkt.NetworkHeader().View())
		ep, err := e.protocol.stack.FindNetworkEndpoint(ProtocolNumber, netHeader.DestinationAddress())
		if err == nil {
			route := r.ReverseRoute(netHeader.SourceAddress(), netHeader.DestinationAddress())
			ep.HandlePacket(&route, pkt)
			return nil
		}
	}

	if r.Loop&stack.PacketLoop != 0 {
		loopedR := r.MakeLoopedRoute()
		e.HandlePacket(&loopedR, pkt)
		loopedR.Release()
	}
	if r.Loop&stack.PacketOut == 0 {
		return nil
	}
	if pkt.Size() > int(e.nic.MTU()) && (gso == nil || gso.Type == stack.GSONone) {
		return e.writePacketFragments(r, gso, e.nic.MTU(), pkt)
	}
	if err := e.nic.WritePacket(r, gso, ProtocolNumber, pkt); err != nil {
		r.Stats().IP.OutgoingPacketErrors.Increment()
		return err
	}
	r.Stats().IP.PacketsSent.Increment()
	return nil
}

// WritePackets implements stack.NetworkEndpoint.WritePackets.
func (e *endpoint) WritePackets(r *stack.Route, gso *stack.GSO, pkts stack.PacketBufferList, params stack.NetworkHeaderParams) (int, *tcpip.Error) {
	if r.Loop&stack.PacketLoop != 0 {
		panic("multiple packets in local loop")
	}
	if r.Loop&stack.PacketOut == 0 {
		return pkts.Len(), nil
	}

	for pkt := pkts.Front(); pkt != nil; {
		e.addIPHeader(r, pkt, params)
		pkt = pkt.Next()
	}

	nicName := e.protocol.stack.FindNICNameFromID(e.nic.ID())
	// iptables filtering. All packets that reach here are locally
	// generated.
	ipt := e.protocol.stack.IPTables()
	dropped, natPkts := ipt.CheckPackets(stack.Output, pkts, gso, r, nicName)
	if len(dropped) == 0 && len(natPkts) == 0 {
		// Fast path: If no packets are to be dropped then we can just invoke the
		// faster WritePackets API directly.
		n, err := e.nic.WritePackets(r, gso, pkts, ProtocolNumber)
		r.Stats().IP.PacketsSent.IncrementBy(uint64(n))
		if err != nil {
			r.Stats().IP.OutgoingPacketErrors.IncrementBy(uint64(pkts.Len() - n))
		}
		return n, err
	}
	r.Stats().IP.IPTablesOutputDropped.IncrementBy(uint64(len(dropped)))

	// Slow path as we are dropping some packets in the batch degrade to
	// emitting one packet at a time.
	n := 0
	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		if _, ok := dropped[pkt]; ok {
			continue
		}
		if _, ok := natPkts[pkt]; ok {
			netHeader := header.IPv4(pkt.NetworkHeader().View())
			if ep, err := e.protocol.stack.FindNetworkEndpoint(ProtocolNumber, netHeader.DestinationAddress()); err == nil {
				src := netHeader.SourceAddress()
				dst := netHeader.DestinationAddress()
				route := r.ReverseRoute(src, dst)
				ep.HandlePacket(&route, pkt)
				n++
				continue
			}
		}
		if err := e.nic.WritePacket(r, gso, ProtocolNumber, pkt); err != nil {
			r.Stats().IP.PacketsSent.IncrementBy(uint64(n))
			r.Stats().IP.OutgoingPacketErrors.IncrementBy(uint64(pkts.Len() - n - len(dropped)))
			// Dropped packets aren't errors, so include them in
			// the return value.
			return n + len(dropped), err
		}
		n++
	}
	r.Stats().IP.PacketsSent.IncrementBy(uint64(n))
	// Dropped packets aren't errors, so include them in the return value.
	return n + len(dropped), nil
}

// WriteHeaderIncludedPacket writes a packet already containing a network
// header through the given route.
func (e *endpoint) WriteHeaderIncludedPacket(r *stack.Route, pkt *stack.PacketBuffer) *tcpip.Error {
	// The packet already has an IP header, but there are a few required
	// checks.
	h, ok := pkt.Data.PullUp(header.IPv4MinimumSize)
	if !ok {
		return tcpip.ErrInvalidOptionValue
	}
	ip := header.IPv4(h)
	if !ip.IsValid(pkt.Data.Size()) {
		return tcpip.ErrInvalidOptionValue
	}

	// Always set the total length.
	ip.SetTotalLength(uint16(pkt.Data.Size()))

	// Set the source address when zero.
	if ip.SourceAddress() == tcpip.Address(([]byte{0, 0, 0, 0})) {
		ip.SetSourceAddress(r.LocalAddress)
	}

	// Set the destination. If the packet already included a destination,
	// it will be part of the route.
	ip.SetDestinationAddress(r.RemoteAddress)

	// Set the packet ID when zero.
	if ip.ID() == 0 {
		// RFC 6864 section 4.3 mandates uniqueness of ID values for
		// non-atomic datagrams, so assign an ID to all such datagrams
		// according to the definition given in RFC 6864 section 4.
		if ip.Flags()&header.IPv4FlagDontFragment == 0 || ip.Flags()&header.IPv4FlagMoreFragments != 0 || ip.FragmentOffset() > 0 {
			ip.SetID(uint16(atomic.AddUint32(&e.protocol.ids[hashRoute(r, 0 /* protocol */, e.protocol.hashIV)%buckets], 1)))
		}
	}

	// Always set the checksum.
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())

	if r.Loop&stack.PacketLoop != 0 {
		e.HandlePacket(r, pkt.Clone())
	}
	if r.Loop&stack.PacketOut == 0 {
		return nil
	}

	if err := e.nic.WritePacket(r, nil /* gso */, ProtocolNumber, pkt); err != nil {
		r.Stats().IP.OutgoingPacketErrors.Increment()
		return err
	}
	r.Stats().IP.PacketsSent.Increment()
	return nil
}

// HandlePacket is called by the link layer when new ipv4 packets arrive for
// this endpoint.
func (e *endpoint) HandlePacket(r *stack.Route, pkt *stack.PacketBuffer) {
	if !e.isEnabled() {
		return
	}

	h := header.IPv4(pkt.NetworkHeader().View())
	if !h.IsValid(pkt.Data.Size() + pkt.NetworkHeader().View().Size() + pkt.TransportHeader().View().Size()) {
		r.Stats().IP.MalformedPacketsReceived.Increment()
		return
	}

	// As per RFC 1122 section 3.2.1.3:
	//   When a host sends any datagram, the IP source address MUST
	//   be one of its own IP addresses (but not a broadcast or
	//   multicast address).
	if r.IsOutboundBroadcast() || header.IsV4MulticastAddress(r.RemoteAddress) {
		r.Stats().IP.InvalidSourceAddressesReceived.Increment()
		return
	}

	// iptables filtering. All packets that reach here are intended for
	// this machine and will not be forwarded.
	ipt := e.protocol.stack.IPTables()
	if ok := ipt.Check(stack.Input, pkt, nil, nil, "", ""); !ok {
		// iptables is telling us to drop the packet.
		r.Stats().IP.IPTablesInputDropped.Increment()
		return
	}

	if h.More() || h.FragmentOffset() != 0 {
		if pkt.Data.Size()+pkt.TransportHeader().View().Size() == 0 {
			// Drop the packet as it's marked as a fragment but has
			// no payload.
			r.Stats().IP.MalformedPacketsReceived.Increment()
			r.Stats().IP.MalformedFragmentsReceived.Increment()
			return
		}
		// The packet is a fragment, let's try to reassemble it.
		start := h.FragmentOffset()
		// Drop the fragment if the size of the reassembled payload would exceed the
		// maximum payload size.
		//
		// Note that this addition doesn't overflow even on 32bit architecture
		// because pkt.Data.Size() should not exceed 65535 (the max IP datagram
		// size). Otherwise the packet would've been rejected as invalid before
		// reaching here.
		if int(start)+pkt.Data.Size() > header.IPv4MaximumPayloadSize {
			r.Stats().IP.MalformedPacketsReceived.Increment()
			r.Stats().IP.MalformedFragmentsReceived.Increment()
			return
		}
		var ready bool
		var err error
		proto := h.Protocol()
		pkt.Data, _, ready, err = e.protocol.fragmentation.Process(
			// As per RFC 791 section 2.3, the identification value is unique
			// for a source-destination pair and protocol.
			fragmentation.FragmentID{
				Source:      h.SourceAddress(),
				Destination: h.DestinationAddress(),
				ID:          uint32(h.ID()),
				Protocol:    proto,
			},
			start,
			start+uint16(pkt.Data.Size())-1,
			h.More(),
			proto,
			pkt.Data,
		)
		if err != nil {
			r.Stats().IP.MalformedPacketsReceived.Increment()
			r.Stats().IP.MalformedFragmentsReceived.Increment()
			return
		}
		if !ready {
			return
		}

		h.SetTotalLength(uint16(pkt.Data.Size() + len((h))))
		h.SetFlagsFragmentOffset(0, 0)
	}
	r.Stats().IP.PacketsDelivered.Increment()

	p := h.TransportProtocol()
	if p == header.ICMPv4ProtocolNumber {
		// TODO(gvisor.dev/issues/3810): when we sort out ICMP and transport
		// headers, the setting of the transport number here should be
		// unnecessary and removed.
		pkt.TransportProtocolNumber = p
		e.handleICMP(r, pkt)
		return
	}
	// XXX check all this  there was a mess on merge
	if len(h) > header.IPv4MinimumSize {
		aux, _, err := processIPOptions(r, h.Options(), ProcessIPOptionsDestination)
		if err != nil {
			// XXX use if errors.Is(err, os.ErrExist)
			if err == header.ErrIPv4TimestampOptInvalidPointer || err == header.ErrIPv4TimestampOptOverflow {
				_ = e.protocol.returnError(r, &icmpReasonParamProblem{pointer: aux}, pkt)
				e.protocol.stack.Stats().MalformedRcvdPackets.Increment()
				r.Stats().IP.MalformedPacketsReceived.Increment()
			}
			return
		}
		// If we did forwarding or had PacketInfo we would use the verified
		// options
	}

	switch res := e.dispatcher.DeliverTransportPacket(r, p, pkt); res {
	case stack.TransportPacketHandled:
	case stack.TransportPacketDestinationPortUnreachable:
		// As per RFC: 1122 Section 3.2.2.1 A host SHOULD generate Destination
		//   Unreachable messages with code:
		//     3 (Port Unreachable), when the designated transport protocol
		//     (e.g., UDP) is unable to demultiplex the datagram but has no
		//     protocol mechanism to inform the sender.
		_ = e.protocol.returnError(r, &icmpReasonPortUnreachable{}, pkt)
	case stack.TransportPacketProtocolUnreachable:
		// As per RFC: 1122 Section 3.2.2.1
		//   A host SHOULD generate Destination Unreachable messages with code:
		//     2 (Protocol Unreachable), when the designated transport protocol
		//     is not supported
		_ = e.protocol.returnError(r, &icmpReasonProtoUnreachable{}, pkt)
	default:
		panic(fmt.Sprintf("unrecognized result from DeliverTransportPacket = %d", res))
	}
}

// Close cleans up resources associated with the endpoint.
func (e *endpoint) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.disableLocked()
	e.mu.addressableEndpointState.Cleanup()
}

// AddAndAcquirePermanentAddress implements stack.AddressableEndpoint.
func (e *endpoint) AddAndAcquirePermanentAddress(addr tcpip.AddressWithPrefix, peb stack.PrimaryEndpointBehavior, configType stack.AddressConfigType, deprecated bool) (stack.AddressEndpoint, *tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mu.addressableEndpointState.AddAndAcquirePermanentAddress(addr, peb, configType, deprecated)
}

// RemovePermanentAddress implements stack.AddressableEndpoint.
func (e *endpoint) RemovePermanentAddress(addr tcpip.Address) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mu.addressableEndpointState.RemovePermanentAddress(addr)
}

// MainAddress implements stack.AddressableEndpoint.
func (e *endpoint) MainAddress() tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.MainAddress()
}

// AcquireAssignedAddress implements stack.AddressableEndpoint.
func (e *endpoint) AcquireAssignedAddress(localAddr tcpip.Address, allowTemp bool, tempPEB stack.PrimaryEndpointBehavior) stack.AddressEndpoint {
	e.mu.Lock()
	defer e.mu.Unlock()

	loopback := e.nic.IsLoopback()
	addressEndpoint := e.mu.addressableEndpointState.ReadOnly().AddrOrMatching(localAddr, allowTemp, func(addressEndpoint stack.AddressEndpoint) bool {
		subnet := addressEndpoint.AddressWithPrefix().Subnet()
		// IPv4 has a notion of a subnet broadcast address and considers the
		// loopback interface bound to an address's whole subnet (on linux).
		return subnet.IsBroadcast(localAddr) || (loopback && subnet.Contains(localAddr))
	})
	if addressEndpoint != nil {
		return addressEndpoint
	}

	if !allowTemp {
		return nil
	}

	addr := localAddr.WithPrefix()
	addressEndpoint, err := e.mu.addressableEndpointState.AddAndAcquireTemporaryAddress(addr, tempPEB)
	if err != nil {
		// AddAddress only returns an error if the address is already assigned,
		// but we just checked above if the address exists so we expect no error.
		panic(fmt.Sprintf("e.mu.addressableEndpointState.AddAndAcquireTemporaryAddress(%s, %d): %s", addr, tempPEB, err))
	}
	return addressEndpoint
}

// AcquireOutgoingPrimaryAddress implements stack.AddressableEndpoint.
func (e *endpoint) AcquireOutgoingPrimaryAddress(remoteAddr tcpip.Address, allowExpired bool) stack.AddressEndpoint {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.AcquireOutgoingPrimaryAddress(remoteAddr, allowExpired)
}

// PrimaryAddresses implements stack.AddressableEndpoint.
func (e *endpoint) PrimaryAddresses() []tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.PrimaryAddresses()
}

// PermanentAddresses implements stack.AddressableEndpoint.
func (e *endpoint) PermanentAddresses() []tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.PermanentAddresses()
}

// JoinGroup implements stack.GroupAddressableEndpoint.
func (e *endpoint) JoinGroup(addr tcpip.Address) (bool, *tcpip.Error) {
	if !header.IsV4MulticastAddress(addr) {
		return false, tcpip.ErrBadAddress
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mu.addressableEndpointState.JoinGroup(addr)
}

// LeaveGroup implements stack.GroupAddressableEndpoint.
func (e *endpoint) LeaveGroup(addr tcpip.Address) (bool, *tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mu.addressableEndpointState.LeaveGroup(addr)
}

// IsInGroup implements stack.GroupAddressableEndpoint.
func (e *endpoint) IsInGroup(addr tcpip.Address) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.IsInGroup(addr)
}

var _ stack.ForwardingNetworkProtocol = (*protocol)(nil)
var _ stack.NetworkProtocol = (*protocol)(nil)

type protocol struct {
	stack *stack.Stack

	// defaultTTL is the current default TTL for the protocol. Only the
	// uint8 portion of it is meaningful.
	//
	// Must be accessed using atomic operations.
	defaultTTL uint32

	// forwarding is set to 1 when the protocol has forwarding enabled and 0
	// when it is disabled.
	//
	// Must be accessed using atomic operations.
	forwarding uint32

	ids    []uint32
	hashIV uint32

	fragmentation *fragmentation.Fragmentation
}

// Number returns the ipv4 protocol number.
func (p *protocol) Number() tcpip.NetworkProtocolNumber {
	return ProtocolNumber
}

// MinimumPacketSize returns the minimum valid ipv4 packet size.
func (p *protocol) MinimumPacketSize() int {
	return header.IPv4MinimumSize
}

// DefaultPrefixLen returns the IPv4 default prefix length.
func (p *protocol) DefaultPrefixLen() int {
	return header.IPv4AddressSize * 8
}

// ParseAddresses implements NetworkProtocol.ParseAddresses.
func (*protocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	h := header.IPv4(v)
	return h.SourceAddress(), h.DestinationAddress()
}

// SetOption implements NetworkProtocol.SetOption.
func (p *protocol) SetOption(option tcpip.SettableNetworkProtocolOption) *tcpip.Error {
	switch v := option.(type) {
	case *tcpip.DefaultTTLOption:
		p.SetDefaultTTL(uint8(*v))
		return nil
	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

// Option implements NetworkProtocol.Option.
func (p *protocol) Option(option tcpip.GettableNetworkProtocolOption) *tcpip.Error {
	switch v := option.(type) {
	case *tcpip.DefaultTTLOption:
		*v = tcpip.DefaultTTLOption(p.DefaultTTL())
		return nil
	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

// SetDefaultTTL sets the default TTL for endpoints created with this protocol.
func (p *protocol) SetDefaultTTL(ttl uint8) {
	atomic.StoreUint32(&p.defaultTTL, uint32(ttl))
}

// DefaultTTL returns the default TTL for endpoints created with this protocol.
func (p *protocol) DefaultTTL() uint8 {
	return uint8(atomic.LoadUint32(&p.defaultTTL))
}

// Close implements stack.TransportProtocol.Close.
func (*protocol) Close() {}

// Wait implements stack.TransportProtocol.Wait.
func (*protocol) Wait() {}

// Parse implements stack.NetworkProtocol.Parse.
func (*protocol) Parse(pkt *stack.PacketBuffer) (proto tcpip.TransportProtocolNumber, hasTransportHdr bool, ok bool) {
	if ok := parse.IPv4(pkt); !ok {
		return 0, false, false
	}

	ipHdr := header.IPv4(pkt.NetworkHeader().View())
	return ipHdr.TransportProtocol(), !ipHdr.More() && ipHdr.FragmentOffset() == 0, true
}

// Forwarding implements stack.ForwardingNetworkProtocol.
func (p *protocol) Forwarding() bool {
	return uint8(atomic.LoadUint32(&p.forwarding)) == 1
}

// SetForwarding implements stack.ForwardingNetworkProtocol.
func (p *protocol) SetForwarding(v bool) {
	if v {
		atomic.StoreUint32(&p.forwarding, 1)
	} else {
		atomic.StoreUint32(&p.forwarding, 0)
	}
}

// calculateMTU calculates the network-layer payload MTU based on the link-layer
// payload mtu.
func calculateMTU(mtu uint32) uint32 {
	if mtu > MaxTotalSize {
		mtu = MaxTotalSize
	}
	return mtu - header.IPv4MinimumSize
}

// calculateFragmentInnerMTU calculates the maximum number of bytes of
// fragmentable data a fragment can have, based on the link layer mtu and pkt's
// network header size.
func calculateFragmentInnerMTU(mtu uint32, pkt *stack.PacketBuffer) uint32 {
	if mtu > MaxTotalSize {
		mtu = MaxTotalSize
	}
	mtu -= uint32(pkt.NetworkHeader().View().Size())
	// Round the MTU down to align to 8 bytes.
	mtu &^= 7
	return mtu
}

// addressToUint32 translates an IPv4 address into its little endian uint32
// representation.
//
// This function does the same thing as binary.LittleEndian.Uint32 but operates
// on a tcpip.Address (a string) without the need to convert it to a byte slice,
// which would cause an allocation.
func addressToUint32(addr tcpip.Address) uint32 {
	_ = addr[3] // bounds check hint to compiler
	return uint32(addr[0]) | uint32(addr[1])<<8 | uint32(addr[2])<<16 | uint32(addr[3])<<24
}

// hashRoute calculates a hash value for the given route. It uses the source &
// destination address, the transport protocol number and a 32-bit number to
// generate the hash.
func hashRoute(r *stack.Route, protocol tcpip.TransportProtocolNumber, hashIV uint32) uint32 {
	a := addressToUint32(r.LocalAddress)
	b := addressToUint32(r.RemoteAddress)
	return hash.Hash3Words(a, b, uint32(protocol), hashIV)
}

// NewProtocol returns an IPv4 network protocol.
func NewProtocol(s *stack.Stack) stack.NetworkProtocol {
	ids := make([]uint32, buckets)

	// Randomly initialize hashIV and the ids.
	r := hash.RandN32(1 + buckets)
	for i := range ids {
		ids[i] = r[i]
	}
	hashIV := r[buckets]

	return &protocol{
		stack:         s,
		ids:           ids,
		hashIV:        hashIV,
		defaultTTL:    DefaultTTL,
		fragmentation: fragmentation.NewFragmentation(fragmentblockSize, fragmentation.HighFragThreshold, fragmentation.LowFragThreshold, reassembleTimeout, s.Clock()),
	}
}

func buildNextFragment(pf *fragmentation.PacketFragmenter, originalIPHeader header.IPv4) (*stack.PacketBuffer, bool) {
	fragPkt, offset, copied, more := pf.BuildNextFragment()
	fragPkt.NetworkProtocolNumber = ProtocolNumber

	originalIPHeaderLength := len(originalIPHeader)
	nextFragIPHeader := header.IPv4(fragPkt.NetworkHeader().Push(originalIPHeaderLength))

	if copied := copy(nextFragIPHeader, originalIPHeader); copied != len(originalIPHeader) {
		panic(fmt.Sprintf("wrong number of bytes copied into fragmentIPHeaders: got = %d, want = %d", copied, originalIPHeaderLength))
	}

	flags := originalIPHeader.Flags()
	if more {
		flags |= header.IPv4FlagMoreFragments
	}
	nextFragIPHeader.SetFlagsFragmentOffset(flags, uint16(offset))
	nextFragIPHeader.SetTotalLength(uint16(nextFragIPHeader.HeaderLength()) + uint16(copied))
	nextFragIPHeader.SetChecksum(0)
	nextFragIPHeader.SetChecksum(^nextFragIPHeader.CalculateChecksum())

	return fragPkt, more
}

// handleTimestamp() checks and  processes an IP Timestamp option.
func handleTimestamp(tsOpt header.IPv4OptionTimestamp, localAddress tcpip.Address, op IPOptionsOperation) (byte, error) {
	flags := tsOpt.Flags()
	optlen := tsOpt.Size()

	var entrySize uint8
	switch flags {
	case header.IPv4OptionTimestampOnlyFlag:
		entrySize = header.IPv4OptionTimestampSize
	case header.IPv4OptionTimestampWithIPFlag, header.IPv4OptionTimestampWithPredefinedIPFlag:
		entrySize = header.IPv4OptionTimestampWithAddrSize
	default:
		return 3, header.ErrIPv4TimestampOptInvalidFlags
	}

	if optlen > header.IPv4OptionTimestampMaxSize || optlen < entrySize+header.IPv4OptionTimestampHdrLength {
		return 1, header.ErrIPv4TimestampOptInvalidLength
	}

	// If we are not going to write, then we don't need to check for room.
	if op == ProcessIPOptionsDestination {
		return 0, nil
	}

	start := tsOpt.Pointer()
	// Set 'pointer' to be a 0 based offset from the base of the timestamp
	// data section. In the packet it is a 1 based offset from the start of the
	// timestamp header.
	// e.g. for a 1 stamp sized data area:
	// 1 2 3 4 | 5 6 7 8 | 9    <--- in packet
	// _ _ _ _ | 0 1 2 3 | 4    <--- 'pointer'
	//
	// Also make optlen based on the data part only.
	pointer := start - (header.IPv4OptionTimestampHdrLength + 1)
	optlen -= header.IPv4OptionTimestampHdrLength

	if pointer == optlen {
		// The data area is full...
		if flags == header.IPv4OptionTimestampWithPredefinedIPFlag {
			// By definition we have nothing to do.
			return 0, nil
		}
		if tsOpt.IncOverflow() == 0 {
			// The overflow count is also full.
			// RFC 791 (page 22) says we should discard the packet.
			//
			//    If there is some room but not enough room for a full timestamp
			//    to be inserted, or the overflow count itself overflows, the
			//    original datagram is considered to be in error and is discarded.
			//    In either case an ICMP parameter problem message may be sent to
			//    the source host [3].
			return 3, header.ErrIPv4TimestampOptOverflow
		}
		return 0, nil
	}

	if pointer > optlen-entrySize {
		// The data area isn't full but there isn't room for a new entry.
		// RFC 791 (see above) suggests this is a different error to being full
		// as we don't use the overflow counter.
		return 2, header.ErrIPv4TimestampOptInvalidPointer
	}

	target := header.IPv4OptTimestampEntry(tsOpt[start-1 : start+entrySize-1])
	if flags == header.IPv4OptionTimestampWithPredefinedIPFlag && target.Address() != localAddress {
		return 0, nil
	}

	switch flags {
	case header.IPv4OptionTimestampOnlyFlag:
		target.SetTimestamp()
		tsOpt.IncPointer(entrySize)
	case header.IPv4OptionTimestampWithIPFlag:
		target.SetIPAddress(localAddress)
		target.SetTimestamp()
		tsOpt.IncPointer(entrySize)
	case header.IPv4OptionTimestampWithPredefinedIPFlag:
		if target.Address() == localAddress {
			target.SetTimestamp()
			tsOpt.IncPointer(entrySize)
		}
	}
	return 0, nil
}

// The IPOptionsOperation type enumerates the ways options
// maybe operated upon during packet reception.
type IPOptionsOperation int

// These values enumerate the ways that the options may need to
// be processed. Options being echoed, forwarded or accepted
// need to be treated slightly differntly.
const (
	ProcessIPOptionsEcho IPOptionsOperation = iota
	ProcessIPOptionsForward
	ProcessIPOptionsDestination
)

// processIPOptions parses the IPv4 options and produces a new set of options
// suitable for use in the next step of packet processing as informed by op.
// The original must not be touched as an original may need to be send back
// to its sender in the case of an error. In some cases the resulting header may
// end up shorter than the original (e.g. in the case of fragmentation).
// processIPOptions can run in three "modes" depending on whether the packet will
// be sent further or not. There are two cases where the packet is sent on.
// Firstly there is the forwarding case (not fully supported in this code) and
// secondly the case of an ICMP echo request, which effectively forwards the packet
// back to the originator.In the remaining case, the packet is being received
// locally, and the options need only be verified, and none of the processing
// that results in changes to the options block need be performed.
// XXX A fourth case, used when fragmenting a packet is not yet supported.
//
// This is called upon reception before forwarding (or echoing).
// In order to correctly process some options we need some information about
// the interface on which the packet will be sent next, specifically whether it
// has a given address or what it's main address is. This information is
// accessed via the supplied route, which is expected to reflect the next hop,
// or in the case of ICMP echo requests, if this is the destination, the return
// path.
//
// Returns
// - The location of an error if there was one (or 0 if no error)
// - If there is an error, information as to what it was was.
// - The replacement option set.
//
func processIPOptions(r *stack.Route, orig header.IPv4OptionsBuffer, op IPOptionsOperation) (byte, header.IPv4OptionsBuffer, error) {
	opts := header.IPv4OptionsBuffer(orig)
	optIter := opts.NewIterator()

	var scoreBoard [256]bool

	for {
		option, done, err := optIter.Next()
		if done || err != nil {
			optIter.CloseBuffer()
			return optIter.ErrCursor, optIter.NewOptions(), err
		}
		optType := option.Type()
		if optType == header.IPv4OptionNopType {
			optIter.PushByte(optType)
			continue
		}
		if optType == header.IPv4OptionListEndType {
			optIter.PushByte(optType)
			optIter.CloseBuffer()
			return optIter.ErrCursor, optIter.NewOptions(), err
		}

		// check for repeating options (multiple NOPs are OK)
		if scoreBoard[optType] {
			return optIter.ErrCursor, nil, header.ErrIPv4OptInvalid
		}
		scoreBoard[optType] = true

		switch option := option.(type) {
		case header.IPv4OptionTimestamp:
			// Copy the timestamp option into the out going buffer and process it.
			r.Stats().IP.OptionTSReceived.Increment()
			newBuffer := optIter.WriteBuffer()[:len(option)]
			copy(newBuffer, option.Contents()) // prepare for in-place processing
			offset, ret := handleTimestamp(header.IPv4OptionTimestamp(newBuffer), r.LocalAddress, op)
			if ret != nil {
				return optIter.ErrCursor + offset, nil, ret
			}
			optIter.ConsumeBuffer(int(option.Size()))

		case header.IPv4OptionRecordRoute:
			r.Stats().IP.OptionRRReceived.Increment()
		default:
			r.Stats().IP.OptionUnknownReceived.Increment()
			// This is a completely unknown option to us.
			return optIter.ErrCursor, nil, header.ErrIPv4OptInvalid
		}
	}
}
