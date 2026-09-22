import BlakTailCore
import Foundation
import Network

/// Answers A/AAAA for enrolled names on the overlay DNS domain. No recursive resolver.
struct MagicDNSResponder {
    var domain: String
    var records: [String: [RecordAddress]]

    init(enrollment: NodeEnrollment, peers: [CoordinatorPeer]) {
        domain = MagicDNS.domain(from: enrollment.dnsName) ?? ""
        var records: [String: [RecordAddress]] = [:]
        func add(name: String, addresses: [String]) {
            let host = name.trimmingCharacters(in: CharacterSet(charactersIn: ".")).lowercased()
            guard !host.isEmpty else { return }
            records[host, default: []].append(contentsOf: addresses.compactMap(Self.address(from:)))
        }
        add(name: enrollment.dnsName, addresses: enrollment.interfaceAddresses)
        if let label = MagicDNS.hostLabel(from: enrollment.dnsName), !domain.isEmpty {
            add(name: "\(label).\(domain)", addresses: enrollment.interfaceAddresses)
        }
        for peer in peers {
            add(name: peer.dnsName, addresses: peer.allowedIPs)
            if let label = MagicDNS.hostLabel(from: peer.dnsName), !domain.isEmpty {
                add(name: "\(label).\(domain)", addresses: peer.allowedIPs)
            }
        }
        self.records = records
    }

    func answer(query packet: Data) -> Data? {
        guard packet.count >= 12 else { return nil }
        let qdcount = Int(packet[4]) << 8 | Int(packet[5])
        guard qdcount >= 1 else { return nil }
        var offset = 12
        guard let name = readName(packet, offset: &offset) else { return nil }
        guard offset + 4 <= packet.count else { return nil }
        let type = Int(packet[offset]) << 8 | Int(packet[offset + 1])
        offset += 4
        let answers = records[name.lowercased()] ?? []
        let selected: [Data]
        switch type {
        case 1:
            selected = answers.compactMap(\.v4)
        case 28:
            selected = answers.compactMap(\.v6)
        default:
            selected = []
        }

        var response = Data(packet.prefix(offset))
        response[2] = 0x81
        response[3] = selected.isEmpty ? 0x83 : 0x80
        response[6] = 0
        response[7] = UInt8(selected.count)
        response[8] = 0
        response[9] = 0
        response[10] = 0
        response[11] = 0
        for rdata in selected {
            response.append(contentsOf: [0xC0, 0x0C])
            response.append(contentsOf: [UInt8(type >> 8), UInt8(type & 0xFF), 0x00, 0x01])
            response.append(contentsOf: [0x00, 0x00, 0x00, 0x1E])
            response.append(contentsOf: [UInt8(rdata.count >> 8), UInt8(rdata.count & 0xFF)])
            response.append(rdata)
        }
        return response
    }

    private func readName(_ packet: Data, offset: inout Int) -> String? {
        var labels: [String] = []
        var jumped = false
        var cursor = offset
        for _ in 0..<16 {
            guard cursor < packet.count else { return nil }
            let length = Int(packet[cursor])
            if length == 0 {
                if !jumped { offset = cursor + 1 }
                return labels.joined(separator: ".")
            }
            if length & 0xC0 == 0xC0 {
                guard cursor + 1 < packet.count else { return nil }
                let pointer = ((length & 0x3F) << 8) | Int(packet[cursor + 1])
                if !jumped { offset = cursor + 2 }
                cursor = pointer
                jumped = true
                continue
            }
            cursor += 1
            guard cursor + length <= packet.count else { return nil }
            guard let label = String(data: packet[cursor..<(cursor + length)], encoding: .utf8) else {
                return nil
            }
            labels.append(label)
            cursor += length
        }
        return nil
    }

    private static func address(from cidr: String) -> RecordAddress? {
        let host = cidr.split(separator: "/").first.map(String.init) ?? cidr
        if let v4 = IPv4Address(host) {
            var bytes = [UInt8](repeating: 0, count: 4)
            withUnsafeBytes(of: v4.rawValue) { raw in
                for (index, byte) in raw.prefix(4).enumerated() {
                    bytes[index] = byte
                }
            }
            return .v4(Data(bytes))
        }
        if let v6 = IPv6Address(host) {
            var bytes = [UInt8](repeating: 0, count: 16)
            withUnsafeBytes(of: v6.rawValue) { raw in
                for (index, byte) in raw.prefix(16).enumerated() {
                    bytes[index] = byte
                }
            }
            return .v6(Data(bytes))
        }
        return nil
    }

    struct RecordAddress {
        var v4: Data?
        var v6: Data?

        static func v4(_ data: Data) -> RecordAddress { RecordAddress(v4: data, v6: nil) }
        static func v6(_ data: Data) -> RecordAddress { RecordAddress(v4: nil, v6: data) }
    }
}
