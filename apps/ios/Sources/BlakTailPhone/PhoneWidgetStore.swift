import BlakTailCore
import Foundation
#if os(iOS)
import WidgetKit
#endif

public struct PhoneWidgetSnapshot: Codable, Equatable, Sendable {
    public static let kind = "BlakTailStatus"
    public static let placeholder = PhoneWidgetSnapshot(
        label: "Connected",
        organisation: "Community services",
        address: "100.64.0.8/32",
        connected: true,
        enrolled: true
    )

    public var label: String
    public var organisation: String
    public var address: String
    public var connected: Bool
    public var enrolled: Bool

    public init(label: String, organisation: String, address: String, connected: Bool, enrolled: Bool) {
        self.label = label
        self.organisation = organisation
        self.address = address
        self.connected = connected
        self.enrolled = enrolled
    }
}

public enum PhoneWidgetStore {
    private static let key = "widget.snapshot"

    public static func save(
        _ snapshot: PhoneWidgetSnapshot,
        suite: String = BlakTailIdentifiers.appGroup
    ) {
        guard let defaults = UserDefaults(suiteName: suite),
              let data = try? JSONEncoder().encode(snapshot)
        else {
            return
        }
        defaults.set(data, forKey: key)
        #if os(iOS)
        if suite == BlakTailIdentifiers.appGroup {
            WidgetCenter.shared.reloadTimelines(ofKind: PhoneWidgetSnapshot.kind)
        }
        #endif
    }

    public static func load(suite: String = BlakTailIdentifiers.appGroup) -> PhoneWidgetSnapshot {
        guard let defaults = UserDefaults(suiteName: suite),
              let data = defaults.data(forKey: key),
              let snapshot = try? JSONDecoder().decode(PhoneWidgetSnapshot.self, from: data)
        else {
            return PhoneWidgetSnapshot(
                label: "Off",
                organisation: "",
                address: "",
                connected: false,
                enrolled: false
            )
        }
        return snapshot
    }
}
