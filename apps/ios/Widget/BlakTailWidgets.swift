import BlakTailPhone
import SwiftUI
import WidgetKit

@main
struct BlakTailWidgets: WidgetBundle {
    var body: some Widget {
        BlakTailStatusWidget()
    }
}

struct BlakTailStatusWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: PhoneWidgetSnapshot.kind, provider: StatusProvider()) { entry in
            BlakTailWidgetView(entry: entry)
                .containerBackground(.fill.tertiary, for: .widget)
        }
        .configurationDisplayName("BlakTail")
        .description("Shows whether this iPhone is on the organisation network.")
        .supportedFamilies([.systemSmall, .systemMedium, .accessoryRectangular, .accessoryInline])
    }
}

struct StatusEntry: TimelineEntry {
    let date: Date
    let snapshot: PhoneWidgetSnapshot
}

struct StatusProvider: TimelineProvider {
    func placeholder(in context: Context) -> StatusEntry {
        StatusEntry(date: .now, snapshot: .placeholder)
    }

    func getSnapshot(in context: Context, completion: @escaping (StatusEntry) -> Void) {
        let snapshot = context.isPreview ? PhoneWidgetSnapshot.placeholder : PhoneWidgetStore.load()
        completion(StatusEntry(date: .now, snapshot: snapshot))
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<StatusEntry>) -> Void) {
        let entry = StatusEntry(date: .now, snapshot: PhoneWidgetStore.load())
        let next = Calendar.current.date(byAdding: .minute, value: 15, to: .now) ?? .now.addingTimeInterval(900)
        completion(Timeline(entries: [entry], policy: .after(next)))
    }
}

struct BlakTailWidgetView: View {
    let entry: StatusEntry
    @Environment(\.widgetFamily) private var family

    var body: some View {
        switch family {
        case .accessoryInline:
            Text(entry.snapshot.connected ? "BlakTail connected" : "BlakTail off")
        case .accessoryRectangular:
            VStack(alignment: .leading) {
                Text("BlakTail").font(.headline)
                Text(entry.snapshot.label)
                if !entry.snapshot.address.isEmpty {
                    Text(entry.snapshot.address).font(.caption2)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        default:
            VStack(alignment: .leading, spacing: 6) {
                Text("BlakTail").font(.headline)
                Text(entry.snapshot.organisation.isEmpty ? "This iPhone" : entry.snapshot.organisation)
                    .font(.subheadline)
                    .lineLimit(1)
                Text(entry.snapshot.label)
                if !entry.snapshot.address.isEmpty {
                    Text(entry.snapshot.address)
                        .font(.caption)
                        .lineLimit(1)
                }
                Spacer(minLength: 0)
                if family != .accessoryCircular, entry.snapshot.enrolled {
                    Button(intent: SetTunnelIntent(connected: !entry.snapshot.connected)) {
                        Text(entry.snapshot.connected ? "Disconnect" : "Connect")
                    }
                    .buttonStyle(.bordered)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
        }
    }
}
