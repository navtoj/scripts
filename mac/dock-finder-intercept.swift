import AppKit
import ApplicationServices

// MARK: - Arguments

guard CommandLine.arguments.count >= 2 else {
	FileHandle.standardError.write(Data(
		"Usage: dock-finder-intercept <path/to/alternative.app>\n".utf8
	))
	exit(64) // EX_USAGE
}

let alternateAppURL = URL(fileURLWithPath: CommandLine.arguments[1])

// MARK: - Accessibility permission

@discardableResult
func ensureAccessibility(prompt: Bool) -> Bool {
	let key = kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String
	return AXIsProcessTrustedWithOptions([key: prompt] as CFDictionary)
}

// MARK: - Finder dock tile frame

/// Walks the Dock's AX tree and returns the screen frame of the Finder tile,
/// or nil if the Dock isn't running or the tile can't be located.
func dockFinderTileFrame() -> CGRect? {
	guard let dock = NSRunningApplication.runningApplications(withBundleIdentifier: "com.apple.dock").first else {
		return nil
	}
	let dockEl = AXUIElementCreateApplication(dock.processIdentifier)

	var childrenRef: CFTypeRef?
	guard
		AXUIElementCopyAttributeValue(dockEl, kAXChildrenAttribute as CFString, &childrenRef) == .success,
		let topChildren = childrenRef as? [AXUIElement]
	else { return nil }

	for child in topChildren {
		var roleRef: CFTypeRef?
		AXUIElementCopyAttributeValue(child, kAXRoleAttribute as CFString, &roleRef)
		guard (roleRef as? String) == "AXList" else { continue }

		var itemsRef: CFTypeRef?
		AXUIElementCopyAttributeValue(child, kAXChildrenAttribute as CFString, &itemsRef)
		guard let items = itemsRef as? [AXUIElement] else { continue }

		for item in items {
			var titleRef: CFTypeRef?
			AXUIElementCopyAttributeValue(item, kAXTitleAttribute as CFString, &titleRef)
			guard (titleRef as? String) == "Finder" else { continue }

			var posRef: CFTypeRef?
			var sizeRef: CFTypeRef?
			AXUIElementCopyAttributeValue(item, kAXPositionAttribute as CFString, &posRef)
			AXUIElementCopyAttributeValue(item, kAXSizeAttribute as CFString, &sizeRef)

			guard let p = posRef, let s = sizeRef else { return nil }
			var origin = CGPoint.zero
			var size = CGSize.zero
			AXValueGetValue(p as! AXValue, .cgPoint, &origin)
			AXValueGetValue(s as! AXValue, .cgSize, &size)
			return CGRect(origin: origin, size: size)
		}
	}
	return nil
}

// MARK: - Interceptor

final class Interceptor {
	let alternateAppURL: URL
	private var tap: CFMachPort?

	init(alternateAppURL: URL) {
		self.alternateAppURL = alternateAppURL
	}

	func start() {
		let mask: CGEventMask =
			(1 << CGEventType.leftMouseDown.rawValue) |
			(1 << CGEventType.tapDisabledByTimeout.rawValue) |
			(1 << CGEventType.tapDisabledByUserInput.rawValue)

		let refcon = Unmanaged.passUnretained(self).toOpaque()

		guard let tap = CGEvent.tapCreate(
			tap: .cgSessionEventTap,
			place: .headInsertEventTap,
			options: .defaultTap,
			eventsOfInterest: mask,
			callback: { _, type, event, refcon in
				let me = Unmanaged<Interceptor>.fromOpaque(refcon!).takeUnretainedValue()
				return me.handle(type: type, event: event)
			},
			userInfo: refcon
		) else {
			FileHandle.standardError.write(Data("Failed to create event tap.\n".utf8))
			exit(1)
		}

		self.tap = tap
		let source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, tap, 0)
		CFRunLoopAddSource(CFRunLoopGetCurrent(), source, .commonModes)
		CGEvent.tapEnable(tap: tap, enable: true)
	}

	private func handle(type: CGEventType, event: CGEvent) -> Unmanaged<CGEvent>? {
		// macOS disables slow/misbehaving taps — re-enable and carry on.
		if type == .tapDisabledByTimeout || type == .tapDisabledByUserInput {
			if let tap { CGEvent.tapEnable(tap: tap, enable: true) }
			return Unmanaged.passUnretained(event)
		}

		guard
			type == .leftMouseDown,
			let frame = dockFinderTileFrame(),
			frame.contains(event.location)
		else {
			return Unmanaged.passUnretained(event)
		}

		DispatchQueue.main.async { [alternateAppURL] in
			let cfg = NSWorkspace.OpenConfiguration()
			cfg.activates = true
			NSWorkspace.shared.openApplication(at: alternateAppURL, configuration: cfg)
		}
		return nil // swallow click — Finder never sees it
	}
}

// MARK: - Entry point

guard ensureAccessibility(prompt: true) else {
	FileHandle.standardError.write(Data(
		"Accessibility permission required. Grant it in System Settings > Privacy & Security > Accessibility, then relaunch.\n".utf8
	))
	exit(77) // EX_NOPERM
}

final class AppDelegate: NSObject, NSApplicationDelegate {
	let interceptor: Interceptor

	init(alternateAppURL: URL) {
		interceptor = Interceptor(alternateAppURL: alternateAppURL)
	}

	func applicationDidFinishLaunching(_: Notification) {
		interceptor.start()
	}
}

let app = NSApplication.shared
let delegate = AppDelegate(alternateAppURL: alternateAppURL)
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
