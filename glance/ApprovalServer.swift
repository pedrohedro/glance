//
//  ApprovalServer.swift
//  glance
//
//  Local "approve with your face" endpoint. A process of the same user connects to a Unix socket, sends one line (the
//  reason), and gets back "OK" or "DENY". Opt-in via GlanceSettings.isApprovalServerEnabled.
//
//  Trust model, and its ceiling: the socket is 0600 and the peer uid is checked, so only this user's processes can ask.
//  A request is never approved silently — the user must click Approve on a panel showing the reason AND pass the face +
//  liveness scan. This is weaker than Touch ID: a replayed video can pass liveness (see FaceUnlockCoordinator), and any
//  consumer granting privileges on "OK" (e.g. a PAM module) must itself verify that the socket's peer is really Glance.
//

import AppKit
import Foundation

final class ApprovalServer: @unchecked Sendable {
    static let shared = ApprovalServer()

    static var socketURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("glance-fork", isDirectory: true)
            .appendingPathComponent("approve.sock")
    }

    private var listenFD: Int32 = -1

    @MainActor
    func start(coordinator: FaceUnlockCoordinator) {
        guard listenFD < 0 else { return }
        let url = Self.socketURL
        try? FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        unlink(url.path)

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let path = url.path
        guard path.utf8.count < MemoryLayout.size(ofValue: addr.sun_path) else { close(fd); return }
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: path.utf8) }

        let oldMask = umask(0o177)
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        umask(oldMask)
        guard bound == 0, listen(fd, 4) == 0 else { close(fd); return }
        listenFD = fd

        Thread.detachNewThread { [weak coordinator] in
            while true {
                let client = accept(fd, nil, nil)
                // accept fails for good once stop() closes the listening socket.
                guard client >= 0 else { if errno == EINTR { continue } else { return } }
                Self.handle(client, coordinator: coordinator)
            }
        }
    }

    @MainActor
    func stop() {
        guard listenFD >= 0 else { return }
        close(listenFD)
        listenFD = -1
        unlink(Self.socketURL.path)
    }

    /// One request at a time, serially — a second prompt stacked on the first would be a confusion attack surface.
    private static func handle(_ client: Int32, coordinator: FaceUnlockCoordinator?) {
        defer { close(client) }

        var uid: uid_t = 0
        var gid: gid_t = 0
        // Root is allowed so a PAM module (running inside setuid sudo) can ask; root needs nothing from us anyway.
        guard getpeereid(client, &uid, &gid) == 0, uid == getuid() || uid == 0 else { return }

        // Never block the accept loop on a silent client.
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var buffer = [UInt8](repeating: 0, count: 256)
        let count = read(client, &buffer, buffer.count)
        guard count > 0 else { return }
        let reason = sanitize(String(decoding: buffer[0..<count], as: UTF8.self))

        let done = DispatchSemaphore(value: 0)
        nonisolated(unsafe) var denial: String? = "declined"
        Task { @MainActor in
            defer { done.signal() }
            guard let coordinator, confirm(reason: reason) else { return }
            denial = await coordinator.approve()
        }
        done.wait()

        let reply = denial.map { "DENY \($0)\n" } ?? "OK\n"
        _ = reply.withCString { write(client, $0, strlen($0)) }
    }

    /// The reason is attacker-controlled text shown next to an Approve button: keep it to one short printable line.
    private static func sanitize(_ raw: String) -> String {
        let line = raw.split(whereSeparator: \.isNewline).first.map(String.init) ?? ""
        let printable = line.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }
        return String(String.UnicodeScalarView(printable).prefix(120))
    }

    @MainActor
    private static func confirm(reason: String) -> Bool {
        let alert = NSAlert()
        alert.messageText = "Approve with your face?"
        alert.informativeText = "A process on this Mac is asking Glance to approve:\n\n\"\(reason)\"\n\nIf you didn't start this, choose Deny."
        alert.addButton(withTitle: "Deny")
        alert.addButton(withTitle: "Approve")
        NSApp.activate(ignoringOtherApps: true)
        return alert.runModal() == .alertSecondButtonReturn
    }
}
