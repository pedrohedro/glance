//
//  glance-approve.swift
//  glance (tools)
//
//  Asks the running Glance app for a face approval. Exit 0 = approved, 1 = denied or Glance not reachable.
//
//      swiftc -O -o /usr/local/bin/glance-approve tools/glance-approve.swift
//      glance-approve "deploy to production" && ./deploy.sh
//

import Foundation

let reason = CommandLine.arguments.dropFirst().joined(separator: " ")
guard !reason.isEmpty else {
    FileHandle.standardError.write(Data("usage: glance-approve <reason>\n".utf8))
    exit(2)
}

let path = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    .appendingPathComponent("glance/approve.sock").path

let fd = socket(AF_UNIX, SOCK_STREAM, 0)
var addr = sockaddr_un()
addr.sun_family = sa_family_t(AF_UNIX)
withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: path.utf8) }
let connected = withUnsafePointer(to: &addr) {
    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
    }
}
guard connected == 0 else {
    FileHandle.standardError.write(Data("glance-approve: Glance is not running or approvals are off\n".utf8))
    exit(1)
}

_ = (reason + "\n").withCString { write(fd, $0, strlen($0)) }
var buffer = [UInt8](repeating: 0, count: 16)
let count = read(fd, &buffer, buffer.count)
exit(count >= 2 && buffer[0] == UInt8(ascii: "O") && buffer[1] == UInt8(ascii: "K") ? 0 : 1)
