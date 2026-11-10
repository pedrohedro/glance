//
//  pam_glance.c
//  glance (tools)
//
//  PAM auth module: asks the running Glance app for a face approval.
//  Meant for `auth sufficient pam_glance.so` in /etc/pam.d/sudo_local, so a
//  denial or any error falls through to the normal password prompt.
//
//  Build (TEAM = your Apple team id, the one that signs Glance):
//      clang -O2 -bundle -o pam_glance.so tools/pam/pam_glance.c \
//        -DGLANCE_TEAM_ID='"TEAM"' -lpam -framework Security -framework CoreFoundation
//  Self-test without installing anything (run as yourself, exit 0 = approved):
//      clang -O2 -DPAM_GLANCE_SELFTEST -o pam_glance_test tools/pam/pam_glance.c \
//        -DGLANCE_TEAM_ID='"TEAM"' -framework Security -framework CoreFoundation
//
//  Security: the socket lives in a directory the user can write, so anything
//  running as that user could put its own listener there. The module therefore
//  only trusts a peer whose running code is signed as Glance by GLANCE_TEAM_ID.
//  That check is only meaningful if Glance itself is built with the hardened
//  runtime and WITHOUT get-task-allow (a debug build can be driven by any
//  process of the same user). Face matching from a 2D webcam is weaker than
//  Touch ID: a replayed video can pass.
//

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <bsm/libbsm.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#ifndef GLANCE_TEAM_ID
#error "define GLANCE_TEAM_ID to the team id that signs Glance"
#endif
#define GLANCE_BUNDLE_ID "dev.pedrohedro.glance"
#define GLANCE_SOCKET "Library/Application Support/glance-fork/approve.sock"
// Covers the Approve click plus the scan window; past this, fall back to the password.
#define GLANCE_TIMEOUT_SECONDS 60

static int peer_is_glance(int fd, uid_t expected_uid) {
    uid_t uid; gid_t gid;
    if (getpeereid(fd, &uid, &gid) != 0 || uid != expected_uid) return 0;

    // Audit token, not pid: a pid can be recycled between the check and the reply.
    audit_token_t token;
    socklen_t length = sizeof(token);
    if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &length) != 0 || length != sizeof(token)) return 0;

    int trusted = 0;
    CFDataRef tokenData = CFDataCreate(NULL, (const UInt8 *)&token, sizeof(token));
    const void *keys[] = { kSecGuestAttributeAudit };
    const void *values[] = { tokenData };
    CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    SecCodeRef code = NULL;
    SecRequirementRef requirement = NULL;
    CFStringRef text = CFSTR("identifier \"" GLANCE_BUNDLE_ID "\" and anchor apple generic and "
                             "certificate leaf[subject.OU] = \"" GLANCE_TEAM_ID "\"");
    if (SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code) == errSecSuccess
        && SecRequirementCreateWithString(text, kSecCSDefaultFlags, &requirement) == errSecSuccess
        && SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement) == errSecSuccess) {
        // Refuse a peer that other same-user processes are allowed to debug.
        CFDictionaryRef info = NULL;
        if (SecCodeCopySigningInformation((SecStaticCodeRef)code, kSecCSRequirementInformation | kSecCSDynamicInformation,
                                          &info) == errSecSuccess && info) {
            CFDictionaryRef entitlements = CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
            CFNumberRef flagsNumber = CFDictionaryGetValue(info, kSecCodeInfoFlags);
            uint32_t flags = 0;
            if (flagsNumber) CFNumberGetValue(flagsNumber, kCFNumberSInt32Type, &flags);
            int debuggable = entitlements
                && CFDictionaryGetValue(entitlements, CFSTR("com.apple.security.get-task-allow")) == kCFBooleanTrue;
            trusted = !debuggable && (flags & kSecCodeSignatureRuntime);
            CFRelease(info);
        }
    }
    if (requirement) CFRelease(requirement);
    if (code) CFRelease(code);
    CFRelease(attributes);
    CFRelease(tokenData);
    return trusted;
}

/// 1 = approved by Glance, 0 = anything else (denied, not running, untrusted peer, timeout).
static int glance_approve(const char *user, const char *reason) {
    struct passwd *entry = getpwnam(user);
    if (!entry) return 0;

    struct sockaddr_un address = { .sun_family = AF_UNIX };
    if (snprintf(address.sun_path, sizeof(address.sun_path), "%s/%s", entry->pw_dir, GLANCE_SOCKET)
        >= (int)sizeof(address.sun_path)) return 0;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    struct timeval timeout = { .tv_sec = GLANCE_TIMEOUT_SECONDS };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    int approved = 0;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0) {
        if (!peer_is_glance(fd, entry->pw_uid)) {
            syslog(LOG_AUTH | LOG_WARNING, "pam_glance: socket peer is not a trusted Glance build, ignoring");
        } else {
            char line[160];
            int length = snprintf(line, sizeof(line), "%s\n", reason);
            char reply[64] = { 0 };
            if (length > 0 && write(fd, line, strlen(line)) > 0 && read(fd, reply, sizeof(reply) - 1) >= 2) {
                approved = strncmp(reply, "OK", 2) == 0;
                if (!approved) syslog(LOG_AUTH | LOG_NOTICE, "pam_glance: %s", reply);
            }
        }
    }
    close(fd);
    return approved;
}

#ifdef PAM_GLANCE_SELFTEST
int main(int argc, char **argv) {
    struct passwd *me = getpwuid(getuid());
    int ok = me && glance_approve(me->pw_name, argc > 1 ? argv[1] : "pam_glance self-test");
    printf("%s\n", ok ? "approved" : "not approved");
    return ok ? 0 : 1;
}
#else
#include <security/pam_appl.h>
#include <security/pam_modules.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL, *service = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user) return PAM_AUTH_ERR;
    pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
    char reason[128];
    snprintf(reason, sizeof(reason), "%s: authenticate as %s", service ? service : "pam", user);
    return glance_approve(user, reason) ? PAM_SUCCESS : PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
#endif
