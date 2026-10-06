// SPDX-License-Identifier: MIT
/* Preserve the OEM control protocol, sharing only its reply sockets with
 * native hostapd. Loaded solely by the confined, native WPS launch path. */
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

struct wpa_ctrl;
extern struct wpa_ctrl *wpa_ctrl_open2(const char *, const char *);
extern int wpa_ctrl_get_fd(struct wpa_ctrl *);
extern void wpa_ctrl_close(struct wpa_ctrl *);

__attribute__((constructor)) static void restrict_to_pairing_daemon(void)
{
    /* OEM board-identity helpers are separate executables without libwpa_ctrl.
     * The compatibility preload must not propagate to those children. */
    unsetenv("LD_PRELOAD");
}

struct wpa_ctrl *wpa_ctrl_open(const char *path)
{
    static const char directory[] = "/var/run/hostapd/deco-wps-control";
    static const char prefix[] = "/var/run/hostapd/deco-wps-control/wpa_ctrl_";
    const char *configured = getenv("ADAPTER_WPA_CTRL_DIR");
    struct sockaddr_un address = {0};
    socklen_t length = sizeof(address);
    struct wpa_ctrl *control;
    if (!configured || strcmp(configured, directory)) {
        errno = EINVAL;
        return NULL;
    }
    control = wpa_ctrl_open2(path, directory);
    if (!control)
        return NULL;
    if (getsockname(wpa_ctrl_get_fd(control), (struct sockaddr *)&address, &length) ||
        address.sun_family != AF_UNIX || length > sizeof(address) ||
        !memchr(address.sun_path, '\0', sizeof(address.sun_path)) ||
        strncmp(address.sun_path, prefix, sizeof(prefix) - 1) ||
        chmod(address.sun_path, 0660)) {
        wpa_ctrl_close(control);
        return NULL;
    }
    return control;
}
