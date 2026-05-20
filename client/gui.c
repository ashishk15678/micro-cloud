// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Aman Deep (amdeep.dev@gmail.com)
// SPDX-FileCopyrightText: 2026 Ashish Kumar <15678ashishk@gmail.com>

#include "raylib.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/stat.h>

#include "daemon/ipc.h"

typedef enum {
    DAEMON_STATUS_UNKNOWN = 0,
    DAEMON_STATUS_RUNNING,
    DAEMON_STATUS_STOPPED
} DaemonStatus;

typedef struct {
    bool logged_in;
    char token[128];
    int64_t token_expires;
} AuthState;

static Font g_ui_font;
static bool g_ui_font_custom = false;

/** \brief Initialize the UI font from environment or system paths. */
static void init_ui_font(void) {
    g_ui_font = GetFontDefault();
    g_ui_font_custom = false;

    const char *env_font = getenv("IAASD_FONT_PATH");
    const char *candidates[] = {
        env_font,
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf",
        NULL
    };

    for (int i = 0; candidates[i]; i++) {
        if (!candidates[i] || candidates[i][0] == '\0') {
            continue;
        }
        if (access(candidates[i], R_OK) != 0) {
            continue;
        }
        Font loaded = LoadFontEx(candidates[i], 22, NULL, 0);
        if (loaded.texture.id != 0) {
            g_ui_font = loaded;
            g_ui_font_custom = true;
            break;
        }
    }
}

/** \brief Release any custom UI font resources. */
static void close_ui_font(void) {
    if (g_ui_font_custom) {
        UnloadFont(g_ui_font);
        g_ui_font_custom = false;
    }
}

/** \brief Draw text using the configured UI font. */
static void draw_text(const char *text, int x, int y, int size, Color color) {
    DrawTextEx(g_ui_font, text, (Vector2){ (float)x, (float)y }, (float)size, 0.0f, color);
}

/** \brief Measure text width using the configured UI font. */
static int measure_text(const char *text, int size) {
    Vector2 m = MeasureTextEx(g_ui_font, text, (float)size, 0.0f);
    return (int)m.x;
}

/** \brief Draw a clickable button and return true when activated. */
static bool draw_button(Rectangle bounds, const char *text, Color base, Color hover) {
    Vector2 mouse = GetMousePosition();
    bool hovering = CheckCollisionPointRec(mouse, bounds);

    DrawRectangleRec(bounds, hovering ? hover : base);
    DrawRectangleLinesEx(bounds, 2, BLACK);

    int font_size = 20;
    int text_width = measure_text(text, font_size);
    draw_text(text,
              (int)(bounds.x + (bounds.width - text_width) / 2),
              (int)(bounds.y + (bounds.height - font_size) / 2),
              font_size,
              RAYWHITE);

    return hovering && IsMouseButtonReleased(MOUSE_BUTTON_LEFT);
}

/** \brief Draw a text input box and return true when it gains focus. */
static bool draw_text_input(Rectangle bounds, const char *label, char *buffer, size_t buffer_len, bool active, bool secret) {
    (void)buffer_len;
    draw_text(label, (int)bounds.x, (int)bounds.y - 22, 16, (Color){ 160, 170, 190, 255 });

    DrawRectangleRec(bounds, active ? (Color){ 40, 50, 70, 255 } : (Color){ 30, 38, 52, 255 });
    DrawRectangleLinesEx(bounds, 2, active ? (Color){ 90, 150, 230, 255 } : (Color){ 60, 70, 90, 255 });

    char display[128];
    if (secret) {
        size_t len = strlen(buffer);
        size_t count = len < sizeof(display) - 1 ? len : sizeof(display) - 1;
        for (size_t i = 0; i < count; i++) {
            display[i] = '*';
        }
        display[count] = '\0';
    } else {
        snprintf(display, sizeof(display), "%s", buffer);
    }

    draw_text(display, (int)bounds.x + 8, (int)bounds.y + 10, 18, RAYWHITE);

    Vector2 mouse = GetMousePosition();
    return CheckCollisionPointRec(mouse, bounds) && IsMouseButtonPressed(MOUSE_BUTTON_LEFT);
}

/** \brief Handle keyboard input for a focused text field. */
static void handle_text_input(char *buffer, size_t buffer_len, bool numeric_only) {
    int key = GetCharPressed();
    while (key > 0) {
        if (key >= 32 && key <= 126) {
            char c = (char)key;
            if (!numeric_only || (c >= '0' && c <= '9')) {
                size_t len = strlen(buffer);
                if (len + 1 < buffer_len) {
                    buffer[len] = c;
                    buffer[len + 1] = '\0';
                }
            }
        }
        key = GetCharPressed();
    }

    if (IsKeyPressed(KEY_BACKSPACE)) {
        size_t len = strlen(buffer);
        if (len > 0) {
            buffer[len - 1] = '\0';
        }
    }
}

/** \brief Connect to the daemon IPC socket. */
static int connect_daemon(int *err_out) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        if (err_out) {
            *err_out = errno;
        }
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, IAASD_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (err_out) {
            *err_out = errno;
        }
        close(fd);
        return -1;
    }

    return fd;
}

/** \brief Send an IPC command and return the raw reply. */
static bool send_command(const char *cmd, char *reply, size_t reply_size, char *detail, size_t detail_size) {
    if (detail && detail_size > 0) {
        detail[0] = '\0';
    }

    int err = 0;
    int fd = connect_daemon(&err);
    if (fd < 0) {
        if (err == ENOENT || err == ECONNREFUSED) {
            if (detail && detail_size > 0) {
                snprintf(detail, detail_size, "Daemon is not running.");
            }
        } else if (detail && detail_size > 0) {
            snprintf(detail, detail_size, "Socket error: %s", strerror(err));
        }
        return false;
    }

    if (send(fd, cmd, strlen(cmd), 0) < 0) {
        if (detail && detail_size > 0) {
            snprintf(detail, detail_size, "Send failed: %s", strerror(errno));
        }
        close(fd);
        return false;
    }

    if (reply && reply_size > 0) {
        ssize_t bytes = recv(fd, reply, reply_size - 1, 0);
        if (bytes < 0) {
            if (detail && detail_size > 0) {
                snprintf(detail, detail_size, "Reply read failed: %s", strerror(errno));
            }
            close(fd);
            return false;
        }
        if (bytes == 0) {
            if (detail && detail_size > 0) {
                snprintf(detail, detail_size, "No reply from daemon.");
            }
            close(fd);
            return false;
        }
        reply[bytes] = '\0';
    }

    close(fd);

    if (reply && reply_size > 0 && strncmp(reply, IAASD_ERROR_REPLY, strlen(IAASD_ERROR_REPLY)) == 0) {
        if (detail && detail_size > 0) {
            snprintf(detail, detail_size, "%s", reply);
        }
        return false;
    }

    return true;
}

/** \brief Check daemon availability via PING. */
static DaemonStatus check_daemon(char *detail, size_t detail_size) {
    if (detail && detail_size > 0) {
        detail[0] = '\0';
    }

    char reply[64];
    if (!send_command(IAASD_PING_CMD, reply, sizeof(reply), detail, detail_size)) {
        return DAEMON_STATUS_STOPPED;
    }

    if (strncmp(reply, IAASD_PONG_REPLY, strlen(IAASD_PONG_REPLY)) == 0) {
        return DAEMON_STATUS_RUNNING;
    }

    if (detail && detail_size > 0) {
        snprintf(detail, detail_size, "Unexpected reply: %s", reply);
    }
    return DAEMON_STATUS_UNKNOWN;
}

/** \brief Authenticate an admin user and store the session token. */
static bool authenticate_admin(const char *user, const char *pass, AuthState *auth,
                               char *detail, size_t detail_size) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "%s %s %s\n", IAASD_AUTH_CMD, user, pass);

    char reply[256];
    if (!send_command(cmd, reply, sizeof(reply), detail, detail_size)) {
        return false;
    }

    char token[128];
    long long expires = 0;
    int parsed = sscanf(reply, "TOKEN %127s %lld", token, &expires);
    if (parsed < 1) {
        if (detail && detail_size > 0) {
            snprintf(detail, detail_size, "Invalid auth reply: %s", reply);
        }
        return false;
    }

    snprintf(auth->token, sizeof(auth->token), "%s", token);
    auth->token_expires = (int64_t)expires;
    auth->logged_in = true;
    return true;
}

/** \brief Request the current quota values from the daemon. */
static bool request_quota(const AuthState *auth, uint64_t *ram_mib, uint64_t *disk_gib, uint64_t *net_mbps,
                          char *detail, size_t detail_size) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "%s %s\n", IAASD_GET_QUOTA_CMD, auth->token);

    char reply[256];
    if (!send_command(cmd, reply, sizeof(reply), detail, detail_size)) {
        return false;
    }

    char token_a[64], token_b[64], token_c[64];
    if (sscanf(reply, "QUOTA %63s %63s %63s", token_a, token_b, token_c) != 3) {
        if (detail && detail_size > 0) {
            snprintf(detail, detail_size, "Invalid quota reply: %s", reply);
        }
        return false;
    }

    uint64_t r = 0, d = 0, n = 0;
    sscanf(token_a, "RAM=%" SCNu64, &r);
    sscanf(token_b, "DISK=%" SCNu64, &d);
    sscanf(token_c, "NET=%" SCNu64, &n);

    *ram_mib = r;
    *disk_gib = d;
    *net_mbps = n;
    return true;
}

/** \brief Apply new quota values on the daemon. */
static bool apply_quota(const AuthState *auth, uint64_t ram_mib, uint64_t disk_gib, uint64_t net_mbps,
                        char *detail, size_t detail_size) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "%s %s RAM=%" PRIu64 " DISK=%" PRIu64 " NET=%" PRIu64 "\n",
             IAASD_SET_QUOTA_CMD, auth->token, ram_mib, disk_gib, net_mbps);

    char reply[128];
    if (!send_command(cmd, reply, sizeof(reply), detail, detail_size)) {
        return false;
    }

    return true;
}

/** \brief Request the daemon to stop. */
static bool stop_daemon(const AuthState *auth, char *detail, size_t detail_size) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "%s %s\n", IAASD_STOP_CMD, auth->token);

    char reply[64];
    if (!send_command(cmd, reply, sizeof(reply), detail, detail_size)) {
        return false;
    }

    return true;
}

/** \brief Start the daemon process using IAASD_DAEMON_PATH. */
static bool start_daemon(char *detail, size_t detail_size) {
    if (detail && detail_size > 0) {
        detail[0] = '\0';
    }

    const char *daemon_path = getenv("IAASD_DAEMON_PATH");
    if (!daemon_path || daemon_path[0] == '\0') {
        daemon_path = "daemon";
    }

    pid_t pid = fork();
    if (pid < 0) {
        if (detail && detail_size > 0) {
            snprintf(detail, detail_size, "fork() failed: %s", strerror(errno));
        }
        return false;
    }

    if (pid == 0) {
        execlp(daemon_path, daemon_path, NULL);
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        if (detail && detail_size > 0) {
            snprintf(detail, detail_size, "waitpid() failed: %s", strerror(errno));
        }
        return false;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
        if (detail && detail_size > 0) {
            snprintf(detail, detail_size, "Could not exec '%s' (not in PATH).", daemon_path);
        }
        return false;
    }

    return true;
}

/** \brief Read the last part of the daemon log for display. */
static void read_log_tail(char *out, size_t out_len, char *detail, size_t detail_len) {
    if (detail && detail_len > 0) {
        detail[0] = '\0';
    }

    FILE *fp = fopen(IAASD_LOG_PATH, "r");
    if (!fp) {
        if (detail && detail_len > 0) {
            snprintf(detail, detail_len, "Log open failed: %s", strerror(errno));
        }
        snprintf(out, out_len, "(log unavailable)\n");
        return;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        snprintf(out, out_len, "(log unavailable)\n");
        return;
    }

    long size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        snprintf(out, out_len, "(log unavailable)\n");
        return;
    }

    long start = size - (long)out_len + 1;
    if (start < 0) {
        start = 0;
    }

    if (fseek(fp, start, SEEK_SET) != 0) {
        fclose(fp);
        snprintf(out, out_len, "(log unavailable)\n");
        return;
    }

    if (start > 0) {
        int c;
        while ((c = fgetc(fp)) != '\n' && c != EOF) {
        }
    }

    size_t read_bytes = fread(out, 1, out_len - 1, fp);
    out[read_bytes] = '\0';
    fclose(fp);
}

/** \brief Collect pointers to newline-delimited log lines. */
static int collect_lines(const char *text, const char **lines, int max_lines) {
    int count = 0;
    if (!text || text[0] == '\0') {
        return 0;
    }
    lines[count++] = text;
    for (const char *p = text; *p != '\0' && count < max_lines; p++) {
        if (*p == '\n') {
            if (*(p + 1) != '\0') {
                lines[count++] = p + 1;
            }
        }
    }
    return count;
}

/** \brief Parse an unsigned 64-bit integer from a string. */
static bool parse_u64(const char *s, uint64_t *out) {
    if (!s || *s == '\0') {
        return false;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long val = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') {
        return false;
    }
    *out = (uint64_t)val;
    return true;
}

/** \brief GUI entry point for daemon control. */
int main(void) {
    const int screen_width = 1100;
    const int screen_height = 700;

    signal(SIGPIPE, SIG_IGN);

    SetConfigFlags(FLAG_WINDOW_RESIZABLE);
    InitWindow(screen_width, screen_height, "NimbusD Control Panel");
    init_ui_font();
    SetTargetFPS(60);

    DaemonStatus status = DAEMON_STATUS_UNKNOWN;
    char status_detail[256] = "";
    char action_detail[256] = "";

    AuthState auth = {0};
    char username[64] = "admin";
    char password[64] = "admin";
    char ram_input[32] = "8192";
    char disk_input[32] = "200";
    char net_input[32] = "1000";

    int active_field = 0;

    char log_text[8192] = "";
    char log_detail[256] = "";
    float log_scroll = 0.0f;

    double last_poll = -1.0;
    double last_log_poll = -1.0;

    while (!WindowShouldClose()) {
        double now = GetTime();
        if (last_poll < 0 || (now - last_poll) >= 1.0) {
            status = check_daemon(status_detail, sizeof(status_detail));
            last_poll = now;
        }

        if (last_log_poll < 0 || (now - last_log_poll) >= 1.0) {
            read_log_tail(log_text, sizeof(log_text), log_detail, sizeof(log_detail));
            last_log_poll = now;
        }

        if (active_field == 1) {
            handle_text_input(username, sizeof(username), false);
        } else if (active_field == 2) {
            handle_text_input(password, sizeof(password), false);
        } else if (active_field == 3) {
            handle_text_input(ram_input, sizeof(ram_input), true);
        } else if (active_field == 4) {
            handle_text_input(disk_input, sizeof(disk_input), true);
        } else if (active_field == 5) {
            handle_text_input(net_input, sizeof(net_input), true);
        }

        BeginDrawing();
        ClearBackground((Color){ 18, 24, 38, 255 });

        int w = GetScreenWidth();
        int h = GetScreenHeight();
        DrawRectangleGradientV(0, 0, w, h, (Color){ 24, 32, 48, 255 }, (Color){ 10, 14, 22, 255 });

        draw_text("NimbusD Control Panel", 40, 28, 32, RAYWHITE);
        draw_text("Micro-cloud daemon status & controls", 40, 66, 16, (Color){ 180, 190, 210, 255 });

        const char *status_text = "Unknown";
        Color status_color = (Color){ 200, 200, 200, 255 };

        if (status == DAEMON_STATUS_RUNNING) {
            status_text = "Running";
            status_color = (Color){ 80, 200, 120, 255 };
        } else if (status == DAEMON_STATUS_STOPPED) {
            status_text = "Stopped";
            status_color = (Color){ 240, 90, 90, 255 };
        }

        draw_text("Daemon:", 40, 110, 20, (Color){ 160, 170, 190, 255 });
        draw_text(status_text, 140, 110, 20, status_color);

        draw_text("Socket:", 40, 138, 18, (Color){ 160, 170, 190, 255 });
        draw_text(IAASD_SOCKET_PATH, 110, 138, 18, (Color){ 160, 170, 190, 255 });

        Rectangle start_btn = { 40, 175, 180, 44 };
        Rectangle stop_btn = { 235, 175, 180, 44 };
        Rectangle refresh_btn = { 430, 175, 140, 44 };

        if (draw_button(start_btn, "Start Daemon", (Color){ 42, 106, 190, 255 }, (Color){ 58, 132, 220, 255 })) {
            if (start_daemon(action_detail, sizeof(action_detail))) {
                snprintf(action_detail, sizeof(action_detail), "Start requested.");
            }
            last_poll = -1.0;
        }

        if (draw_button(stop_btn, "Stop Daemon", (Color){ 160, 60, 60, 255 }, (Color){ 190, 80, 80, 255 })) {
            if (!auth.logged_in) {
                snprintf(action_detail, sizeof(action_detail), "Login required to stop daemon.");
            } else if (stop_daemon(&auth, action_detail, sizeof(action_detail))) {
                snprintf(action_detail, sizeof(action_detail), "Stop requested.");
            }
            last_poll = -1.0;
        }

        if (draw_button(refresh_btn, "Refresh", (Color){ 70, 70, 90, 255 }, (Color){ 90, 90, 120, 255 })) {
            status = check_daemon(status_detail, sizeof(status_detail));
            last_poll = now;
        }

        Rectangle user_input = { 40, 250, 220, 40 };
        Rectangle pass_input = { 280, 250, 220, 40 };

        if (draw_text_input(user_input, "Username", username, sizeof(username), active_field == 1, false)) {
            active_field = 1;
        }
        if (draw_text_input(pass_input, "Password", password, sizeof(password), active_field == 2, true)) {
            active_field = 2;
        }

        Rectangle login_btn = { 520, 250, 140, 40 };
        if (draw_button(login_btn, auth.logged_in ? "Re-Auth" : "Login", (Color){ 80, 120, 80, 255 }, (Color){ 110, 150, 110, 255 })) {
            if (authenticate_admin(username, password, &auth, action_detail, sizeof(action_detail))) {
                snprintf(action_detail, sizeof(action_detail), "Authenticated as %s", username);
            }
        }

        draw_text("Resource Quotas", 40, 320, 20, (Color){ 180, 190, 210, 255 });

        Rectangle ram_box = { 40, 360, 160, 40 };
        Rectangle disk_box = { 220, 360, 160, 40 };
        Rectangle net_box = { 400, 360, 160, 40 };

        if (draw_text_input(ram_box, "RAM MiB", ram_input, sizeof(ram_input), active_field == 3, false)) {
            active_field = 3;
        }
        if (draw_text_input(disk_box, "Disk GiB", disk_input, sizeof(disk_input), active_field == 4, false)) {
            active_field = 4;
        }
        if (draw_text_input(net_box, "Net Mbps", net_input, sizeof(net_input), active_field == 5, false)) {
            active_field = 5;
        }

        Rectangle get_btn = { 580, 360, 140, 40 };
        Rectangle set_btn = { 740, 360, 140, 40 };

        if (draw_button(get_btn, "Get", (Color){ 80, 90, 120, 255 }, (Color){ 100, 110, 140, 255 })) {
            if (!auth.logged_in) {
                snprintf(action_detail, sizeof(action_detail), "Login required to query quotas.");
            } else {
                uint64_t r = 0, d = 0, n = 0;
                if (request_quota(&auth, &r, &d, &n, action_detail, sizeof(action_detail))) {
                    snprintf(ram_input, sizeof(ram_input), "%" PRIu64, r);
                    snprintf(disk_input, sizeof(disk_input), "%" PRIu64, d);
                    snprintf(net_input, sizeof(net_input), "%" PRIu64, n);
                    snprintf(action_detail, sizeof(action_detail), "Quota loaded.");
                }
            }
        }

        if (draw_button(set_btn, "Set", (Color){ 80, 120, 140, 255 }, (Color){ 100, 150, 170, 255 })) {
            if (!auth.logged_in) {
                snprintf(action_detail, sizeof(action_detail), "Login required to apply quotas.");
            } else {
                uint64_t r = 0, d = 0, n = 0;
                if (!parse_u64(ram_input, &r) || !parse_u64(disk_input, &d) || !parse_u64(net_input, &n)) {
                    snprintf(action_detail, sizeof(action_detail), "Quota values must be numeric.");
                } else if (apply_quota(&auth, r, d, n, action_detail, sizeof(action_detail))) {
                    snprintf(action_detail, sizeof(action_detail), "Quota updated.");
                }
            }
        }

        draw_text("Status detail:", 40, 420, 18, (Color){ 160, 170, 190, 255 });
        draw_text(status_detail[0] ? status_detail : "OK", 40, 444, 18, (Color){ 200, 210, 220, 255 });

        draw_text("Last action:", 40, 468, 18, (Color){ 160, 170, 190, 255 });
        draw_text(action_detail[0] ? action_detail : "-", 40, 492, 18, (Color){ 200, 210, 220, 255 });

        int log_y = 520;
        int log_height = h - log_y - 30;
        if (log_height < 120) {
            log_height = 120;
        }
        Rectangle log_panel = { 40, (float)log_y, (float)(w - 80), (float)log_height };

        draw_text("Daemon Output", 40, log_y - 24, 18, (Color){ 180, 190, 210, 255 });
        DrawRectangleRec(log_panel, (Color){ 20, 26, 36, 255 });
        DrawRectangleLinesEx(log_panel, 1, (Color){ 60, 70, 90, 255 });

        const char *lines[512];
        int line_count = collect_lines(log_text, lines, 512);
        float line_height = 16.0f;
        float total_height = line_count * line_height;
        float max_scroll = total_height > log_panel.height ? total_height - log_panel.height + 6.0f : 0.0f;

        Vector2 mouse = GetMousePosition();
        if (CheckCollisionPointRec(mouse, log_panel)) {
            float wheel = GetMouseWheelMove();
            if (wheel != 0.0f) {
                log_scroll -= wheel * line_height * 3.0f;
                if (log_scroll < 0.0f) log_scroll = 0.0f;
                if (log_scroll > max_scroll) log_scroll = max_scroll;
            }
        }

        BeginScissorMode((int)log_panel.x, (int)log_panel.y, (int)log_panel.width, (int)log_panel.height);
        float y = log_panel.y + 6.0f - log_scroll;
        for (int i = 0; i < line_count; i++) {
            draw_text(lines[i], (int)log_panel.x + 6, (int)(y + i * line_height), 14, (Color){ 200, 210, 220, 255 });
        }
        EndScissorMode();

        if (log_detail[0]) {
            draw_text(log_detail, (int)log_panel.x, (int)(log_panel.y + log_panel.height + 6), 14, (Color){ 200, 120, 120, 255 });
        }

        EndDrawing();
    }

    close_ui_font();
    CloseWindow();
    return 0;
}