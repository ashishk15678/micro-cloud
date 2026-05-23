// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ashish Kumar <15678ashishk@gmail.com>

#pragma once

#define IAASD_PID_PATH "/run/iaasd/iaasd.pid"
#define IAASD_SOCKET_PATH "/run/iaasd/iaasd.sock"
#define IAASD_LOG_PATH "/var/log/iaasd/iaasd.log"
#define IAASD_STATE_PATH "/var/lib/iaasd/iaasd.state"
#define IAASD_INSTANCE_DIR "/var/lib/iaasd/instances"
#define IAASD_SOCKET_BACKLOG 8
#define IAASD_MAX_CMD_LEN 512
#define IAASD_DEFAULT_IDENT "iaasd"

#define IAASD_PING_CMD "PING\n"
#define IAASD_STATUS_CMD "STATUS\n"
#define IAASD_STOP_CMD "STOP"
#define IAASD_AUTH_CMD "AUTH"
#define IAASD_GET_QUOTA_CMD "GET_QUOTA"
#define IAASD_SET_QUOTA_CMD "SET_QUOTA"
#define IAASD_CREATE_INSTANCE_CMD "CREATE_INSTANCE"
#define IAASD_START_INSTANCE_CMD "START_INSTANCE"
#define IAASD_STOP_INSTANCE_CMD "STOP_INSTANCE"
#define IAASD_STATUS_INSTANCE_CMD "STATUS_INSTANCE"

#define IAASD_PONG_REPLY "PONG"
#define IAASD_OK_REPLY "OK"
#define IAASD_RUNNING_REPLY "RUNNING"
#define IAASD_ERROR_REPLY "ERR"
