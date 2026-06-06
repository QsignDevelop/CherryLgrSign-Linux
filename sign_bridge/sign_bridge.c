#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <link.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

typedef long long (*sign_func)(char *, unsigned char *, int, int, unsigned char *);

static sign_func g_sign = NULL;
static unsigned long long g_module_base = 0;
static unsigned long long g_offset = 0;
static int g_server_started = 0;
static pthread_mutex_t g_init_lock = PTHREAD_MUTEX_INITIALIZER;

static int find_wrapper_callback(struct dl_phdr_info *info, size_t size, void *data) {
	(void)size;
	(void)data;
	if (info && info->dlpi_name && strstr(info->dlpi_name, "wrapper.node")) {
		g_module_base = info->dlpi_addr;
		return 1;
	}
	return 0;
}

static void refresh_sign_pointer(void) {
	const char *off_env = getenv("SIGN_OFFSET");
	if (off_env && *off_env) {
		unsigned long long parsed = 0;
		if (sscanf(off_env, "0x%llx", &parsed) == 1) {
			g_offset = parsed;
		} else if (sscanf(off_env, "%llu", &parsed) == 1) {
			g_offset = parsed;
		}
	}
	if (g_offset == 0) {
		g_offset = 0x557A6A0;
	}

	g_module_base = 0;
	dl_iterate_phdr(find_wrapper_callback, NULL);
	if (g_module_base == 0) {
		g_sign = NULL;
		return;
	}

	g_sign = (sign_func)(g_module_base + g_offset);
}

static void ensure_sign_ready(void) {
	pthread_mutex_lock(&g_init_lock);
	if (!g_sign) {
		refresh_sign_pointer();
	}
	pthread_mutex_unlock(&g_init_lock);
}

static int hex_nibble(char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static int decode_hex(const char *hex, unsigned char *out, int out_cap) {
	int len = 0;
	int hi = -1;
	for (const char *p = hex; *p; ++p) {
		int n = hex_nibble(*p);
		if (n < 0) continue;
		if (hi < 0) {
			hi = n;
		} else {
			if (len >= out_cap) return -1;
			out[len++] = (unsigned char)((hi << 4) | n);
			hi = -1;
		}
	}
	return len;
}

static void encode_hex(const unsigned char *in, int in_len, char *out, int out_cap) {
	static const char *digits = "0123456789ABCDEF";
	int pos = 0;
	for (int i = 0; i < in_len; ++i) {
		if (pos + 2 >= out_cap) break;
		out[pos++] = digits[(in[i] >> 4) & 0xF];
		out[pos++] = digits[in[i] & 0xF];
	}
	out[pos] = '\0';
}

static int do_sign_request(const char *cmd, int seq, const char *src_hex, char *err, int err_cap) {
	unsigned char src[65536];
	unsigned char output[0x300];
	char cmd_buf[1024];
	int src_len = 0;

	ensure_sign_ready();
	if (!g_sign) {
		snprintf(err, err_cap, "wrapper.node not loaded in QQ process yet");
		return -1;
	}

	strncpy(cmd_buf, cmd ? cmd : "", sizeof(cmd_buf) - 1);
	cmd_buf[sizeof(cmd_buf) - 1] = '\0';
	src_len = decode_hex(src_hex ? src_hex : "", src, (int)sizeof(src));
	if (src_len < 0) {
		snprintf(err, err_cap, "invalid hex src");
		return -1;
	}

	memset(output, 0, sizeof(output));
	if (g_sign(cmd_buf, src, src_len, seq, output) != 0) {
		snprintf(err, err_cap, "native sign function failed");
		return -1;
	}

	int token_len = output[0x0FF];
	int extra_len = output[0x1FF];
	int sign_len = output[0x2FF];
	if (token_len < 0) token_len = 0;
	if (extra_len < 0) extra_len = 0;
	if (sign_len < 0) sign_len = 0;
	if (token_len > 0xFF) token_len = 0xFF;
	if (extra_len > 0xFF) extra_len = 0xFF;
	if (sign_len > 0xFF) sign_len = 0xFF;

	char token_hex[1024];
	char extra_hex[1024];
	char sign_hex[1024];
	encode_hex(output, token_len, token_hex, sizeof(token_hex));
	encode_hex(output + 0x100, extra_len, extra_hex, sizeof(extra_hex));
	encode_hex(output + 0x200, sign_len, sign_hex, sizeof(sign_hex));

	snprintf(err, err_cap, "OK\t%s\t%s\t%s", token_hex, extra_hex, sign_hex);
	return 0;
}

static void handle_client(int client_fd) {
	char req[131072];
	ssize_t n = read(client_fd, req, sizeof(req) - 1);
	if (n <= 0) {
		close(client_fd);
		return;
	}
	req[n] = '\0';

	char *line = req;
	char *nl = strchr(line, '\n');
	if (nl) *nl = '\0';

	char *cmd = line;
	char *seq_str = strchr(line, '\t');
	if (!seq_str) {
		const char *resp = "ERR\tbad request format\n";
		write(client_fd, resp, strlen(resp));
		close(client_fd);
		return;
	}
	*seq_str++ = '\0';
	char *src_hex = strchr(seq_str, '\t');
	if (!src_hex) {
		const char *resp = "ERR\tbad request format\n";
		write(client_fd, resp, strlen(resp));
		close(client_fd);
		return;
	}
	*src_hex++ = '\0';
	int seq = atoi(seq_str);

	char result[4096];
	if (do_sign_request(cmd, seq, src_hex, result, sizeof(result)) != 0) {
		char resp[4096];
		snprintf(resp, sizeof(resp), "ERR\t%s\n", result);
		write(client_fd, resp, strlen(resp));
		close(client_fd);
		return;
	}

	char resp[4096];
	snprintf(resp, sizeof(resp), "%s\n", result);
	write(client_fd, resp, strlen(resp));
	close(client_fd);
}

static void *bridge_server_thread(void *arg) {
	(void)arg;
	const char *sock_path = getenv("SIGN_BRIDGE_SOCK");
	if (!sock_path || !*sock_path) {
		sock_path = "/tmp/nekogel_sign_bridge.sock";
	}

	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) return NULL;

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
	unlink(sock_path);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return NULL;
	}
	if (listen(fd, 16) < 0) {
		close(fd);
		return NULL;
	}
	chmod(sock_path, 0666);

	for (;;) {
		int client = accept(fd, NULL, NULL);
		if (client < 0) {
			if (errno == EINTR) continue;
			break;
		}
		handle_client(client);
	}

	close(fd);
	return NULL;
}

static void start_bridge_server_once(void) {
	if (g_server_started) return;
	g_server_started = 1;
	pthread_t tid;
	pthread_create(&tid, NULL, bridge_server_thread, NULL);
	pthread_detach(tid);
}

static void *poll_wrapper_thread(void *arg) {
	(void)arg;
	for (int i = 0; i < 600; ++i) {
		ensure_sign_ready();
		if (g_sign) {
			start_bridge_server_once();
			return NULL;
		}
		usleep(500000);
	}
	return NULL;
}

__attribute__((constructor)) static void sign_bridge_init(void) {
	pthread_t tid;
	pthread_create(&tid, NULL, poll_wrapper_thread, NULL);
	pthread_detach(tid);
}

void *dlopen(const char *filename, int flag) {
	static void *(*real_dlopen)(const char *, int) = NULL;
	if (!real_dlopen) {
		real_dlopen = dlsym(RTLD_NEXT, "dlopen");
	}
	void *handle = real_dlopen(filename, flag);
	if (filename && strstr(filename, "wrapper.node")) {
		refresh_sign_pointer();
		start_bridge_server_once();
	}
	return handle;
}
