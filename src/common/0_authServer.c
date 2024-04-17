#include <arpa/inet.h>
#include <evutil.h>
#include <player.h>
#include <playerdto.h>

u64 connectedusers = 0;

u64 getConnectedUsers() { return connectedUsers; }
struct IPv4_PORT {
        char ip[INET_ADDRSTRLEN];
        int port;
};
struct IPv4_PORT getIPStr(struct bufferevent *bev)
{
        struct IPv4_PORT ipPort;

        var fd = bufferevent_getfd(bev);
        struct sockaddr_in addr;
        socklen_t len = sizeof(struct sockaddr_in);
        getpeername(fd, &addr, &len);
        inet_ntop(AF_INET, &(addr.sin_addr), ipPort.ip, INET_ADDRSTRLEN);
        ipPort.port = ntohs(addr.sin_port);

        return ipPort;
}
#define disconnectClient(X)                                                                                                                          \
        {                                                                                                                                            \
                var ipPort = getIPStr(X);                                                                                                            \
                Lw("[%s][%d] Disconnecting client", ipPort.ip, ipPort.port);                                                                         \
                bufferevent_free(X);                                                                                                                 \
                connectedUsers--;                                                                                                                    \
        }
var FPS_TARGET = 1;
void CB_2_userAuthDataLoop(evutil_socket_t fd, short what, void *arg)
{
        struct {
                struct bufferevent *bev;
                struct timespec nextTick;
        } *data = arg;

        var currfd = fd;
        if (currfd == -1) {
                Lw("Client disconnected");
                return;
        }

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        struct timespec diff;
        diff.tv_sec = data->nextTick.tv_sec - now.tv_sec;
        diff.tv_nsec = data->nextTick.tv_nsec - now.tv_nsec;
        L("[%lld %ld] %lld %ld\n", (long long)data->nextTick.tv_sec, data->nextTick.tv_nsec, (long long)now.tv_sec, now.tv_nsec);

        struct playerInfoDTO *playersInfo;
        var len = db_playerInfo_all(&playersInfo);
        struct allposDTO allposDTO;
        allposDTO.authToken = rand();
        allposDTO.nPlayers = len;
        var ret = bufferevent_write(data->bev, &allposDTO.authToken, sizeof(allposDTO.authToken));
        if (ret == -1) {
                Le("bufferevent_write");
                goto errorExit;
        }
        ret = bufferevent_write(data->bev, &allposDTO.nPlayers, sizeof(allposDTO.nPlayers));
        ret = bufferevent_write(data->bev, playersInfo, len * sizeof(struct playerInfoDTO));
        if (ret == -1) {
                Le("bufferevent_write");
                goto errorExit;
        }
#ifdef DEBUG
        for (size_t i = 0; i < len; i++) {
                var player = playersInfo + i;
                Ld("Player %d: lat=%f, lon=%f, LookAt(%f, %f, %f)", i, player->lat, player->lon, player->lookAtVector.X, player->lookAtVector.Y,
                   player->lookAtVector.Z);
        }
#endif

        return;
errorExit:
        disconnectClient(data->bev);
        free(data);
}
void authEvCB(struct bufferevent *bev, short events, void *arg);
void CB_1_authRead(struct bufferevent *bev, void *arg)
{
        var ipPort = getIPStr(bev);

        Lw("[%s][%d] Auth ", ipPort.ip, ipPort.port);
        struct loginDTO loginDTO;
        var bytesRead = bufferevent_read(bev, &loginDTO, sizeof(struct loginDTO));
        if (bytesRead == 0) {
                Le("Very weird, bytesRead == 0");
                goto errorExit;
        }
        L("Received: %d\n", (int)bytesRead);
        L("[%s][%d] Username: %s, Password: %s\n", ipPort.ip, ipPort.port, loginDTO.username, loginDTO.password);

        var userId = db_playerId(loginDTO.username, loginDTO.password);
        if (userId == 0) {
                Le("[%s][%d] User not found\n", ipPort.ip, ipPort.port);
                struct loginDTO loginDTO = {
                    .authToken = 0,
                    .username = "",
                    .password = "",
                };
                bufferevent_write(bev, &loginDTO, sizeof(loginDTO));
                goto errorExit;
        }

        var tkn = db_playerTokenAdd(userId);
        if (tkn == 0) {
                Lw("[%s][%d] Error adding token\n", ipPort.ip, ipPort.port);
                bufferevent_write(bev, &kDefaultLoginDTO, sizeof(kDefaultLoginDTO));
                goto errorExit;
        }

        Lw("[%s][%d] User logged in\n", ipPort.ip, ipPort.port);
        if (bufferevent_write(bev, &(struct loginDTO){.authToken = tkn}, sizeof(struct loginDTO)) == -1) {
                Le("[%s][%d] bufferevent_write", ipPort.ip, ipPort.port);
                goto errorExit;
        }

        // Make persistent event
        var FPS = atoi(getenv("FPS") ?: "0") ?: 1;
        var e = 1.0 / FPS;
        struct timeval fps = {.tv_sec = 0, .tv_usec = e * 1000000};
        struct {
                struct bufferevent *bev;
                struct timespec lastTick;
        } *data = malloc(sizeof(*data));
        data->bev = bev;
        struct timespec ts;
        var tc = clock_gettime(CLOCK_MONOTONIC, &ts);
        ts.tv_sec += fps.tv_sec;
        ts.tv_nsec += fps.tv_usec;
        L("[%s][%d] %lld %ld\n", ipPort.ip, ipPort.port, (long long)ts.tv_sec, ts.tv_nsec);

        data->lastTick = ts;
        var ev = event_new(bufferevent_get_base(bev), bufferevent_getfd(bev), EV_TIMEOUT | EV_PERSIST, CB_2_userAuthDataLoop, data);
        if (ev == NULL) {
                Lf("[%s][%d] event_new", ipPort.ip, ipPort.port);
                free(data);
                goto errorExit;
        }
        event_add(ev, &fps);

        bufferevent_setcb(bev, NULL, NULL, authEvCB, ev);

        return;
errorExit:
        disconnectClient(bev);
}

void authEvCB(struct bufferevent *bev, short events, void *arg)
{
        var readOrWrite = events & (BEV_EVENT_READING | BEV_EVENT_WRITING);
        if (readOrWrite) {
                var ipPort = getIPStr(bev);
                Lw("[%s][%d] Error reading/writing", ipPort.ip, ipPort.port);
                disconnectClient(bev);
        }

        var nextErrors = events >> 4;
        nextErrors <<= 4;
        switch (nextErrors) {
        case BEV_EVENT_EOF: {
                var ipPort = getIPStr(bev);
                Lw("[%s][%d] EOF reached", ipPort.ip, ipPort.port);
                if (arg) {
                        event_free(arg);
                }
        } break;
        case BEV_EVENT_ERROR: {
                var ipPort = getIPStr(bev);
                Lf("[%s][%d] BEV_EVENT_ERROR", ipPort.ip, ipPort.port);
                disconnectClient(bev);
                if (arg) {
                        event_free(arg);
                }
        } break;
        case BEV_EVENT_TIMEOUT: {
                var ipPort = getIPStr(bev);
                Le("[%s][%d] Timeout", ipPort.ip, ipPort.port);
                disconnectClient(bev);
                if (arg) {
                        event_free(arg);
                }
        } break;
        case BEV_EVENT_CONNECTED: {
                var ipPort = getIPStr(bev);
                L("[%s][%d]  Connected", ipPort.ip, ipPort.port);
        } break;
        default:
                L("Unknown event: %d", events);
                disconnectClient(bev);
                if (arg) {
                        event_free(arg);
                }
                break;
        }
}

void CB_0_authConnected(struct evconnlistener *evcon, evutil_socket_t evutil, struct sockaddr *sock, int socklen, void *baseptr)
{
        struct event_base *base = baseptr;
        // L("Main loop called with fd: %d, what: %d, arg: %p", fd, what, arg);
        __clean char *ipStr = malloc(INET_ADDRSTRLEN);
        assert(ipStr);
        struct sockaddr_in *addr = (struct sockaddr_in *)sock;
        inet_ntop(AF_INET, &(addr->sin_addr), ipStr, INET_ADDRSTRLEN);
        Lw("Accepted connection from %s:%d", ipStr, ntohs(addr->sin_port));

        connectedUsers++;

        struct bufferevent *bev = bufferevent_socket_new(base, evutil, BEV_OPT_CLOSE_ON_FREE);
        assert(bev);
        bufferevent_setcb(bev, CB_1_authRead, NULL, authEvCB, NULL);
        bufferevent_enable(bev, EV_READ | EV_WRITE);

        struct serverInfoDTO serverInfo = {.status = kSERVERSTATUS_OK, .playerCount = connectedUsers, .serverVersion = 1};

        bufferevent_write(bev, &serverInfo, sizeof(serverInfo));
}
