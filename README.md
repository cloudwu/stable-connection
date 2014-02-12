Stable Connection
=================

这个模块的最初想法记录在 http://blog.codingnow.com/2014/02/connection_reuse.html ， 但最终实现的时候 API 有所变化。

我想加强 TCP 连接的稳定性，在 Client 失去 Server 的响应后（通常在应用层用心跳保持），可以重新发起一个 TCP 连接，取代之前的连接。这个模块可以完成这项工作，但模块本身不设计 socket api ，它仅仅封装了控制协议。并且，这个模块会顺便对数据做简单的加密。

Server API
==========

在服务器端，只需要把 connectionserver.c encrypt.c 链入你的项目即可使用，API 如下：

```C
struct pool_message {
	int id;
	size_t sz;
	const char *buffer;
};

struct connection_pool * cp_new();
void cp_delete(struct connection_pool *cp);
void cp_timeout(struct connection_pool *cp);

void cp_recv(struct connection_pool *cp, int fd, const char * buffer, size_t sz);
void cp_send(struct connection_pool *cp, int id, const char * buffer, size_t sz);

#define POOL_EMPTY 0
#define POOL_IN 1
#define POOL_OUT 2

int cp_poll(struct connection_pool *cp, struct pool_message *m);
```

首先需要用 cp_new 创建一个连接池对象 connection_pool ，程序结束时应该调用 cp_delete 销毁它。

由于本模块并不真正负责管理连接，所以你需要额外编写连接管理的程序。当你在外部管理的连接 fd 上有数据输入时，应该调用 cp_recv 把输入的数据置入。不必告诉 connection_pool 有新的 fd 创建，cp_recv 内部会自动为新的 fd 分配所需的内部数据结构。

如果一个 fd 断开，应该调用 cp_recv(cp, fd, NULL, 0) ，通知此连接已无效。这样之后对 fd 的处理都被视为新的外部连接。

由于外部可以创建新的 fd 取代旧连接，connection_pool 为每个 stable connection 分配了额外的 id 。这个 id 是一个 32 位正整数，0 是一个无效 id 。

如果你想向一个 id 发送数据 ，需要调用 cp_send 方法。这里必须传入由内部分配出来的合法 id 。如果 id 无效，这组数据会被抛弃掉。如果你想主动断开一个 id 对应的连接，那么调用 cp_send(cp, id, NULL, 0) 。

cp_poll 这个 API 会帮助你把所有的数据流转化为真正的网络数据流。你应该尽量在每次 cp_recv 或 cp_send 都重复调用它。

每次 cp_poll 会返回一个数据包，以及这个数据包的类型。如果返回了 POLL_EMPTY ，表示没有新的数据包了。

如果 cp_poll 返回了 POOL_IN ，表示有一个连接上有数据进入。id 字段表示是哪个连接上有了数据，buffer 和 sz 字段是数据内容。取得数据后，应该立即处理这段数据，数据指针的有效性只保证到下一次 cp_poll 之前。如果你要保留这串数据，需要重新分配内存复制下来，不得持有 buffer 指针。

如果 cp_poll 返回了 POOL_OUT ，表示需要向一个外部连接 fd 写入一串数据。这串数据可能是握手协议，也可能是加密过的，曾经通过 cp_send 传入的文本。

为了防止有连接连入却迟迟不进行握手协议，你需要定期调用 cp_timeout 清理那些在握手阶段停留太久的 fd 。注：cp_timeout 目前暂未实现。

Client API
==========

在客户端，需要把 connectionclient.c encrypt.c 链入你的项目。API 如下：

```C
struct connection_message {
	int sz;
	const char * buffer;
};

struct connection * cc_open();
void cc_close(struct connection *);
void cc_handshake(struct connection *);

void cc_send(struct connection *, const char * buffer, size_t sz);
void cc_recv(struct connection *, const char * buffer, size_t sz);

#define MESSAGE_EMPTY 0
#define MESSAGE_IN 1
#define MESSAGE_OUT 2

int cc_poll(struct connection *, struct connection_message *);
```

这个模块不会为你维护系统 socket ，所以你需要自己创建一个 socket ，连接到服务器，然后调用 cc_open 为你真正的 socket 创建一个 connection 结构。在你想断开连接时调用 cc_close 销毁它。

当你的 socket 收到任何数据，都应该调用 cc_recv 交给它处理；如果你想发送数据，应该调用 cc_send 。

和 server API 类似，cc_send 和 cc_recv 并不会真正收发数据，你需要在之后调用 cc_poll 。

如果 cc_poll 返回 MESSAGE_IN ，表示你获得了新的数据包；当其返回 MESSAGE_OUT 时，你需要把数据真正写入 socket 。

一旦你发现 socket 状态不太正常，通常是应用层发现太久没有收到服务器的回应。你可以创建一个新的 socket ，重新连接到服务器。然后调用 cc_handshake 表示需要重新握手。之后，处理 cc_poll 的返回即可（把后续的 MESSAGE_OUT 包写到新的 socket 上）。

握手协议
========

每当客户端发起一个新的连接，它首先向服务器发送 16 个字节：

前 8 个字节为 0 ，表示是一个新的连接。

接下来 8 个字节是用来和服务器协商通讯加密。

接下来，服务器会返回 16 字节：

前 8 个字节用于通讯加密协商，后 8 个字节是一个随机挑战码。

客户端需要利用协商出来的加密密钥，对挑战码做一次 hash （目前是用 md5 算法），生成 8 字节的回应码发送回去完成握手。

随后的数据将利用协商出来的密钥做 RC4 加密。

当客户端想用一个新的连接替代过去的连接时，它需要向服务器发送 12 个字节：

前 8 个字节为小头的 64bit 正整数，表示它曾经从这个连接上收到多少字节的数据。

接下来 4 个字节为收到的这些数据的指纹。（指纹算法见代码实现）

服务器收到重连请求后，会在连接池中找到指纹匹配的连接，取得这个连接的密钥。然后返回 16 字节：

前 8 个字节是小头 64bit 正整数，表示服务器曾经从这个连接上接收到多少数据，后 8 个字节是一个随机挑战码，用于验证客户端是否真正持有密钥。

之后，客户端应回应挑战，然后补发服务器没有收到的数据包。

在重连握手协议交互过程中，任何一方发现无法合法的修复连接，都应该主动断开。











