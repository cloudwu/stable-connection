local socket = require "lsocket"
local client = require "lsocket.client"

local ip, port = ...
port = assert(tonumber(port))

local function sendmsg(so, msg)
	local len = so:send(msg)
	if len then
		if len ~= #msg then
			sendmsg(so, msg:sub(len+1))
		end
	else
		error "write failed"
	end
end

local so = assert(socket.connect(ip, port))
local c = client()

local function poll()
	while true do
		local t, msg = c:poll()
		if t == nil then
			break
		end
		if t == 1 then
			-- message in
			print("<=====", msg)
		else
			-- message out
			sendmsg(so, msg)
		end
	end
end

c:send "1234567890"
poll()
so:close()
so = assert(socket.connect(ip, port))
c:handshake()
poll()
c:send "abcdef"
poll()
local readsocket = { so }

while true do
	local r = socket.select(readsocket)
	assert(r[1] == so)
	local msg = assert(so:recv())
	c:recv(msg)
	poll()
end
