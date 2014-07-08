local socket = require "lsocket"
local server = require "lsocket.server"
local port = assert(tonumber(...))
local so = assert(socket.bind(port))
local pool = server()

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

local readsocket = { so }
local client = {}
local fds = {}
local current_id

local function accept(c)
	table.insert(readsocket, c)
	local fd = c:info().fd
	client[c] = fd
	fds[fd] = c
end

local function close(s)
	fds[client[s]] = nil
	client[s] = nil
	local tmp = readsocket
	readsocket = {}
	for _,v in pairs(tmp) do
		if v ~= s then
			table.insert(readsocket, v)
		end
	end
end

local function recv(s)
	local fd = client[s]
	local str, err = s:recv()
	if str then
		pool:recv(fd, str)
	elseif str == nil then
		print("disconnect", fd)
--		report closed
--		pool:recv(fd, "")
		close(s)
		current_id = nil
	end
end

local function poll()
	while true do
		local t, id, msg = pool:poll()
		if t == nil then
			break
		elseif t == 1 then
			-- message in
			current_id = id
			print("<=======", id, msg)
		else
			-- message out
			local so = assert(fds[id])
			sendmsg(so, msg)
		end
	end
end

while true do
	local r = socket.select(readsocket)
	local t = 0
	for _, s in ipairs(r) do
		if s == so then
			local c, ip, port = so:accept()
			if c then
				print("accept :", ip, port)
				accept(c)
			end
		else
			recv(s)
			poll()
			if current_id then
				pool:send(current_id, tostring(t) .. "\n")
			end
			t=t+1
			poll()
		end
	end
end
