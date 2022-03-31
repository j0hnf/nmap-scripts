description = [[
Checks for spring4shell (spring core 0 day) based upon the detection opportunity identified
by tweedge here: https://github.com/tweedge/springcore-0day-en
]]

---
--- @usage nmap -p 80,443,8000 <target> --script http-spring4shells.nse
--- 
--- @output
--- PORT    STATE SERVICE
--- 22/tcp  open  ssh
--- 80/tcp  open  http
--- |_http-spring4shells: probably not vulnerable
--- 443/tcp open  https
--- |_http-spring4shells: probably not vulnerable
---

author = "@j0hn__f <john.fitzpatrick [at] jumpsec.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local shortport = require "shortport"
local http = require "http"

portrule = shortport.http

action = function(host, port)

    local uri = "/path?class.module.classLoader.URLs%5B0%5D=0"
    local response = http.get(host, port, uri)
    
    if (response.status == 400) then
        return "possibly VULNERABLE"
    else
        return "probably OK"
    end
end
