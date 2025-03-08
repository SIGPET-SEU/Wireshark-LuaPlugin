
local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

local DEBUG = debug_level.LEVEL_1

local default_settings = {
    debug_level = DEBUG,
    ports = { 443 },  -- VLESS 默认端口
    reassemble = true,
    info_text = true,
    ports_in_info = true,
}

-- 定义 VLESS 协议
local vless = Proto("VLESS", "VLESS Protocol")
local PROTOCOL_NAME = "VLESS"

-- 定义协议字段
local pf_uuid = ProtoField.bytes("vless.uuid", "VLESS User UUID")
local pf_addon_len = ProtoField.uint8("vless.addon_len", "Additional Info Length")
local pf_addon_info = ProtoField.bytes("vless.addon_info", "Additional Info")
local pf_cmd = ProtoField.uint8("vless.cmd", "Command Type")
local pf_dst_port = ProtoField.uint16("vless.dst_port", "Destination Port")
local pf_atype = ProtoField.uint8("vless.atype", "Address Type")
local pf_dst_addr = ProtoField.string("vless.dst_addr", "Destination Address")
local pf_payload = ProtoField.bytes("vless.payload", "Payload")
local pf_tunnel_data = ProtoField.bytes("vless.tunnel_data", "Tunneled Data")

vless.fields = {
    pf_uuid, pf_addon_len, pf_addon_info, pf_cmd, pf_dst_port, pf_atype, pf_dst_addr, pf_payload, pf_tunnel_data
}

local f_data = Field.new("data.data")

-- 验证 UUID 是否符合 RFC 4122 格式
local function is_valid_uuid(tvb, offset)
    if tvb:len() < offset + 16 then
        return false
    end

    local uuid_bytes = {}
    for i = 0, 15 do
        uuid_bytes[i + 1] = tvb(offset + i, 1):uint()
    end

    local version = (uuid_bytes[7] >> 4) & 0x0F
    if version ~= 4 then
        return false
    end

    local variant = (uuid_bytes[9] >> 6) & 0x03
    if variant ~= 2 then
        return false
    end

    return true
end

-- 判断是否可能是 VLESS 报文
local function is_likely_vless(tvb)
    if tvb:len() < 21 then
        return false
    end

    if tvb(0, 1):uint() ~= 0 then
        return false
    end

    if not is_valid_uuid(tvb, 1) then
        return false
    end

    local addon_len = tvb(17, 1):uint()
    if tvb:len() < 18 + addon_len + 3 then
        return false
    end

    local cmd_offset = 18 + addon_len
    local cmd = tvb(cmd_offset, 1):uint()
    if cmd < 1 or cmd > 3 then
        return false
    end

    local atype_offset = cmd_offset + 3
    local atype = tvb(atype_offset, 1):uint()
    if atype < 1 or atype > 3 then
        return false
    end

    local addr_offset = atype_offset + 1
    if atype == 1 then
        if tvb:len() < addr_offset + 4 then return false end
    elseif atype == 2 then
        if tvb:len() < addr_offset + 1 then return false end
        local domain_len = tvb(addr_offset, 1):uint()
        if tvb:len() < addr_offset + 1 + domain_len then return false end
    elseif atype == 3 then
        if tvb:len() < addr_offset + 16 then return false end
    end

    return true
end

-- 获取 VLESS 请求长度（目标地址部分，不含端口）
local function get_request_length(tvb, offset)
    local atype = tvb(offset, 1):uint()
    if atype == 1 then
        return 4
    elseif atype == 2 then
        local domain_len = tvb(offset + 1, 1):uint()
        return 1 + 1 + domain_len
    elseif atype == 3 then
        return 16
    end
    return 0
end

-- 主解析函数
local function doDissect(tvb, pktinfo, root)
    if not is_likely_vless(tvb) then
        -- 如果不是 VLESS 请求，尝试解析为隧道化的 TLS 数据
        local tunnel_tree = root:add(pf_tunnel_data, tvb(0))
        pktinfo.cols.info = "VLESS Tunneled Data"

        local save_port_type = pktinfo.port_type
        pktinfo.port_type = _EPAN.PT_NONE
        local save_can_desegment = pktinfo.can_desegment
        pktinfo.can_desegment = 2
        Dissector.get("tls"):call(tvb, pktinfo, tunnel_tree)  -- 这里使用 Tvb

        if f_data() ~= nil then
            local data_tvb = f_data().range:tvb()
            local app_tree = tunnel_tree:add(pf_TLS_app_data, data_tvb)
            local save_inner_port_type = pktinfo.port_type
            pktinfo.port_type = _EPAN.PT_SCTP
            local save_inner_can_desegment = pktinfo.can_desegment
            pktinfo.can_desegment = 2
            Dissector.get("http"):call(data_tvb, pktinfo, app_tree)
        end

        pktinfo.port_type = save_port_type
        pktinfo.can_desegment = save_can_desegment

        pktinfo.cols.protocol:set(PROTOCOL_NAME)
        
        return true
    end

    -- 解析 VLESS 请求
    local tree = root:add(vless, tvb)
    tree:add(pf_uuid, tvb(1, 16))

    local addon_len = tvb(17, 1):uint()
    tree:add(pf_addon_len, tvb(17, 1))
    
    if addon_len > 0 then
        tree:add(pf_addon_info, tvb(18, addon_len))
    end

    local cmd_offset = 18 + addon_len
    tree:add(pf_cmd, tvb(cmd_offset, 1))

    local port_offset = cmd_offset + 1
    local port = tvb(port_offset, 2):uint()
    tree:add(pf_dst_port, tvb(port_offset, 2))

    local offset = port_offset + 2
    local atype = tvb(offset, 1):uint()
    local request_len = get_request_length(tvb, offset)

    local addr_tree = tree:add(vless, tvb(offset, request_len + 1), "Destination")
    addr_tree:add(pf_atype, tvb(offset, 1))
    offset = offset + 1

    local addr
    if atype == 1 then
        addr = tostring(tvb(offset, 4):ipv4())
        offset = offset + 4
    elseif atype == 2 then
        local domain_len = tvb(offset, 1):uint()
        addr = tvb(offset + 1, domain_len):string()
        offset = offset + 1 + domain_len
    elseif atype == 3 then
        addr = tostring(tvb(offset, 16):ipv6())
        offset = offset + 16
    end

    addr_tree:add(pf_dst_addr, addr)

    -- 添加负载数据（如果有）
    if tvb:len() > offset then
        tree:add(pf_payload, tvb(offset))
    end

    -- 设置协议和信息列
    pktinfo.cols.protocol:set(PROTOCOL_NAME)
    pktinfo.cols.info = "VLESS Request"
    return true
end

-- 解析器入口
function vless.dissector(tvb, pktinfo, root)
    -- 执行解析
    pktinfo.cols.protocol:set(PROTOCOL_NAME)
    if default_settings.info_text then
        pktinfo.cols.info = "VLESS data"
    end

    if not doDissect(tvb, pktinfo, root) then
        pktinfo.cols.info = "Invalid VLESS packet"
        return 0
    end

    return tvb:len()
end

-- 注册解析器
local function enableDissector()
    DissectorTable.get("tls.port"):add(default_settings.ports[1], vless)
    DissectorTable.get("tls.alpn"):add("h2", vless)
    DissectorTable.get("tls.alpn"):add("http/1.1", vless)
end

enableDissector()