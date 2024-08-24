
local M = {}




function M.table_size(t)
    local count = 0
    for _ in pairs(t) do count = count + 1 end
    return count
end

function M.table_eq(t1, t2)
    if not t1 or not t2 then return false end

    if M.table_size(t1) ~= M.table_size(t2) then return false end
    for k, v in pairs(t1) do
        if not t2[k] then return false end
        if v ~= t2[k] then return false end
    end

    return true
end

function M.sequence_eq(t1, t2)
    if not t1 or not t2 then return false end

    if #t1 ~= #t2 then return false end
    for i = 1, #t1 do
        if t1[i] ~= t2[i] then return false end
    end

    return true
end

---
--- Extend the string:find() function. It returns all the (first, last) pairs for str in the string, instead of the
--- first pair in string:find().
--- @param str, the target pattern to search.
--- @return table the tables that contains all the firsts and lasts.
---
function M.find_all(str, pattern)
    local firsts = {}
    local lasts = {}
    local first, last
    local b = 1
    while true do
        first, last = string.find(str, pattern, b)
        if not first then break end
        firsts[#firsts + 1] = first
        lasts[#lasts + 1] = last
        b = first + 1
    end
    return firsts, lasts
end

function M.print_table(t)
    if not t then print(t) return end
    local size = M.table_size(t)
    local count = 0
    io.write("{")
    for k, v in pairs(t) do
        count = count + 1
        if count == size then io.write(k, ": ", v) break end
        io.write(k, ": ", v, ", ")
    end
    io.write("}")
end

function M.print_seq(t)
    if not t then print(t) return end
    local count = 0
    io.write("{")
    for i = 1, #t do
        count = count + 1
        if count == #t then io.write(t[i]) break end
        io.write(t[i], ", ")
    end
    io.write("}")
end

function M.tohex(str)
    return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
    end))
end

return M