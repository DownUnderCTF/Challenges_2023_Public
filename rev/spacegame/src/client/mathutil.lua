mathutil = {}
mathutil.__index = mathutil

function mathutil.absmin(x, y)
    if math.abs(x) < math.abs(y) then return x end
    return y
end

function mathutil.sign(x)
    if x > 0 then return 1 end
    if x < 0 then return -1 end
    return 0
end

function mathutil.sign(x)
    if x > 0 then return 1 end
    if x < 0 then return -1 end
    return 0
end

function mathutil.clamp(n, low, high)
    return math.min(math.max(n, low), high)
end