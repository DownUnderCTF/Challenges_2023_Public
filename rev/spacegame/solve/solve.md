The game is a LOVE2D packed executable with obfuscated lua scripts.

Open the exe as a zipfile and extract the contents. We are going to inspect `Player.lua`.

Remove the return keyword and add the following below `Player.lua` to debug the program globals (modified from https://stackoverflow.com/a/41943392):

```
function tprint (tbl, indent)
  if not indent then indent = 0 end
  if indent > 4 then
  	return ""
  end
  local toprint = string.rep(" ", indent) .. "{\r\n"
  indent = indent + 2 
  for k, v in pairs(tbl) do
    toprint = toprint .. string.rep(" ", indent)
    if (type(k) == "number") then
      toprint = toprint .. "[" .. k .. "] = "
    elseif (type(k) == "string") then
      toprint = toprint  .. k ..  "= "   
    end
    if (type(v) == "number") then
      toprint = toprint .. v .. ",\r\n"
    elseif (type(v) == "string") then
      toprint = toprint .. "\"" .. v .. "\",\r\n"
    elseif (type(v) == "table") then
      toprint = toprint .. tprint(v, indent + 2) .. ",\r\n"
    else
      toprint = toprint .. "\"" .. tostring(v) .. "\",\r\n"
    end
  end
  toprint = toprint .. string.rep(" ", indent-2) .. "}"
  return toprint
end

print(tprint(_G))
```

You will see there is a variable named `Player` that has a kill function. What happens if we override it with nop?

```
function Player:kill() end
```

Recompile the game and you can now play invincible.