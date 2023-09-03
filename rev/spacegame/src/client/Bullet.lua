require "mathutil"
require "constants"

Bullet = {}
Bullet.__index = Bullet

function Bullet.new(x, y, vx, vy)
	local bl = {}
	setmetatable(bl, Bullet)

	bl.x = x
	bl.y = y
	bl.vx = vx
	bl.vy = vy

	bl.anim_img = love.graphics.newImage("img/bullet.png")

	return bl
end

function Bullet:update(dt)
	self.x = self.x + self.vx
	self.y = self.y + self.vy
end

function Bullet:isdead()
	return (self.x < -20 or self.x > constants.tile_size * constants.map_width + 20 or self.y < -20 or self.y > constants.tile_size * constants.map_height + 20)
end


function Bullet:draw()
	love.graphics.draw(self.anim_img, self.x, self.y)
end