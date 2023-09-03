require "mathutil"
require "constants"

PlayerBullet = {}
PlayerBullet.__index = PlayerBullet

function PlayerBullet.new(x, y, vx, vy)
	local bl = {}
	setmetatable(bl, PlayerBullet)

	bl.x = x
	bl.y = y
	bl.vx = vx
	bl.vy = vy

	bl.anim_img = love.graphics.newImage("img/playerbullet.png")

	return bl
end

function PlayerBullet:update(dt)
	self.x = self.x + self.vx
	self.y = self.y + self.vy
end

function PlayerBullet:isdead()
	return (self.x < -20 or self.x > constants.tile_size * constants.map_width + 20 or self.y < -20 or self.y > constants.tile_size * constants.map_height + 20)
end

function PlayerBullet:draw()
	love.graphics.draw(self.anim_img, self.x, self.y)
end