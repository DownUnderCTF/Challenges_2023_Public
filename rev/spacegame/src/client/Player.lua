require "mathutil"
require "constants"

Player = {}
Player.__index = Player

function Player.new(x, y)
	local pl = {}
	setmetatable(pl, Player)

	pl.x = x
	pl.y = y
	pl.isdead = false
	pl.internal_exit_timer = 0
	pl.deadparticles = {}

	pl.anim_img = love.graphics.newImage("img/player.png")

	return pl
end

function Player:update(dt)
	if not player.isdead then
		local dir_x = 0
		local dir_y = 0
		if love.keyboard.isDown('left') then
	        dir_x = dir_x - 1
	    end
	    if love.keyboard.isDown('right') then
	        dir_x = dir_x + 1
	    end
	    if love.keyboard.isDown('up') then
	        dir_y = dir_y - 1
	    end
	    if love.keyboard.isDown('down') then
	        dir_y = dir_y + 1
	    end

		local speed = 1
		self.x = self.x + dir_x * speed
		self.x = mathutil.clamp(self.x, 0, constants.tile_size * (constants.map_width - 1))
		self.y = self.y + dir_y * speed
		self.y = mathutil.clamp(self.y, 0, constants.tile_size * (constants.map_height - 1))
	else
		self.internal_exit_timer = self.internal_exit_timer + dt

		if self.internal_exit_timer > 5 then
			love.event.quit(0)
		end
	end
end

function Player:kill()
	if not player.isdead then
		player.isdead = true
		hit = love.audio.newSource("aud/boom.wav", "static")
    	hit:play()
    	for _=0,200 do
    		s = love.math.random(200) / 5
    		ang = love.math.random(360) / 360 * 2 * 3.1415
    		table.insert(self.deadparticles, s*math.cos(ang))
    		table.insert(self.deadparticles, s*math.sin(ang))
    	end
	end
end

function Player:draw()
	if not player.isdead then
		love.graphics.draw(self.anim_img, self.x, self.y)
	else
		qq = {}
		for k, v in pairs(self.deadparticles) do
			if k % 2 == 1 then
				qq[k] = self.x + v * self.internal_exit_timer 
			else
				qq[k] = self.y + v * self.internal_exit_timer 
			end
		end

		love.graphics.setColor(1, 50/255, 50/255, 1)
    	love.graphics.points(qq)
    	love.graphics.setColor(1, 1, 1, 1)
	end
end