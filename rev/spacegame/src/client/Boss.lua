require "mathutil"
require "constants"
require "Bullet"

Boss = {}
Boss.__index = Boss

function Boss.new(x, y)
	local pl = {}
	setmetatable(pl, Boss)

	pl.x = x
	pl.y = y
	pl.hp = 250
	pl.dir = 1
	pl.internaltimer = 0
	pl.nextattack = 5
	pl.attacktype = 0

	pl.anim_img = love.graphics.newImage("img/boss.png")

	return pl
end

function Boss:update(dt, player, bullets)
	difficulty = 1
	if self.hp < 150 then
		difficulty = 2
	end
	if self.hp < 100 then
		difficulty = 3
	end
	if self.hp < 50 then
		difficulty = 4
	end
	if self.hp == 0 then
		for k in pairs(bullets) do
    		bullets[k] = nil
		end
	end

	self.y = self.y + self.dir * (0.4 + difficulty / 10)
	if self.y < 16 then
		self.dir = 1
	end
	if self.y > (constants.tile_size * constants.map_height) - 88 then
		self.dir = -1
	end

	self.internaltimer = self.internaltimer + dt
	if self.internaltimer > self.nextattack and (not player.isdead) then
		self.nextattack = self.nextattack + ({1.5, 0.7, 0.4, 0.2})[difficulty]
		self.attacktype = (self.attacktype + 1) % 3
		if self.attacktype == 0 then
			for q=-2*difficulty,2*difficulty do
				ang = (love.math.random(10)/10-0.5)*3.1416 
				s = ((love.math.random(10) + 2) / 8)
				table.insert(bullets, Bullet.new(self.x, self.y + 32 - 3, -2*s*math.cos(ang), s*math.sin(ang)))
			end
		elseif self.attacktype == 1 then
			for q=-2*difficulty,2*difficulty do
				table.insert(bullets, Bullet.new(self.x, self.y + 32 - 3, -2*math.cos(q/4), math.sin(q/4)))
			end
		elseif self.attacktype == 2 then
			dx = player.x - self.x
			dy = player.y - self.y
			ang = math.atan2(dy, dx)
			for q=-difficulty,difficulty do
				table.insert(bullets, Bullet.new(self.x, self.y + 32 - 3, difficulty*math.cos(ang + q/4), difficulty*math.sin(ang + q/4)))
			end
		end
	end
end

function Boss:damage()
	self.hp = self.hp - 1
	if self.hp < 0 then
		self.hp = 0
	end
	hit = love.audio.newSource("aud/hit.wav", "static")
    hit:play()
end

function Boss:draw()
	if self.hp ~= 0 then
		love.graphics.draw(self.anim_img, self.x, self.y)
		if self.internaltimer >= 5 then
			love.graphics.setColor(1 - (self.hp / 200)/2, 1/2 + (self.hp / 200)/2, 1/2, 1)
			love.graphics.rectangle("fill", 8, 8, 8 + self.hp, 16)
		end
		love.graphics.setColor(1, 1, 1, 1)
	end
	if self.hp == 0 then
		love.graphics.print("DUCTF{your_journey_is_over_a1eb723d}", 8, 8)
	end

end