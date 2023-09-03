require "constants"

require "Player"
require "PlayerBullet"
require "Bullet"
require "Boss"

function love.load()
    love.window.setFullscreen(true)
    graphics_scale = select_graphics_scale()
    graphics_canvas = love.graphics.newCanvas(
        constants.tile_size * constants.map_width,
        constants.tile_size * constants.map_height
    )
    -- love.graphics.setBackgroundColor(0, 0, 0, 1)

    stars = {}
    for _=1,150 do
        table.insert(stars, love.math.random(constants.tile_size * constants.map_width))
        table.insert(stars, love.math.random(constants.tile_size * constants.map_height))
    end

    player = Player.new(32, constants.tile_size * constants.map_height / 2 - 12)
    boss = Boss.new(constants.tile_size * constants.map_width - 96, constants.tile_size * constants.map_height / 2 - 36)
    bullets = {}
    playerbullets = {}
    internaltimer = 0
    next_playerbullet_at = 5

    music = love.audio.newSource("aud/bowsers-castle-sincx.ogg", "stream")
    music:play()
    
end

function select_graphics_scale()
    local window_width, window_height = love.graphics.getDimensions()

    local req_space_ratio_x = window_width / (constants.tile_size * constants.map_width)
    local req_space_ratio_y = window_height / (constants.tile_size * constants.map_height)

    local scale_x = math.floor(req_space_ratio_x * 2) / 2
    local scale_y = math.floor(req_space_ratio_y * 2) / 2

    return math.max(1, math.min(scale_x, scale_y))
end

function love.update(dt)
    internaltimer = internaltimer + dt

    if internaltimer > next_playerbullet_at and (not player.isdead) then
        table.insert(playerbullets, PlayerBullet.new(player.x+9,player.y+9,3,0))
        next_playerbullet_at = next_playerbullet_at + 0.25
    end

    player:update(dt)
    boss:update(dt, player, bullets)
    if player.x + 12 > boss.x and player.x + 12 < boss.x + 72 and player.y + 12 > boss.y and player.y + 12 < boss.y + 72 then
        player:kill()
    end
    for k, v in pairs(bullets) do
        v:update()
        if v.x + 6 > player.x and v.x + 6 < player.x + 24  and v.y + 6 > player.y and v.y + 6 < player.y + 24 then
            player:kill()
        end
        if v:isdead() then
            bullets[k] = nil
        end
    end
    for k, v in pairs(playerbullets) do
        v:update()
        if v.x + 3 > boss.x and v.x + 3 < boss.x + 72  and v.y + 3 > boss.y and v.y + 3 < boss.y + 72 then
            boss:damage()
            playerbullets[k] = nil
        elseif v:isdead() then
            playerbullets[k] = nil
        end
    end
    for k in pairs(stars) do
        if k%2 == 1 then
            stars[k] = (stars[k] - (math.floor(k/50)+1)/5) % (constants.tile_size * constants.map_width)
        end
    end
end

function love.keypressed(key)
    if love.keyboard.isDown('left') then
        player.dir_x = -1
    elseif key == 'right' then
        player.dir_x = 1
    elseif key == 'up' then
        player.dir_y = -1
    elseif key == 'down' then
        player.dir_y = 1
    elseif key == 'escape' then
        love.event.quit(0)
    end
end

function love.keyreleased(key)
    if key == 'left' then
        player.dir_x = 0
    elseif key == 'right' then
        player.dir_x = 0
    elseif key == 'up' then
        player.dir_y = 0
    elseif key == 'down' then
        player.dir_y = 0
    end
end

function love.draw()
    -- start canvas
    love.graphics.setCanvas(graphics_canvas)

    -- draw background 
    love.graphics.clear(0, 0, 0, 0)
    love.graphics.setColor(20/255, 20/255, 20/255, 1)
    love.graphics.rectangle("fill", 0, 0, constants.tile_size * constants.map_width, constants.tile_size * constants.map_height)
    
    -- first layer
    love.graphics.setColor(240/255, 240/255, 240/255, 1)
    love.graphics.points(stars)

    love.graphics.setColor(1, 1, 1, 1)


    -- draw graphics
    player:draw()
    boss:draw()
    for _, v in pairs(bullets) do
        v:draw()
    end
    for _, v in pairs(playerbullets) do
        v:draw()
    end

    -- end canvas
    love.graphics.setCanvas()

    local window_width, window_height = love.graphics.getDimensions()

    love.graphics.draw(
        graphics_canvas,
        (window_width - constants.tile_size * constants.map_width * graphics_scale) / 2,
        (window_height - constants.tile_size * constants.map_height * graphics_scale) / 2,
        0,
        graphics_scale,
        graphics_scale
    )
end