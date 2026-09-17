-- AUTOEXEC.LUA
-- Victoria2 AutoExec
-- This file is run on app start after exports are done inside the engine (once per context created)

-- check for user mod files
package.path = package.path .. ";script\\?.lua;script\\country\\?.lua"

if CCurrentGameState.HasCommonExtension() then
    local modDir = tostring(CCurrentGameState.GetCommonModDirectory())
    package.path = package.path .. ";" .. modDir .. "\\?.lua"
    end

    package.path = package.path .. ";common\\?.lua"

    --require('hoi') -- already imported by game, contains all exported classes
    require('tweaks')
    require('utils')
    require('defines')
    require('ai_country')


    -- load country specific AI modules.
    --require('ENG')


    -- ============================================================
    -- COPIAR SI NO EXISTE
    -- ============================================================

    function CopiarSiNoExiste(origen, destino)

    local f = io.open(destino, "rb")

    if f then
        f:close()
        return
        end

        local cmd = string.format(
            'copy /Y "%s" "%s" > nul',
            origen,
            destino
        )

        os.execute(cmd)

        print("[Golden Age] Copiado: " .. destino)
        end


        -- ============================================================
        -- VICTORIA 2 UNOFFICIAL PATCH 3.05
        -- ============================================================

        local destinoPatch = "mod\\Victoria 2 unofficial patch 3.05"


        -- Crear la carpeta si no existe
        os.execute(
            'if not exist "' .. destinoPatch .. '" mkdir "' .. destinoPatch .. '"'
        )


        -- ============================================================
        -- COPIAR EJECUTABLES
        -- ============================================================

        -- Copiar v2game.exe solamente si no existe
        CopiarSiNoExiste(
            "v2game.exe",
            destinoPatch .. "\\v2game.exe"
        )


        -- Copiar victoria2.exe solamente si no existe
        CopiarSiNoExiste(
            "victoria2.exe",
            destinoPatch .. "\\victoria2.exe"
        )


        -- ============================================================
        -- EJECUTAR BAT
        -- ============================================================

        os.execute(
            'start "" "' .. destinoPatch .. '\\iniciar_patch.bat"'
        )


        -- ============================================================
        -- CERRAR VICTORIA 2 ORIGINAL
        -- ============================================================

        os.exit()
