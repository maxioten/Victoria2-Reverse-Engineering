// V2TechButton.cpp
//
// Mod para Victoria 2: botones que lanzan decisiones, ocultamiento de
// esas decisiones en la ventana de política, cambio porcentual de
// precios, parches de bytes de refuerzos y objetivos de guerra,
// indicador de texto.
//
// Compilar: Visual Studio, Dynamic-Link Library, plataforma x86 (Win32),
// configuración Release, runtime /MT.
//
// Se carga como proxy de lua51.dll: el original se renombra a
// lua51_real.dll, y las exportaciones se reenvían ahí vía
// lua51_exports.h.

#ifdef _WIN64
#error This DLL must be built for Win32 (x86)
#endif

#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <intrin.h>
#include <ctype.h>

#include "lua51_exports.h"

// ---------------------------------------------------------------
// Configuración de compilación
// ---------------------------------------------------------------

// Versión. El juego no verifica los binarios, así que la única
// protección contra "alguien tiene una DLL vieja" es comparar esta
// cadena en los logs antes de una partida en red.
// CLAUDE CAMBIÁ LA VERSIÓN EN CADA EDICIÓN DEL ARCHIVO
#define MOD_VERSION "2.66"

// La configuración de abajo se lee de v2dll_settings.ini junto al exe
// en cada arranque del juego. Si el archivo todavía no existe, se crea
// con los valores por defecto (listados aquí). Editar el archivo no
// requiere recompilar la DLL - los cambios se aplican en el próximo
// arranque del juego.
struct Settings
{
    bool log            = true;   // log en v2dll.log (muchas entradas por tick, para distribuir poner 0)
    bool buttons        = true;   // botones que lanzan decisiones
    bool decisionFilter = true;   // ocultamiento de decisiones en la ventana de política
    bool priceDelta     = false;  // paso porcentual de cambio de precios
    bool popDisplay     = false;  // población total en el panel superior (revertido: no se pudo escribir el número real entre paréntesis sin riesgo)
    bool versionLabel   = true;   // versión del mod en el subtítulo del menú principal

    // Parches de bytes del exe de la tabla EXE_PATCHES (ver más abajo
    // en el archivo) se controlan directamente vía BytePatch::enabled
    // por claves PATCH_<NOMBRE> en el ini - acá solo van los parches
    // del exe que NO están en esa tabla (cada uno es una función
    // separada con su propio hook).
    bool patchOccupiedReinforceSplit = true;
    bool patchAllyOwnerCheck         = true;
    bool patchCivilizeNullCheck      = true;
    bool patchGraphPointClamp        = true;
    bool patchFactoryDumpScan        = true;
    bool patchProdListVisibility     = true;
    bool patchProdTypeGate           = true;
};

static Settings g_settings;

// Carga/guardado de configuración (v2dll_settings.ini) implementado
// más abajo en el archivo, después de la tabla EXE_PATCHES - la
// sustitución de valores por claves PATCH_<NOMBRE> busca el parche
// en esa tabla por nombre.
static void LoadSettings();

static bool g_logStarted = false;

static void Log(const char* fmt, ...)
{
    if (!g_settings.log)
        return;

    FILE* f = 0;
    if (fopen_s(&f, "v2dll.log", g_logStarted ? "a" : "w") != 0 || !f)
        return;

    g_logStarted = true;

    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);

    fprintf(f, "\n");
    fclose(f);
}


// ---------------------------------------------------------------
// CONFIGURACIÓN DE CONTENIDO — se edita acá
// ---------------------------------------------------------------

// Vista — pantalla del juego con su propia clase. Para conectar una
// nueva hacen falta:
//   rvaVtable   — dirección de la vftable de la clase menos 0x400000
//   slot        — slot que se llama regularmente mientras la ventana está viva
//   tooltipSlot — true si es el slot del tooltip (firma distinta)
//   offGlue     — desplazamiento de cualquier CButtonObserverGlue dentro de la vista
//   offContainer— desplazamiento del contenedor GUI, en todas las vistas vistas es 0x4C
//   window      — ventana anidada de .gui, o 0
//
// El slot se encuentra por prueba: en tecnologías funcionó el 11
// (Update), en presupuesto y producción el 10 (tooltip, se dispara al
// pasar el mouse).
struct ViewDef
{
    const char* name;
    DWORD       rvaVtable;
    int         slot;
    bool        tooltipSlot;
    int         offGlue;
    int         offContainer;
    const char* window;
};

static const ViewDef VIEWS[] =
{
    { "CTechnologyView", 0xA17FA4, 11, false, 0x60, 0x4C, "selected_tech_window" },
    { "CBudgetView",     0xA059F0, 10, true,  0x5C, 0x4C, 0                      },
    { "CProductionView", 0xA0FECC, 10, true,  0x120, 0x4C, 0                     },
    { "CPoliticsView",   0xA0E458, 10, true,  0x00, 0x4C, 0                      },
};

static const int VIEW_POLITICS = 3;

// Botones. view — número de fila en VIEWS, empezando desde cero.
struct ButtonDef
{
    int         view;
    const char* button;      // nombre del elemento de .gui
    const char* decision;    // nombre de la decisión de decisions/*.txt
};

static const ButtonDef BUTTONS[] =
{
    { 0, "FE_ACADEMIES_BDSM",     "open_academy_decisions_dec" },
    { 0, "FE_RPROJECTS_BDSM",     "open_research_projects_dec" },
    { 1, "FE_BUDGET_DIPLO_BDSM",  "exchange_settings_dec"      },
};

static const int VIEW_COUNT = sizeof(VIEWS) / sizeof(VIEWS[0]);
static const int BUTTON_COUNT = sizeof(BUTTONS) / sizeof(BUTTONS[0]);

// Techos: cada vista y cada botón necesita su propio adaptador, y hay
// que declararlos de antemano — ver macros más abajo.
static const int MAX_VIEWS = 4;
static const int MAX_BUTTONS = 8;


// ---------------------------------------------------------------
// Direcciones. RVA = dirección en Ghidra menos 0x400000.
// ASLR está activado, así que todo se calcula desde la base del
// módulo en tiempo de ejecución.
// ---------------------------------------------------------------

static const DWORD RVA_ONMAKEDECISION = 0x2DCE10;  // OnMakeDecisionClicked
static const DWORD RVA_VTABLE_DECISION = 0xA29B54;  // CDecision::vftable

static const int VT_SLOT_ISVALID = 6;   // CDecision, desplazamiento 0x18

// Límites de PoliticsView_OnClick — la función que arma la lista de decisiones.
static const DWORD RVA_POLITICS_DRAW_BEGIN = 0x2DB2E0;
static const DWORD RVA_POLITICS_DRAW_END = 0x2DC750;

// ---------------------------------------------------------------
// Desplazamientos dentro de los objetos de la interfaz
// ---------------------------------------------------------------

static const int GLUE_SIZE = 44;    // tamaño del glue
static const int OFF_GLUE_METHOD = 0x08;  // glue -> puntero al método

static const int VT_FIND_WINDOW = 0x6C;  // contenedor: buscar ventana anidada
static const int VT_FIND_CHILD = 0x34;  // ventana: buscar botón por nombre
static const int OFF_OBSERVABLE = 0x54;  // botón -> Observable
static const int VT_ADD_OBSERVER = 0x04;  // Observable: AddObserver
static const int VT_GET_NAME = 0x44;  // elemento: nombre desde .gui

// Elemento falso para OnMakeDecisionClicked: la función solo lee de él
// +0x14 (datos del std::string) y +0x28 (_Myres).
static const int ELEM_STRDATA = 0x14;
static const int ELEM_STRRES = 0x28;


// ---------------------------------------------------------------
// std::string del motor: buffer de 16 bytes, _Mysize en +0x10, _Myres en +0x14
// ---------------------------------------------------------------

struct GStr
{
    char     data[16];
    unsigned size;
    unsigned res;
};

static void MakeStr(GStr* s, char* storage, unsigned storageSize, const char* text)
{
    size_t n = strlen(text);

    memset(s, 0, sizeof(GStr));
    s->size = (unsigned)n;

    if (n < 16)
    {
        memcpy(s->data, text, n + 1);
        s->res = 15;
    }
    else
    {
        memcpy(storage, text, n + 1);
        *(char**)s->data = storage;
        s->res = storageSize - 1;
    }
}


// ---------------------------------------------------------------
// Llamada a métodos virtuales con convención __thiscall.
// MSVC no permite declarar un puntero __thiscall directamente, así
// que usamos __fastcall con un EDX ficticio — el layout coincide.
// ---------------------------------------------------------------

typedef void* (__fastcall* tCallNoArgs)(void* ecx, void* edx);
typedef void* (__fastcall* tCallOneArg)(void* ecx, void* edx, void* arg);

static void* VCall0(void* obj, int byteSlot)
{
    void** vt = *(void***)obj;
    tCallNoArgs fn = (tCallNoArgs)vt[byteSlot / 4];
    return fn(obj, 0);
}

static void* VCall1(void* obj, int byteSlot, void* arg)
{
    void** vt = *(void***)obj;
    tCallOneArg fn = (tCallOneArg)vt[byteSlot / 4];
    return fn(obj, 0, arg);
}


// Nombre de la clase del objeto vía RTTI (MSVC x86): antes de la
// tabla de funciones virtuales hay un puntero a CompleteObjectLocator,
// su 4to campo es un puntero a TypeDescriptor, y ahí en +8 está el
// nombre "decorado" tipo ".?AVCProvinceView@@". No funciona con
// clases sin RTTI/vtable.
static const char* GetRTTIClassName(void* obj)
{
    if (!obj)
        return "(null)";

    void** vtable = *(void***)obj;
    if (!vtable)
        return "(no vtable)";

    DWORD* completeObjectLocator = *(DWORD**)((unsigned char*)vtable - 4);
    if (!completeObjectLocator)
        return "(no RTTI)";

    DWORD* typeDescriptor = (DWORD*)completeObjectLocator[3];
    if (!typeDescriptor)
        return "(no RTTI)";

    return (const char*)typeDescriptor + 8;
}


// Contenido del std::string del motor.
static const char* GStrText(void* str)
{
    if (!str)
        return "";

    unsigned char* p = (unsigned char*)str;
    unsigned res = *(unsigned*)(p + 0x14);

    const char* data = (res > 15) ? *(const char**)p : (const char*)p;
    return data ? data : "";
}


// Escribir texto en un std::string existente sin exceder su capacidad.
static void GStrSet(void* str, const char* text)
{
    if (!str)
        return;

    unsigned char* p = (unsigned char*)str;
    unsigned res = *(unsigned*)(p + 0x14);
    unsigned len = (unsigned)strlen(text);

    if (len > res)
        len = res;

    char* data = (res > 15) ? *(char**)p : (char*)p;
    if (!data)
        return;

    memcpy(data, text, len);
    data[len] = 0;
    *(unsigned*)(p + 0x10) = len;
}


// ---------------------------------------------------------------
// Estado
// ---------------------------------------------------------------

static DWORD  g_base = 0;
static void* g_fnOnMakeDecision = 0;

typedef BOOL(WINAPI* tIsBadReadPtr)(const void*, UINT_PTR);
static tIsBadReadPtr g_fnIsBadReadPtr = 0;

static unsigned char g_glue[MAX_BUTTONS][GLUE_SIZE];
static unsigned char g_fakeElem[MAX_BUTTONS][0x30];
static char          g_decisionText[MAX_BUTTONS][128];
static char          g_nameStorage[128];


// ---------------------------------------------------------------
// Manejadores de clics
//
// __stdcall: la propia función limpia el stack. Con __cdecl el
// compilador agregaba su add esp,4 encima del ret 4 de la función, y
// el retorno se iba por un stack roto — comprobado por log.
// ---------------------------------------------------------------

typedef void(__stdcall* tOnMakeDecision)(void*);

static void __cdecl FireDecision(int index)
{
    if (!g_fnOnMakeDecision || index < 0 || index >= BUTTON_COUNT)
    {
        Log("FireDecision: estado inválido, index=%d", index);
        return;
    }

    Log("FireDecision: '%s' -> '%s'",
        BUTTONS[index].button, BUTTONS[index].decision);

    ((tOnMakeDecision)g_fnOnMakeDecision)(g_fakeElem[index]);
}


// El glue guarda un solo puntero a método, así que cada botón necesita
// su propio manejador. Solo se diferencian por el número.
//
// Forma con __asm antes de cada instrucción: la escritura en bloque
// __asm { ... } dentro de la macro se colapsa en una sola línea y no
// se puede usar.
#define THUNK(n)                             \
__declspec(naked) static void Thunk##n() \
{                                        \
    __asm push ebp                       \
    __asm mov  ebp, esp                  \
    __asm pushad                         \
    __asm push n                         \
    __asm call FireDecision              \
    __asm add  esp, 4                    \
    __asm popad                          \
    __asm mov  esp, ebp                  \
    __asm pop  ebp                       \
    __asm ret                            \
}

THUNK(0) THUNK(1) THUNK(2) THUNK(3)
THUNK(4) THUNK(5) THUNK(6) THUNK(7)

static void* const THUNKS[MAX_BUTTONS] =
{
    (void*)&Thunk0, (void*)&Thunk1, (void*)&Thunk2, (void*)&Thunk3,
    (void*)&Thunk4, (void*)&Thunk5, (void*)&Thunk6, (void*)&Thunk7,
};


// La cadena de tooltip "PLURALITY_CHANGE" está harcodeada en el exe y
// siempre se arma como "<localización>: <número>" — recortar su
// ensamblado dentro del motor es riesgoso (cerca hay bytes de estado
// de desenrollado de pila de excepciones C++ para std::string
// temporales). En cambio, el texto de localización ya está vaciado
// (localisation/*.csv), y de la cadena queda un número desnudo tipo
// "0.00" en una línea aparte. Quitamos esas líneas ya del texto final
// del tooltip, después de que el original lo construyó.
static bool IsBareNumberLine(const char* s, size_t len)
{
    // La etiqueta vacía en localización se guarda como un solo espacio
    // (si no, el juego pone en su lugar la clave cruda), así que la
    // línea se ve como " : 0.00" — también saltamos espacios/tabs/dos
    // puntos al principio.
    while (len && (s[0] == ' ' || s[0] == '\t' || s[0] == ':'))
    {
        ++s;
        --len;
    }
    while (len && (s[len - 1] == ' ' || s[len - 1] == '\t' || s[len - 1] == '\r'))
        --len;

    if (len == 0)
        return false;

    bool sawDigit = false;
    size_t i = 0;
    while (i < len)
    {
        unsigned char c = (unsigned char)s[i];

        // Código de color de Paradox: 0xA7 + un byte (ej. §G...§!) —
        // invisible en pantalla, se saltea tal cual.
        if (c == 0xA7 && i + 1 < len)
        {
            i += 2;
            continue;
        }

        if (c >= '0' && c <= '9')
        {
            sawDigit = true;
            ++i;
            continue;
        }
        if (c == '.' || c == '-' || c == '+')
        {
            ++i;
            continue;
        }
        return false;
    }
    return sawDigit;
}

static void StripBareNumberLines(void* retBuf)
{
    const char* text = GStrText(retBuf);
    if (!text || !*text)
        return;

    char buf[1024];
    size_t n = strlen(text);
    if (n >= sizeof(buf))
        n = sizeof(buf) - 1;
    memcpy(buf, text, n);
    buf[n] = 0;

    char out[1024];
    size_t o = 0;
    size_t lineStart = 0;

    for (size_t i = 0; i <= n; ++i)
    {
        if (i == n || buf[i] == '\n')
        {
            size_t lineLen = i - lineStart;
            if (!IsBareNumberLine(buf + lineStart, lineLen))
            {
                memcpy(out + o, buf + lineStart, lineLen);
                o += lineLen;
                if (i < n)
                    out[o++] = '\n';
            }
            lineStart = i + 1;
        }
    }
    out[o] = 0;

    GStrSet(retBuf, out);
}


// Tooltip sobre el elemento. Se llama después del original: este pone
// su texto en retBuf.
static void OnTooltip(int viewIndex, void* retBuf, void* element)
{
    if (!retBuf || !element)
        return;

    const char* name = GStrText(VCall0(element, VT_GET_NAME));

    if (viewIndex == VIEW_POLITICS && strcmp(name, "plurality") == 0)
        StripBareNumberLines(retBuf);
}


// ---------------------------------------------------------------
// Suscripción de botones
// ---------------------------------------------------------------

static bool SetupButtons(int viewIndex, void* view)
{
    const ViewDef& vd = VIEWS[viewIndex];
    unsigned char* v = (unsigned char*)view;

    void* container = *(void**)(v + vd.offContainer);
    if (!container)
    {
        Log("Setup[%s]: contenedor vacío", vd.name);
        return false;
    }

    void* host = container;

    if (vd.window)
    {
        GStr sWindow;
        MakeStr(&sWindow, g_nameStorage, sizeof(g_nameStorage), vd.window);

        host = VCall1(container, VT_FIND_WINDOW, &sWindow);
        if (!host)
        {
            Log("Setup[%s]: ventana '%s' no encontrada", vd.name, vd.window);
            return false;
        }
    }

    int done = 0;

    for (int i = 0; i < BUTTON_COUNT && i < MAX_BUTTONS; ++i)
    {
        if (BUTTONS[i].view != viewIndex)
            continue;

        GStr sButton;
        MakeStr(&sButton, g_nameStorage, sizeof(g_nameStorage), BUTTONS[i].button);

        void* button = VCall1(host, VT_FIND_CHILD, &sButton);
        if (!button)
        {
            Log("Setup[%s]: botón '%s' no encontrado", vd.name, BUTTONS[i].button);
            continue;
        }

        // Cada botón tiene su propio clon del glue con su propio manejador.
        memcpy(g_glue[i], v + vd.offGlue, GLUE_SIZE);
        *(void**)(g_glue[i] + OFF_GLUE_METHOD) = THUNKS[i];

        void* observable = (unsigned char*)button + OFF_OBSERVABLE;
        VCall1(observable, VT_ADD_OBSERVER, g_glue[i]);

        Log("Setup[%s]: '%s' suscripto", vd.name, BUTTONS[i].button);
        ++done;
    }

    return done > 0;
}


// ---------------------------------------------------------------
// Botón "Ocultar colonias" en la ventana de producción (pestaña "Fábricas").
//
// Suscripción propia, separada del sistema BUTTONS[]/THUNKS[]: ese
// sistema apunta a MakeDecision, y acá hace falta un flag normal más
// un redibujado de lista.
// El glue se toma de offGlue (para CProductionView es 0x120 —
// encontrado en el constructor FUN_006ee930: param_1[0x48] es el
// único CButtonObserverGlue<CProductionView> ahí, cuyo callback es la
// propia FUN_006f83b0, manejador de clics de los botones de la
// fábrica), pero se clona y parchea a mano, aparte de g_glue[]/
// THUNKS[], para no tocar el sistema de decisiones existente.
//
// FUN_006f3e70 (actualización de la lista de la pestaña "Fábricas")
// lee "this" no de ECX/stack sino de EDI, que queda de la función que
// la llamó (FUN_006f83b0, manejador de clics de los botones de esa
// pestaña) — por eso la llamamos nosotros mismos, poniendo EDI a mano.
// ---------------------------------------------------------------

static bool          g_hideColonialStates = false;
static void*         g_hideColonialView = 0;
static void*         g_hideColonialConfiguredView = 0;
static unsigned char g_hideColonialGlue[GLUE_SIZE];

static const DWORD RVA_PRODUCTION_REFRESH_FACTORIES = 0x2F3E70;  // FUN_006f3e70

static void __cdecl OnHideColonialClicked()
{
    g_hideColonialStates = !g_hideColonialStates;
    Log("HideColonialStates: %s", g_hideColonialStates ? "activado" : "desactivado");

    if (!g_hideColonialView)
        return;

    void* view = g_hideColonialView;
    void* fn = (void*)(g_base + RVA_PRODUCTION_REFRESH_FACTORIES);

    __asm {
        pushad
        mov edi, view
        call fn
        popad
    }
}

__declspec(naked) static void HideColonialThunk()
{
    __asm {
        push ebp
        mov ebp, esp
        pushad
        call OnHideColonialClicked
        popad
        mov esp, ebp
        pop ebp
        ret
    }
}

static bool SetupHideColonialButton(void* view)
{
    unsigned char* v = (unsigned char*)view;
    const ViewDef& vd = VIEWS[2];  // CProductionView

    void* container = *(void**)(v + vd.offContainer);
    if (!container)
        return false;

    GStr sWindow;
    MakeStr(&sWindow, g_nameStorage, sizeof(g_nameStorage), "factory_buttons");

    void* host = VCall1(container, VT_FIND_WINDOW, &sWindow);
    if (!host)
    {
        Log("SetupHideColonialButton: ventana 'factory_buttons' no encontrada");
        return false;
    }

    GStr sButton;
    MakeStr(&sButton, g_nameStorage, sizeof(g_nameStorage), "hide_colonial_states");

    void* button = VCall1(host, VT_FIND_CHILD, &sButton);
    if (!button)
    {
        Log("SetupHideColonialButton: botón 'hide_colonial_states' no encontrado");
        return false;
    }

    memcpy(g_hideColonialGlue, v + vd.offGlue, GLUE_SIZE);
    *(void**)(g_hideColonialGlue + OFF_GLUE_METHOD) = HideColonialThunk;

    void* observable = (unsigned char*)button + OFF_OBSERVABLE;
    VCall1(observable, VT_ADD_OBSERVER, g_hideColonialGlue);

    g_hideColonialView = view;

    Log("SetupHideColonialButton: suscripto");
    return true;
}


// ---------------------------------------------------------------
// Visibilidad de filas en la lista de la pestaña "Fábricas" (FUN_006f3e70).
//
// Bifurcación (abs. 0x6F424B, RVA 0x2F424B):
//   CMP dword ptr[ECX+0x84],0 ; JLE +8   (ECX = puntero al state, ya
//   cargado por el código llamante un poco antes)
//   CMP ESI,EBX ; JZ <saltear fila>  (ESI = cantidad de fábricas ya
//   construidas de esa categoría en la región)
// Vainilla: una región colonial sin fábricas construidas se saltea
// incondicionalmente, sin pasar siquiera por la verificación normal
// de "Ocultar libres" (esa parte ya está neutralizada — la
// condición colonial en sí dejó de ser una condición aparte).
// Acá agregamos un tercer flag propio: si g_hideColonialStates está
// activado, la región colonial se oculta siempre, sin importar
// "Ocultar libres" ni si hay fábricas construidas — tal como pidió
// el usuario.
// ---------------------------------------------------------------

static const DWORD RVA_PRODLIST_HOOK = 0x2F424B;
static const DWORD RVA_PRODLIST_RESUME_SHOW = 0x2F4255;
static const DWORD RVA_PRODLIST_RESUME_SKIP = 0x2F42DE;
// Solo verificamos los primeros 2 bytes (JLE +8) — el mismo ancla ya
// confirmada como funcional en la versión 2.8 con un simple parche de
// bytes. Los bytes 3-10 (CMP ESI,EBX ; JZ) se sobrescriben a ciegas -
// su codificación (39 DE o 3B F3 para CMP registro-registro — no
// verificado directamente) no le importa a nuestra lógica; el código
// viejo ahí ya no se ejecuta.
static const unsigned char PRODLIST_SIG[2] = { 0x7E, 0x08 };
static DWORD g_prodListResumeShow = 0;
static DWORD g_prodListResumeSkip = 0;

__declspec(naked) static void ProdListVisibilityThunk()
{
    __asm {
        cmp byte ptr [g_hideColonialStates], 0
        jz show
        cmp dword ptr [ecx + 0x84], 0
        jle show
        jmp dword ptr [g_prodListResumeSkip]
        show:
        jmp dword ptr [g_prodListResumeShow]
    }
}

static bool InstallProdListVisibilityHook()
{
    unsigned char* hook = (unsigned char*)(g_base + RVA_PRODLIST_HOOK);

    if (memcmp(hook, PRODLIST_SIG, sizeof(PRODLIST_SIG)) != 0)
    {
        Log("ProdListVisibilityHook: la firma no coincide - no se parchea");
        return false;
    }

    g_prodListResumeShow = g_base + RVA_PRODLIST_RESUME_SHOW;
    g_prodListResumeSkip = g_base + RVA_PRODLIST_RESUME_SKIP;

    unsigned char patch[10];
    patch[0] = 0xE9;
    *(DWORD*)(patch + 1) = (DWORD)(DWORD_PTR)&ProdListVisibilityThunk - ((DWORD)hook + 5);
    for (int i = 5; i < 10; ++i)
        patch[i] = 0x90;

    DWORD oldProtect = 0;
    if (!VirtualProtect(hook, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    memcpy(hook, patch, sizeof(patch));
    VirtualProtect(hook, sizeof(patch), oldProtect, &oldProtect);

    Log("ProdListVisibilityHook: instalado");
    return true;
}


// ---------------------------------------------------------------
// Prohibir fábricas concretas en colonias según limit_by_local_supply.
//
// FUN_004d04b0(param_1=state, param_2=tipo_producción, param_3)
// — la única verificación que realmente decide el destino del botón
// "Construir" (ver build_confirm_ignore_colonial). Adentro,
// param_2+0x58 guarda el número de orden del tipo de producción en
// production_types.txt — confirmado en vivo mediante diagnóstico:
// los valores reales 2/29/35 coincidieron con automobile_factory/
// fertilizer_factory/fishing_wharf al contar SIN incluir bloques
// "template" (bloques cuyo nombre aparece como valor de
// "template = X" en algún lugar del archivo).
//
// Leemos production_types.txt nosotros mismos (junto a la DLL, con
// verificación de mod\2\common\ como override prioritario) y armamos
// una tabla "está permitido construir en colonia" por ese mismo
// índice: permitido si el tipo tiene explícitamente
// limit_by_local_supply = yes.
// ---------------------------------------------------------------

static const int MAX_PRODUCTION_TYPES = 512;
static unsigned char g_limitByLocalSupply[MAX_PRODUCTION_TYPES];
static bool g_productionTypesLoaded = false;

// El runtime del juego asigna a cada tipo de producción SU PROPIO
// número interno (campo +0x58 del objeto tipo), que NO coincide con
// el orden de declaración en production_types.txt - confirmado por
// medición (cattle_factory en el archivo va con el número 51, pero en
// runtime su objeto lleva [+0x58]=1). Por eso no comparamos por
// índice sino por nombre: guardamos el nombre de cada tipo al
// parsear el archivo y en runtime buscamos coincidencia con la
// cadena que el motor guarda en el propio objeto tipo en el
// desplazamiento +0x20.
static const int PRODTYPE_NAME_MAX = 32;
static char g_productionTypeNames[MAX_PRODUCTION_TYPES][PRODTYPE_NAME_MAX];
static int  g_productionTypeCount = 0;

static const int OFF_PRODTYPE_NAME = 0x20;

static void GetOwnDllDirectory(char* outDir, size_t outSize)
{
    outDir[0] = 0;

    HMODULE hMod = 0;
    if (!GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)&GetOwnDllDirectory, &hMod))
        return;

    char path[MAX_PATH];
    if (!GetModuleFileNameA(hMod, path, sizeof(path)))
        return;

    char* lastSlash = strrchr(path, '\\');
    if (!lastSlash)
        return;

    *lastSlash = 0;
    strncpy_s(outDir, outSize, path, _TRUNCATE);
}

static bool IsIdentChar(char c)
{
    return isalnum((unsigned char)c) || c == '_';
}

// Lee el archivo completo en un buffer estático. Devuelve false si el
// archivo no existe o no entra.
static bool ReadWholeFile(const char* path, char* buf, size_t bufSize, size_t* outLen)
{
    FILE* f = 0;
    if (fopen_s(&f, path, "rb") != 0 || !f)
        return false;

    *outLen = fread(buf, 1, bufSize - 1, f);
    buf[*outLen] = 0;
    fclose(f);
    return true;
}

static void ParseProductionTypes(const char* text, size_t len)
{
    // Pasada 1: juntar los nombres de bloques usados como
    // "template = X" (esos en sí no son tipos de producción y no
    // participan en la numeración).
    static char templateNames[256][64];
    int templateCount = 0;

    for (size_t i = 0; i + 8 < len; ++i)
    {
        if (strncmp(text + i, "template", 8) != 0)
            continue;
        if (i > 0 && IsIdentChar(text[i - 1]))
            continue;  // parte de un identificador más largo
            if (IsIdentChar(text[i + 8]))
                continue;  // también parte de un identificador más largo (por el final)

                size_t p = i + 8;
            while (p < len && (text[p] == ' ' || text[p] == '\t'))
                ++p;
        if (p >= len || text[p] != '=')
            continue;
        ++p;
        while (p < len && (text[p] == ' ' || text[p] == '\t'))
            ++p;

        size_t nameStart = p;
        while (p < len && IsIdentChar(text[p]))
            ++p;
        size_t nameLen = p - nameStart;

        if (nameLen > 0 && nameLen < 64 && templateCount < 256)
        {
            memcpy(templateNames[templateCount], text + nameStart, nameLen);
            templateNames[templateCount][nameLen] = 0;
            ++templateCount;
        }
    }

    // Pasada 2: bloques de nivel superior "name = { ... }" en orden;
    // saltamos comentarios (# hasta fin de línea) y templates.
    int index = 0;
    int depth = 0;
    size_t i = 0;

    while (i < len)
    {
        char c = text[i];

        if (c == '#')
        {
            while (i < len && text[i] != '\n' && text[i] != '\r')
                ++i;
            continue;
        }

        if (depth == 0 && IsIdentChar(c) && (i == 0 || !IsIdentChar(text[i - 1])))
        {
            size_t nameStart = i;
            size_t p = i;
            while (p < len && IsIdentChar(text[p]))
                ++p;
            size_t nameLen = p - nameStart;

            size_t q = p;
            while (q < len && (text[q] == ' ' || text[q] == '\t' || text[q] == '\r' || text[q] == '\n'))
                ++q;

            if (q < len && text[q] == '=')
            {
                ++q;
                while (q < len && (text[q] == ' ' || text[q] == '\t' || text[q] == '\r' || text[q] == '\n'))
                    ++q;

                if (q < len && text[q] == '{')
                {
                    // Encontramos un bloque de nivel superior. Buscamos el
                    // final (la '}' pareja), ignorando comentarios de paso
                    // para que una '{'/'}' suelta en un comentario no
                    // arruine el conteo de profundidad.
                    size_t blockStart = q;
                    size_t j = q;
                    int localDepth = 0;

                    while (j < len)
                    {
                        char cj = text[j];
                        if (cj == '#')
                        {
                            while (j < len && text[j] != '\n' && text[j] != '\r')
                                ++j;
                            continue;
                        }
                        if (cj == '{')
                            ++localDepth;
                            else if (cj == '}')
                            {
                                --localDepth;
                                if (localDepth == 0)
                                {
                                    ++j;
                                    break;
                                }
                            }
                            ++j;
                    }

                    bool isTemplate = false;
                    for (int t = 0; t < templateCount; ++t)
                    {
                        size_t tlen = strlen(templateNames[t]);
                        if (tlen == nameLen && strncmp(templateNames[t], text + nameStart, nameLen) == 0)
                        {
                            isTemplate = true;
                            break;
                        }
                    }

                    if (!isTemplate)
                    {
                        bool hasLimitFlag = false;

                        // Buscamos "limit_by_local_supply" ... "yes" dentro
                        // del rango [blockStart, j) de este bloque concreto.
                        // La longitud de "limit_by_local_supply" es 21
                        // caracteres (sin contar el nulo final - antes acá
                        // había un 22, que comparaba TAMBIÉN el terminador
                        // nulo del literal con el carácter real del archivo
                        // (normalmente un espacio), por lo que strncmp nunca
                        // coincidía y el flag no se encontraba nunca).
                        for (size_t k = blockStart; k + 21 < j; ++k)
                        {
                            if (strncmp(text + k, "limit_by_local_supply", 21) != 0)
                                continue;
                            if (k > 0 && IsIdentChar(text[k - 1]))
                                continue;
                            if (IsIdentChar(text[k + 21]))
                                continue;

                            size_t r = k + 21;
                            while (r < j && (text[r] == ' ' || text[r] == '\t'))
                                ++r;
                            if (r < j && text[r] == '=')
                            {
                                ++r;
                                while (r < j && (text[r] == ' ' || text[r] == '\t'))
                                    ++r;
                                if (r + 3 <= j && strncmp(text + r, "yes", 3) == 0 &&
                                    !IsIdentChar(text[r + 3]))
                                    hasLimitFlag = true;
                            }
                            break;
                        }

                        if (index < MAX_PRODUCTION_TYPES)
                        {
                            g_limitByLocalSupply[index] = hasLimitFlag ? 1 : 0;

                            size_t copyLen = nameLen < (size_t)(PRODTYPE_NAME_MAX - 1)
                            ? nameLen : (size_t)(PRODTYPE_NAME_MAX - 1);
                            memcpy(g_productionTypeNames[index], text + nameStart, copyLen);
                            g_productionTypeNames[index][copyLen] = 0;

                            g_productionTypeCount = index + 1;
                        }

                        Log("  [%d] %.*s limit=%d", index, (int)nameLen, text + nameStart,
                            hasLimitFlag ? 1 : 0);

                        ++index;
                    }

                    i = j;
                    continue;
                }
            }

            i = p;
            continue;
        }

        if (c == '{')
            ++depth;
            else if (c == '}')
                --depth;

        ++i;
    }

    Log("ParseProductionTypes: se analizaron %d tipos de producción (templates omitidos: %d)",
        index, templateCount);
}

static void LoadProductionTypeLimits()
{
    if (g_productionTypesLoaded)
        return;
    g_productionTypesLoaded = true;

    for (int i = 0; i < MAX_PRODUCTION_TYPES; ++i)
        g_limitByLocalSupply[i] = 1;  // fallback seguro: índice desconocido - se permite

        char dir[MAX_PATH];
    GetOwnDllDirectory(dir, sizeof(dir));
    if (!dir[0])
    {
        Log("LoadProductionTypeLimits: no se pudo determinar el directorio de la DLL");
        return;
    }

    static char fileBuf[1 << 20];
    size_t fileLen = 0;
    char path[MAX_PATH];

    sprintf_s(path, sizeof(path), "%s\\mod\\2\\common\\production_types.txt", dir);
    bool ok = ReadWholeFile(path, fileBuf, sizeof(fileBuf), &fileLen);

    if (!ok)
    {
        sprintf_s(path, sizeof(path), "%s\\common\\production_types.txt", dir);
        ok = ReadWholeFile(path, fileBuf, sizeof(fileBuf), &fileLen);
    }

    if (!ok)
    {
        Log("LoadProductionTypeLimits: production_types.txt no encontrado junto a la DLL");
        return;
    }

    Log("LoadProductionTypeLimits: leyendo '%s' (%u bytes)", path, (unsigned)fileLen);
    ParseProductionTypes(fileBuf, fileLen);
}

// Bifurcación dentro de FUN_004d04b0 (abs. 0x4D04BC, RVA 0xD04BC):
//   CMP dword ptr[ECX+0x84],0 ; PUSH EBX ; PUSH ESI ; PUSH EDI
//   ; JLE +8 (0xD04C6, -> 0xD04D3 continuación) ; si no, 0xD04C8: XOR AL,AL (return false)
//
// IMPORTANTE: 0xD04C8 NO es solo el destino de nuestra verificación.
// En el resto de la función hay OTRA DECENA de condiciones distintas
// que saltan justo ahí como "return false" genérico (disponibilidad
// del bien, permiso del partido gobernante, límite de fábricas, etc).
// La primera versión del parche sobrescribía por error 8 bytes
// EMPEZANDO DESDE JLE — eso borraba también el propio 0xD04C8,
// rompiendo TODAS esas verificaciones sin relación (crash en
// cualquier llamada a la función, lo que explicaba el cuelgue al
// cargar la partida). El parche correcto se pone MÁS ATRÁS, desde el
// propio CMP (10 bytes hasta el JLE inclusive: CMP+PUSH EBX+PUSH
// ESI+PUSH EDI), y NO toca 0xD04C6+ para nada — por eso 0xD04C8 queda
// intacto, y el camino "bloqueado" simplemente salta ahí como siempre.
static const DWORD RVA_PRODTYPE_GATE_HOOK = 0xD04BC;
static const DWORD RVA_PRODTYPE_GATE_RESUME_ALLOW = 0xD04D3;
static const DWORD RVA_PRODTYPE_GATE_RESUME_BLOCK = 0xD04C8;
static const unsigned char PRODTYPE_GATE_SIG[10] =
{ 0x83, 0xB9, 0x84, 0x00, 0x00, 0x00, 0x00, 0x53, 0x56, 0x57 };
static DWORD g_prodTypeGateResumeAllow = 0;
static DWORD g_prodTypeGateResumeBlock = 0;

// El puntero param_2 ([EBP+0xC] dentro de FUN_004d04b0) es justamente
// el objeto del tipo de producción; el nombre del tipo (como en
// production_types.txt) se guarda en el propio objeto en el
// desplazamiento OFF_PRODTYPE_NAME como cadena C normal. Comparamos
// esa cadena con los nombres guardados al parsear el archivo, y
// miramos el índice encontrado por nombre en g_limitByLocalSupply -
// NO leemos el índice numérico del propio objeto (ver el comentario
// junto a la declaración de g_productionTypeNames: no coincide con
// el del archivo). Excepciones puntuales además de
// limit_by_local_supply: tipos a los que también hay que permitirles
// construir en colonia, pero no se armó un flag aparte en
// production_types.txt para ellos - el parche es solo por nombre.
// Por ahora es fishery (is_coastal = yes).
static const char* const PRODTYPE_EXTRA_WHITELIST[] = { "fishery" };
static const int PRODTYPE_EXTRA_WHITELIST_COUNT =
sizeof(PRODTYPE_EXTRA_WHITELIST) / sizeof(PRODTYPE_EXTRA_WHITELIST[0]);

static int __cdecl IsProdTypeWhitelistedByName(void* typePtr)
{
    if (!typePtr)
        return 0;

    const char* src = (const char*)typePtr + OFF_PRODTYPE_NAME;
    char name[PRODTYPE_NAME_MAX];

    int i = 0;
    for (; i < PRODTYPE_NAME_MAX - 1; ++i)
    {
        char c = src[i];
        if (c == 0)
            break;
        name[i] = c;
    }
    name[i] = 0;

    for (int e = 0; e < PRODTYPE_EXTRA_WHITELIST_COUNT; ++e)
        if (strcmp(PRODTYPE_EXTRA_WHITELIST[e], name) == 0)
            return 1;

    for (int t = 0; t < g_productionTypeCount; ++t)
    {
        if (strcmp(g_productionTypeNames[t], name) == 0)
            return g_limitByLocalSupply[t] ? 1 : 0;
    }
    return 0;
}

static DWORD g_prodTypeGateWhitelisted = 0;

__declspec(naked) static void ProdTypeGateThunk()
{
    __asm {
        // Primero, ANTES de reproducir los bytes sobrescritos y de
        // ramificar, calculamos en un bloque aislado "está permitido
        // por nombre". Guardamos ECX (state) con un solo par
        // push/pop para todo el bloque - igual que hacía un
        // diagnóstico anterior que funcionó sin fallos; push/pop
        // anidados alrededor de una llamada a función C EN MEDIO de
        // lógica ya ramificada (versión anterior del parche) en la
        // práctica hacían caer el juego al cargar la partida - no se
        // determinó exactamente cómo, pero la estructura "una
        // llamada - un save/restore - recién después ramificar" está
        // probada y es segura.
        push ecx

        mov eax, dword ptr [ebp + 0x0c]
        test eax, eax
        jz faulty_allow
        push 0x5C
        push eax
        mov edx, g_fnIsBadReadPtr
        test edx, edx
        jz faulty_allow_clean8
        call edx
        test eax, eax
        jnz faulty_allow
        push dword ptr [ebp + 0x0c]
        call IsProdTypeWhitelistedByName
        add esp, 4
        jmp store_result
        faulty_allow_clean8:
        add esp, 8
        faulty_allow:
        mov eax, 1   // puntero malo/vacío - fallback seguro: se permite, como antes
        store_result:
        mov dword ptr [g_prodTypeGateWhitelisted], eax

        pop ecx

        // Reproducimos los bytes sobrescritos (esto NO es destino de
        // saltos externos, así que se puede ejecutar tranquilamente acá).
        cmp dword ptr [ecx + 0x84], 0
        push ebx
        push esi
        push edi
        jle allow
        cmp dword ptr [g_prodTypeGateWhitelisted], 0
        jnz allow
        jmp dword ptr [g_prodTypeGateResumeBlock]
        allow:
        jmp dword ptr [g_prodTypeGateResumeAllow]
    }
}

static bool InstallProdTypeGateHook()
{
    LoadProductionTypeLimits();

    g_fnIsBadReadPtr = (tIsBadReadPtr)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsBadReadPtr");
    if (!g_fnIsBadReadPtr)
        Log("ProdTypeGateHook: IsBadReadPtr no encontrado - verificación de seguridad del puntero desactivada");

    unsigned char* hook = (unsigned char*)(g_base + RVA_PRODTYPE_GATE_HOOK);

    if (memcmp(hook, PRODTYPE_GATE_SIG, sizeof(PRODTYPE_GATE_SIG)) != 0)
    {
        Log("ProdTypeGateHook: la firma no coincide - no se parchea");
        return false;
    }

    g_prodTypeGateResumeAllow = g_base + RVA_PRODTYPE_GATE_RESUME_ALLOW;
    g_prodTypeGateResumeBlock = g_base + RVA_PRODTYPE_GATE_RESUME_BLOCK;

    unsigned char patch[10];
    patch[0] = 0xE9;
    *(DWORD*)(patch + 1) = (DWORD)(DWORD_PTR)&ProdTypeGateThunk - ((DWORD)hook + 5);
    for (int i = 5; i < 10; ++i)
        patch[i] = 0x90;

    DWORD oldProtect = 0;
    if (!VirtualProtect(hook, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    memcpy(hook, patch, sizeof(patch));
    VirtualProtect(hook, sizeof(patch), oldProtect, &oldProtect);

    Log("ProdTypeGateHook: instalado");
    return true;
}


// ---------------------------------------------------------------
// Slots reemplazados de las vistas
// ---------------------------------------------------------------

// Slot Update: __thiscall sin argumentos en el stack, ret plano.
typedef void(__fastcall* tUpdate)(void* ecx, void* edx);

// Slot de tooltip: __thiscall con dos argumentos en el stack y ret 8 —
// buffer para el resultado y elemento bajo el cursor.
typedef void* (__fastcall* tTooltip)(void* ecx, void* edx, void* retBuf, void* element);

static void* g_origSlot[MAX_VIEWS] = { 0 };
static void* g_configuredView[MAX_VIEWS] = { 0 };
static int   g_updateSeen[MAX_VIEWS] = { 0 };

static void OnViewUpdate(int viewIndex, void* view)
{
    if (!view)
        return;

    if (g_updateSeen[viewIndex] < 2)
    {
        ++g_updateSeen[viewIndex];
        Log("Update[%s]: llamado, view=%08X",
            VIEWS[viewIndex].name, (DWORD)(DWORD_PTR)view);
    }

    // El puntero cambió — la vista se recreó, por ejemplo por una nueva partida.
    if (view == g_configuredView[viewIndex])
        return;

    if (g_settings.buttons && SetupButtons(viewIndex, view))
        g_configuredView[viewIndex] = view;

    if (viewIndex == 2 && view != g_hideColonialConfiguredView)
    {
        if (SetupHideColonialButton(view))
            g_hideColonialConfiguredView = view;
    }
}

#define VIEW_THUNKS(n)                                              \
static void __fastcall Update##n(void* view, void* edx)         \
{                                                               \
    if (n < VIEW_COUNT)                                         \
        OnViewUpdate(n, view);                                  \
        if (g_origSlot[n])                                          \
            ((tUpdate)g_origSlot[n])(view, 0);                      \
}                                                               \
static void* __fastcall Tip##n(void* view, void* edx,           \
void* retBuf, void* element)     \
{                                                               \
    if (n < VIEW_COUNT)                                         \
        OnViewUpdate(n, view);                                  \
        void* result = g_origSlot[n]                                \
        ? ((tTooltip)g_origSlot[n])(view, 0, retBuf, element)    \
        : retBuf;                                               \
        OnTooltip(n, result, element);                               \
        return result;                                              \
}

VIEW_THUNKS(0) VIEW_THUNKS(1) VIEW_THUNKS(2) VIEW_THUNKS(3)

static void* const UPDATE_THUNKS[MAX_VIEWS] =
{
    (void*)&Update0, (void*)&Update1, (void*)&Update2, (void*)&Update3,
};

static void* const TOOLTIP_THUNKS[MAX_VIEWS] =
{
    (void*)&Tip0, (void*)&Tip1, (void*)&Tip2, (void*)&Tip3,
};


// ---------------------------------------------------------------
// Filtro de la lista de decisiones
//
// El slot 0x18 en la vtable de CDecision es un stub que siempre
// devolvía 1. El motor lo llama tanto al dibujar la lista como al
// ejecutar, así que distinguimos por la dirección de retorno: es
// determinística e igual en todas las máquinas, a diferencia del
// timer, que rompía el multijugador.
// ---------------------------------------------------------------

typedef char(__fastcall* tIsValid)(void* ecx, void* edx);
static tIsValid g_origIsValid = 0;

static const int OFF_DECISION_NAME = 0x08;

static const char* DecisionName(void* decision)
{
    const char* p = (const char*)decision + OFF_DECISION_NAME;

    unsigned res = *(const unsigned*)(p + 0x14);
    unsigned size = *(const unsigned*)(p + 0x10);

    // Verificación grosera de sensatez: los nombres de decisión son
    // cortos, y la capacidad nunca es menor que la longitud.
    if (size > 250 || res < size)
        return "";

    if (res > 15)
    {
        p = *(const char* const*)p;
        if (!p)
            return "";
    }

    return p;
}

static char __fastcall MyDecisionIsValid(void* decision, void* edx)
{
    if (!decision)
        return 1;

    const char* name = DecisionName(decision);
    if (!*name)
        return 1;

    bool mine = false;
    for (int i = 0; i < BUTTON_COUNT; ++i)
    {
        if (strcmp(name, BUTTONS[i].decision) == 0)
        {
            mine = true;
            break;
        }
    }

    if (!mine)
        return 1;

    DWORD caller = (DWORD)(DWORD_PTR)_ReturnAddress();
    bool fromList = caller >= g_base + RVA_POLITICS_DRAW_BEGIN
    && caller < g_base + RVA_POLITICS_DRAW_END;

    return fromList ? 0 : 1;
}




// ---------------------------------------------------------------
// Paso porcentual de cambio de precio
//
// De fábrica el paso es fijo: en 0x0125B9E0 hay un int64 = 328, es
// decir 0.01 en punto fijo (0.01 * 2^15). Interceptamos el lugar
// donde en ECX:EAX ya está el precio actual, y reescribimos la
// constante como una fracción de ese precio. Nadie más lee esa
// constante aparte de esta función.
//
// La aritmética es entera, no depende del tiempo ni del orden de
// eventos: con la misma DLL todos los clientes obtienen un resultado
// idéntico bit a bit.
// ---------------------------------------------------------------

// Paso en centésimas de porcentaje: 25 = 0.25% por día, 100 = 1%.
static const int PRICE_BASIS_POINTS = 25;

static const DWORD PRICE_MUL = (DWORD)((PRICE_BASIS_POINTS * 65536LL) / 10000);

static const DWORD RVA_PRICE_HOOK = 0x82BA9;   // SAR EDX,0Fh
static const DWORD RVA_PRICE_RESUME = 0x82BAE;   // SUB EDI,[delta]
static const DWORD RVA_PRICE_DELTA = 0xE5B9E0;  // int64, palabra baja

static const unsigned char PRICE_SIG[5] = { 0xC1, 0xFA, 0x0F, 0x8B, 0xF8 };

static bool InstallPriceDelta()
{
    unsigned char* hook = (unsigned char*)(g_base + RVA_PRICE_HOOK);

    if (memcmp(hook, PRICE_SIG, sizeof(PRICE_SIG)) != 0)
    {
        Log("PriceDelta: la firma no coincide - no se parchea");
        return false;
    }

    unsigned char* cave = (unsigned char*)VirtualAlloc(
        0, 128, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!cave)
        return false;

    DWORD deltaLo = g_base + RVA_PRICE_DELTA;
    DWORD deltaHi = deltaLo + 4;

    int n = 0;

    // Restauramos lo que tapó el salto.
    cave[n++] = 0xC1; cave[n++] = 0xFA; cave[n++] = 0x0F;   // sar edx, 0Fh
    cave[n++] = 0x8B; cave[n++] = 0xF8;                     // mov edi, eax

    // EAX y ECX son el precio, EDX es el precio objetivo; MUL pisa EDX.
    cave[n++] = 0x50;                                       // push eax
    cave[n++] = 0x51;                                       // push ecx
    cave[n++] = 0x52;                                       // push edx

    cave[n++] = 0xB9;                                       // mov ecx, PRICE_MUL
    *(DWORD*)(cave + n) = PRICE_MUL; n += 4;
    cave[n++] = 0xF7; cave[n++] = 0xE1;                     // mul ecx
    cave[n++] = 0x0F; cave[n++] = 0xAC; cave[n++] = 0xD0;
    cave[n++] = 0x10;                                       // shrd eax, edx, 16
    cave[n++] = 0xC1; cave[n++] = 0xEA; cave[n++] = 0x10;   // shr edx, 16

    // En bienes baratos la fracción se redondea a cero, y el precio se
    // quedaría congelado.
    cave[n++] = 0x85; cave[n++] = 0xD2;                     // test edx, edx
    cave[n++] = 0x75; cave[n++] = 0x05;                     // jnz store
    cave[n++] = 0x85; cave[n++] = 0xC0;                     // test eax, eax
    cave[n++] = 0x75; cave[n++] = 0x01;                     // jnz store
    cave[n++] = 0x40;                                       // inc eax

    cave[n++] = 0xA3;                                       // mov [deltaLo], eax
    *(DWORD*)(cave + n) = deltaLo; n += 4;
    cave[n++] = 0x89; cave[n++] = 0x15;                     // mov [deltaHi], edx
    *(DWORD*)(cave + n) = deltaHi; n += 4;

    cave[n++] = 0x5A;                                       // pop edx
    cave[n++] = 0x59;                                       // pop ecx
    cave[n++] = 0x58;                                       // pop eax

    cave[n++] = 0xE9;                                       // jmp de vuelta
    *(DWORD*)(cave + n) = (g_base + RVA_PRICE_RESUME) - (DWORD)(cave + n + 4);
    n += 4;

    unsigned char patch[5];
    patch[0] = 0xE9;
    *(DWORD*)(patch + 1) = (DWORD)cave - ((DWORD)hook + 5);

    DWORD oldProtect = 0;
    if (!VirtualProtect(hook, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    memcpy(hook, patch, sizeof(patch));
    VirtualProtect(hook, sizeof(patch), oldProtect, &oldProtect);

    Log("PriceDelta: %d centésimas de porcentaje, multiplicador %u",
        PRICE_BASIS_POINTS, PRICE_MUL);
    return true;
}


// ---------------------------------------------------------------
// Parches de bytes del exe
//
// Los desplazamientos están dados como en los mods de exe de
// ZombieFreak115 — como desplazamientos en el ARCHIVO. Los
// traducimos vía la tabla de secciones PE en runtime.
// Los parches cambian la simulación, así que la DLL debe ser igual
// para todos.
// ---------------------------------------------------------------

// El parche se da por desplazamiento en el archivo (como en los mods
// de exe de ZombieFreak115), o directamente por RVA. Se rellena uno
// de los dos.
struct BytePatch
{
    const char* name;
    DWORD         fileOffset;
    DWORD         rva;
    int           len;
    unsigned char expect[8];
    unsigned char replace[8];
    bool          enabled;
};

static BytePatch EXE_PATCHES[] =
{
    // Debug alwaysaddwargoal siempre activado.
    { "always_add_wargoals", 0x137EFF, 0, 1, { 0x00 }, { 0x02 }, true },

    // naval_reinforce — sin corrimiento de dirección respecto al array anterior.
    { "naval_reinforce", 0x1C7F1C, 0, 1, { 0x89 }, { 0x8B }, true },

    // land_reinforce — sin corrimiento de dirección.
    { "land_reinforce", 0x1C809B, 0, 4, { 0x89, 0x4C, 0x24, 0x20 },
    { 0x90, 0x90, 0x90, 0x90 }, true },

    // consciousness_plurality_growth — dirección corrida (era 0x10C5DE, acá 0x10B9DE).
    { "consciousness_plurality_growth", 0x10B9DE, 0, 1, { 0x03 }, { 0x8B }, true },

    // allied_reinforce_150 — dirección corrida (era 0x1D74BE, acá 0x1D68BE).
    { "allied_reinforce_150", 0x1D68BE, 0, 5,
        { 0xB8, 0xE8, 0x03, 0x00, 0x00 },
        { 0xB8, 0xDC, 0x05, 0x00, 0x00 }, true },

        // build_factory_button_enable_ignore_colonial — dirección corrida (era 0x12E977, acá 0x12DD77).
        { "build_factory_button_enable_ignore_colonial", 0x12DD77, 0, 2,
            { 0x7F, 0x5F }, { 0x90, 0x90 }, true },

            // local_supply_factory_ignore_colonial — dirección corrida (era 0xD0E9D, acá 0xD029D).
            { "local_supply_factory_ignore_colonial", 0xD029D, 0, 2,
                { 0x7E, 0x35 }, { 0xEB, 0x35 }, true },

                // build_factory_ignore_uncivilized_button — dirección corrida (era 0x12E96E, acá 0x12DD6E).
                { "build_factory_ignore_uncivilized_button", 0x12DD6E, 0, 2,
                    { 0x74, 0x68 }, { 0x90, 0x90 }, true },

                    // build_factory_checklist_uncivilized_own — dirección corrida (era 0x12EA67, acá 0x12DE67).
                    { "build_factory_checklist_uncivilized_own", 0x12DE67, 0, 6,
                        { 0x8A, 0x86, 0xD0, 0x12, 0x00, 0x00 },
                        { 0xB0, 0x01, 0x90, 0x90, 0x90, 0x90 }, true },

                        // build_factory_checklist_uncivilized_other — dirección corrida (era 0x12F0D4, acá 0x12E4D4).
                        { "build_factory_checklist_uncivilized_other", 0x12E4D4, 0, 2,
                            { 0x74, 0x0C }, { 0x90, 0x90 }, true },

                            // build_factory_ignore_uncivilized_can_build (jump) — dirección corrida (era 0x12CA3E, acá 0x12BE3E).
                            { "build_factory_ignore_uncivilized_can_build", 0x12BE3E, 0, 2,
                                { 0x75, 0x08 }, { 0xEB, 0x08 }, true },

                                // human_player_patch (uncivilized tech studies) — dirección corrida (era 0x3AA757, acá 0x3A9B57).
                                // Solo cambia el primer byte del salto (75->EB); el desplazamiento 0x5A no se toca.
                                { "human_player_patch", 0x3A9B57, 0, 1, { 0x75 }, { 0xEB }, true },
};

static const int EXE_PATCH_COUNT = sizeof(EXE_PATCHES) / sizeof(EXE_PATCHES[0]);


// ---------------------------------------------------------------
// Carga/guardado de configuración (v2dll_settings.ini)
//
// Las claves ENABLE_* y las siete PATCH_* nombradas corrigen campos
// de g_settings. Cualquier otra clave PATCH_<NOMBRE> se busca (sin
// distinguir mayúsculas) en la tabla EXE_PATCHES de arriba y corrige
// el BytePatch::enabled de la entrada encontrada - por eso todo este
// bloque está declarado acá, después de la tabla, y no al principio
// del archivo.
// ---------------------------------------------------------------

static bool ParseBoolValue(const char* value)
{
    while (*value == ' ' || *value == '\t')
        ++value;
    return atoi(value) != 0;
}

static void ApplySetting(const char* key, const char* value)
{
    bool v = ParseBoolValue(value);

    if (_stricmp(key, "ENABLE_LOG") == 0)                  { g_settings.log            = v; return; }
    if (_stricmp(key, "ENABLE_BUTTONS") == 0)               { g_settings.buttons        = v; return; }
    if (_stricmp(key, "ENABLE_DECISION_FILTER") == 0)       { g_settings.decisionFilter = v; return; }
    if (_stricmp(key, "ENABLE_PRICE_DELTA") == 0)           { g_settings.priceDelta     = v; return; }
    if (_stricmp(key, "ENABLE_POP_DISPLAY") == 0)           { g_settings.popDisplay     = v; return; }
    if (_stricmp(key, "ENABLE_VERSION_LABEL") == 0)         { g_settings.versionLabel   = v; return; }

    if (_stricmp(key, "PATCH_OCCUPIED_REINFORCE_SPLIT") == 0) { g_settings.patchOccupiedReinforceSplit = v; return; }
    if (_stricmp(key, "PATCH_ALLY_OWNER_CHECK") == 0)          { g_settings.patchAllyOwnerCheck         = v; return; }
    if (_stricmp(key, "PATCH_CIVILIZE_NULL_CHECK") == 0)       { g_settings.patchCivilizeNullCheck      = v; return; }
    if (_stricmp(key, "PATCH_GRAPH_POINT_CLAMP") == 0)         { g_settings.patchGraphPointClamp        = v; return; }
    if (_stricmp(key, "PATCH_FACTORY_DUMP_SCAN") == 0)         { g_settings.patchFactoryDumpScan        = v; return; }
    if (_stricmp(key, "PATCH_PROD_LIST_VISIBILITY") == 0)      { g_settings.patchProdListVisibility     = v; return; }
    if (_stricmp(key, "PATCH_PROD_TYPE_GATE") == 0)            { g_settings.patchProdTypeGate           = v; return; }

    if (_strnicmp(key, "PATCH_", 6) == 0)
    {
        const char* patchName = key + 6;
        for (int i = 0; i < EXE_PATCH_COUNT; ++i)
        {
            if (_stricmp(EXE_PATCHES[i].name, patchName) == 0)
            {
                EXE_PATCHES[i].enabled = v;
                return;
            }
        }
    }
}

static void WriteDefaultSettings(const char* path)
{
    FILE* f = 0;
    if (fopen_s(&f, path, "w") != 0 || !f)
        return;

    fprintf(f,
            "; Configuracion de V2DLL. 1 = activado, 0 = desactivado.\n"
            "; Se edita a mano, sin recompilar la DLL - los cambios se\n"
            "; aplican en el proximo arranque del juego.\n"
            "\n"
            "ENABLE_LOG=%d                 ; log en v2dll.log (muchas entradas por tick, para distribuir poner 0)\n"
            "ENABLE_BUTTONS=%d             ; botones que lanzan decisiones\n"
            "ENABLE_DECISION_FILTER=%d     ; ocultamiento de decisiones en la ventana de politica\n"
            "ENABLE_PRICE_DELTA=%d         ; paso porcentual de cambio de precios\n"
            "ENABLE_POP_DISPLAY=%d         ; poblacion total en el panel superior (experimental)\n"
            "ENABLE_VERSION_LABEL=%d       ; version del mod en el subtitulo del menu principal\n",
            (int)g_settings.log, (int)g_settings.buttons, (int)g_settings.decisionFilter,
            (int)g_settings.priceDelta, (int)g_settings.popDisplay, (int)g_settings.versionLabel);

    fprintf(f,
            "\n"
            "; --- Parches de bytes del exe (lista = tabla EXE_PATCHES en\n"
            "; V2TechButton.cpp, ahi mismo esta la descripcion detallada de cada uno) ---\n");

    for (int i = 0; i < EXE_PATCH_COUNT; ++i)
    {
        char nameUpper[64];
        size_t nlen = strlen(EXE_PATCHES[i].name);
        if (nlen >= sizeof(nameUpper))
            nlen = sizeof(nameUpper) - 1;
        size_t j = 0;
        for (; j < nlen; ++j)
            nameUpper[j] = (char)toupper((unsigned char)EXE_PATCHES[i].name[j]);
        nameUpper[j] = '\0';

        fprintf(f, "PATCH_%s=%d\n", nameUpper, (int)EXE_PATCHES[i].enabled);
    }

    fprintf(f,
            "\n"
            "; --- Hooks individuales del exe (no estan en la tabla de arriba) ---\n"
            "PATCH_OCCUPIED_REINFORCE_SPLIT=%d   ; tasa propia de refuerzo occupied vs allied (afina ALLIED_REINFORCE_150)\n"
            "PATCH_ALLY_OWNER_CHECK=%d           ; tasa propia occupied-by-ally vs owned-by-ally (afina OCCUPIED_REINFORCE_SPLIT)\n"
            "PATCH_GRAPH_POINT_CLAMP=%d          ; clamp de puntos del grafico de presupuesto - arregla un crash por desborde de buffer, no se recomienda desactivar\n"
            "PATCH_FACTORY_DUMP_SCAN=%d          ; hilo de fondo que vuelca al log la memoria de fabricas monitoreadas (diagnostico, no afecta el gameplay)\n"
            "PATCH_PROD_LIST_VISIBILITY=%d       ; visibilidad de filas de la lista \"Fabricas\" (lo necesita el boton \"ocultar colonias\")\n"
            "PATCH_PROD_TYPE_GATE=%d             ; gate por production_types.txt para PATCH_LOCAL_SUPPLY_FACTORY_IGNORE_COLONIAL\n"
            "\n"
            "; IMPORTANTE: si esta activado cualquiera de los\n"
            "; PATCH_BUILD_FACTORY_IGNORE_UNCIVILIZED_* de arriba, manten\n"
            "; PATCH_CIVILIZE_NULL_CHECK tambien activado - es el parche que\n"
            "; arregla el crash del juego al civilizarse un pais (0xc0000005),\n"
            "; no es una configuracion independiente. Sin el, el crash vuelve\n"
            "; apenas un pais no civilizado con una fabrica construida se civilice.\n"
            "PATCH_CIVILIZE_NULL_CHECK=%d\n",
            (int)g_settings.patchOccupiedReinforceSplit,
            (int)g_settings.patchAllyOwnerCheck,
            (int)g_settings.patchGraphPointClamp,
            (int)g_settings.patchFactoryDumpScan,
            (int)g_settings.patchProdListVisibility,
            (int)g_settings.patchProdTypeGate,
            (int)g_settings.patchCivilizeNullCheck);

    fclose(f);
}

// Formato de línea: CLAVE=VALOR, un "; comentario" opcional al final
// de la línea no molesta al parseo (atoi se detiene en la primera
// posición no numérica). Las líneas sin '=' (vacías, comentarios) se
// saltean.
static void LoadSettings()
{
    static const char* PATH = "v2dll_settings.ini";

    FILE* f = 0;
    if (fopen_s(&f, PATH, "r") != 0 || !f)
    {
        WriteDefaultSettings(PATH);
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), f))
    {
        char* eq = strchr(line, '=');
        if (!eq)
            continue;

        *eq = '\0';
        const char* value = eq + 1;

        char key[64];
        size_t klen = strlen(line);
        if (klen >= sizeof(key))
            klen = sizeof(key) - 1;
        memcpy(key, line, klen);
        key[klen] = '\0';
        while (klen > 0 && (key[klen - 1] == ' ' || key[klen - 1] == '\t'))
            key[--klen] = '\0';

        ApplySetting(key, value);
    }

    fclose(f);
}


static DWORD FileOffsetToRVA(DWORD fileOffset)
{
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)g_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(g_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
    {
        DWORD start = sec->PointerToRawData;
        DWORD size = sec->SizeOfRawData;

        if (fileOffset >= start && fileOffset < start + size)
            return sec->VirtualAddress + (fileOffset - start);
    }

    return 0;
}


static void InstallExePatches()
{
    for (int i = 0; i < EXE_PATCH_COUNT; ++i)
    {
        BytePatch& bp = EXE_PATCHES[i];

        if (!bp.enabled)
            continue;

        DWORD rva = bp.rva ? bp.rva : FileOffsetToRVA(bp.fileOffset);
        if (!rva)
        {
            Log("Patch '%s': el desplazamiento %06X esta fuera de las secciones", bp.name, bp.fileOffset);
            continue;
        }

        unsigned char* at = (unsigned char*)(g_base + rva);

        if (memcmp(at, bp.expect, bp.len) != 0)
        {
            Log("Patch '%s': la firma no coincide - no se parchea", bp.name);
            continue;
        }

        DWORD oldProtect = 0;
        if (!VirtualProtect(at, bp.len, PAGE_EXECUTE_READWRITE, &oldProtect))
            continue;

        memcpy(at, bp.replace, bp.len);
        VirtualProtect(at, bp.len, oldProtect, &oldProtect);

        Log("Patch '%s': aplicado en rva %06X", bp.name, rva);
    }
}


// ---------------------------------------------------------------
// División de tasa de refuerzo: occupied vs allied
//
// allied_reinforce_150 de arriba corrige la ÚNICA instrucción mov
// eax,1000 en LAB_005d74bb (FUN_005d7420) — pero a ese punto llegan
// DOS ramas distintas: "controlamos nosotros mismos la provincia, y
// no es nuestro core" (occupied) y "provincia bajo control de un
// aliado, sin estar en guerra" (allied). El mov general afecta a
// ambas a la vez, no se puede separar sin ramificar (ver comentario
// arriba).
//
// Interceptamos la rama occupied ANTES de la fusión: "cmp
// edx,[ecx+0x20]; jz LAB_005d74bb" (rva 0x1D751B, 5 bytes) — esta es
// la verificación "dueño de la unidad == país que controla la
// provincia". Saltamos a la cueva, repetimos el cmp; si coincide
// (occupied) escribimos nuestra tasa y nos vamos al epílogo general
// de la función (rva 0x1D74C5, mov eax,ecx; pop edi; pop esi; pop
// ebx; mov esp,ebp; pop ebp; ret 4) — está DESPUÉS de la instrucción
// parcheada por allied_reinforce_150 y no se ve afectado por ella. Si
// no coincide (allied) repetimos el "mov esi,[ecx+0xbe8]"
// sobrescrito y saltamos de vuelta al código original (rva
// 0x1D7526) — esa rama sigue como antes y ella misma cae en
// LAB_005d74bb, donde la siguen esperando los 1500 (150.0%)
// parcheados por allied_reinforce_150.
// ---------------------------------------------------------------

static const int OCCUPIED_REINFORCE_RATE = 1000;   // 100.0%, como en vainilla

static const DWORD RVA_OCC_REINFORCE_HOOK   = 0x1D751B;   // cmp edx,[ecx+0x20]; jz
static const DWORD RVA_OCC_REINFORCE_RESUME = 0x1D7526;   // mov edx,[esi+edx*4] (continuación de la rama allied)
static const DWORD RVA_OCC_REINFORCE_TAIL   = 0x1D74C5;   // mov eax,ecx; pop edi; ...; ret 4
static const DWORD RVA_LAB_74BB             = 0x1D74BB;   // mov ecx,[ebp+8]; mov eax,1000(->1500) — LAB_005d74bb

static const unsigned char OCC_REINFORCE_SIG[5] =
{ 0x3B, 0x51, 0x20, 0x74, 0x9B };

static bool InstallOccupiedReinforceSplit()
{
    unsigned char* hook = (unsigned char*)(g_base + RVA_OCC_REINFORCE_HOOK);

    if (memcmp(hook, OCC_REINFORCE_SIG, sizeof(OCC_REINFORCE_SIG)) != 0)
    {
        Log("OccupiedReinforceSplit: la firma no coincide - no se parchea");
        return false;
    }

    unsigned char* cave = (unsigned char*)VirtualAlloc(
        0, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!cave)
        return false;

    int n = 0;

    // Repetimos los bytes tapados por el salto.
    cave[n++] = 0x3B; cave[n++] = 0x51; cave[n++] = 0x20;   // cmp edx,[ecx+0x20]

    int jzAt = n;
    cave[n++] = 0x74; cave[n++] = 0x00;                     // jz occupied (la dirección se completa abajo)

    // allied: restauramos el "mov esi,[ecx+0xbe8]" tapado y volvemos
    // al código original.
    cave[n++] = 0x8B; cave[n++] = 0xB1;
    *(DWORD*)(cave + n) = 0xBE8; n += 4;

    cave[n++] = 0xE9;                                       // jmp de vuelta (allied continúa como antes)
    *(DWORD*)(cave + n) = (g_base + RVA_OCC_REINFORCE_RESUME) - (DWORD)(cave + n + 4);
    n += 4;

    int occupiedAt = n;
    cave[jzAt + 1] = (unsigned char)(occupiedAt - (jzAt + 2));

    cave[n++] = 0x8B; cave[n++] = 0x4D; cave[n++] = 0x08;   // mov ecx,[ebp+8]
    cave[n++] = 0xB8;                                       // mov eax, OCCUPIED_REINFORCE_RATE
    *(DWORD*)(cave + n) = (DWORD)OCCUPIED_REINFORCE_RATE; n += 4;
    cave[n++] = 0x89; cave[n++] = 0x01;                     // mov [ecx],eax

    cave[n++] = 0xE9;                                       // jmp al epílogo general de la función
    *(DWORD*)(cave + n) = (g_base + RVA_OCC_REINFORCE_TAIL) - (DWORD)(cave + n + 4);
    n += 4;

    unsigned char patch[5];
    patch[0] = 0xE9;
    *(DWORD*)(patch + 1) = (DWORD)cave - ((DWORD)hook + 5);

    DWORD oldProtect = 0;
    if (!VirtualProtect(hook, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    memcpy(hook, patch, sizeof(patch));
    VirtualProtect(hook, sizeof(patch), oldProtect, &oldProtect);

    Log("OccupiedReinforceSplit: occupied=%d.%d%%, cueva %08X",
        OCCUPIED_REINFORCE_RATE / 10, OCCUPIED_REINFORCE_RATE % 10, (DWORD)(DWORD_PTR)cave);
    return true;
}


// ---------------------------------------------------------------
// División de tasa de refuerzo: occupied-by-ally vs owned-by-ally
//
// InstallOccupiedReinforceSplit de arriba solo atrapa el caso
// "controlamos nosotros mismos la provincia sin ser core" (Check A,
// cmp edx,[ecx+0x20]). Pero a la misma rama LAB_005d74bb también
// lleva el Check B — "provincia bajo control de un país amigo
// nuestro" (relations[controller][us] == 0) —, y el Check B se
// dispara SIN IMPORTAR si ese país amigo posee la provincia por core
// o también la ocupó nada más. O sea, "aliado dueño" y "aliado
// ocupando territorio ajeno" hoy son indistinguibles y ambos van a 150%.
//
// Tres JNZ en rva 0x1D7544/0x1D754E/0x1D7558 (verificación byte por
// byte del tag del controlador contra "REB") al no coincidir llevan
// justo a LAB_005d74bb — son los únicos puntos de entrada al Check B.
// Los tres ya están codificados por el compilador como near jmp (0F
// 85 rel32, 6 bytes, porque LAB_005d74bb no se alcanza desde acá con
// un salto corto), así que solo corregimos el rel32 de 4 bytes, sin
// cueva-trampolín para los saltos en sí — solo para la nueva
// bifurcación a la que ahora llevan.
//
// En la bifurcación, la provincia (EDI, no cambia en toda la
// función) da owner (+0x12c) y controller (+0x134) directamente, sin
// apoyarse en ECX/EDX, que el Check B ya usó para sus propios fines:
// si son iguales, el controlador es el verdadero dueño, es
// owned-by-ally (150%, vamos al LAB_005d74bb original); si no,
// ocupación de un aliado sobre tierra ajena (100%, el mismo
// epílogo-cola que usa el Check A).
// ---------------------------------------------------------------

static const DWORD RVA_ALLY_JNZ1 = 0x1D7544;   // jnz LAB_005d74bb (controller.tag[0] != 'R')
static const DWORD RVA_ALLY_JNZ2 = 0x1D754E;   // jnz LAB_005d74bb (controller.tag[1] != 'E')
static const DWORD RVA_ALLY_JNZ3 = 0x1D7558;   // jnz LAB_005d74bb (controller.tag[2] != 'B')

static const unsigned char ALLY_JNZ1_SIG[6] = { 0x0F, 0x85, 0x71, 0xFF, 0xFF, 0xFF };
static const unsigned char ALLY_JNZ2_SIG[6] = { 0x0F, 0x85, 0x67, 0xFF, 0xFF, 0xFF };
static const unsigned char ALLY_JNZ3_SIG[6] = { 0x0F, 0x85, 0x5D, 0xFF, 0xFF, 0xFF };

static bool RepointNearJnz(DWORD rva, const unsigned char* sig, DWORD newTargetVA)
{
    unsigned char* at = (unsigned char*)(g_base + rva);

    if (memcmp(at, sig, 6) != 0)
    {
        Log("AllyOwnerCheck: la firma no coincide en rva %06X - no se parchea", rva);
        return false;
    }

    unsigned char patch[6];
    patch[0] = 0x0F;
    patch[1] = 0x85;
    *(DWORD*)(patch + 2) = newTargetVA - ((DWORD)at + 6);

    DWORD oldProtect = 0;
    if (!VirtualProtect(at, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    memcpy(at, patch, sizeof(patch));
    VirtualProtect(at, sizeof(patch), oldProtect, &oldProtect);
    return true;
}

static bool InstallAllyOwnerCheck()
{
    unsigned char* cave = (unsigned char*)VirtualAlloc(
        0, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!cave)
        return false;

    int n = 0;

    cave[n++] = 0x8B; cave[n++] = 0x97;                     // mov edx,[edi+0x12c]  (province.owner_id)
    *(DWORD*)(cave + n) = 0x12C; n += 4;

    cave[n++] = 0x3B; cave[n++] = 0x97;                     // cmp edx,[edi+0x134]  (province.controller_id)
    *(DWORD*)(cave + n) = 0x134; n += 4;

    cave[n++] = 0x0F; cave[n++] = 0x84;                     // jz owned-by-ally -> LAB_005d74bb original (150%)
    *(DWORD*)(cave + n) = (g_base + RVA_LAB_74BB) - (DWORD)(cave + n + 4);
    n += 4;

    // occupied-by-ally: tasa propia, el mismo epílogo-cola que el Check A.
    cave[n++] = 0x8B; cave[n++] = 0x4D; cave[n++] = 0x08;   // mov ecx,[ebp+8]
    cave[n++] = 0xB8;                                       // mov eax, OCCUPIED_REINFORCE_RATE
    *(DWORD*)(cave + n) = (DWORD)OCCUPIED_REINFORCE_RATE; n += 4;
    cave[n++] = 0x89; cave[n++] = 0x01;                     // mov [ecx],eax

    cave[n++] = 0xE9;                                       // jmp al epílogo general de la función
    *(DWORD*)(cave + n) = (g_base + RVA_OCC_REINFORCE_TAIL) - (DWORD)(cave + n + 4);
    n += 4;

    DWORD target = (DWORD)(DWORD_PTR)cave;

    bool ok = true;
    ok &= RepointNearJnz(RVA_ALLY_JNZ1, ALLY_JNZ1_SIG, target);
    ok &= RepointNearJnz(RVA_ALLY_JNZ2, ALLY_JNZ2_SIG, target);
    ok &= RepointNearJnz(RVA_ALLY_JNZ3, ALLY_JNZ3_SIG, target);

    Log("AllyOwnerCheck: owned-by-ally=150%%, occupied-by-ally=%d.%d%%, cueva %08X, ok=%d",
        OCCUPIED_REINFORCE_RATE / 10, OCCUPIED_REINFORCE_RATE % 10, target, (int)ok);
    return ok;
}


// ---------------------------------------------------------------
// Crash al civilizarse un país (0xc0000005, fault offset 0x14248b).
//
// FUN_00542370 - manejador de "on_civilize": recorre las
// construcciones existentes del país (FUN_005c2ad0 - búsqueda por
// nombre en una tabla hash "categoría/bien -> slot") y las reparte
// en slots para procesarlas después. Antes esto solo fallaba en
// teoría: los países no civilizados no podían construir fábricas en
// absoluto, así que nunca se llegaba a este código con nada aparte
// de construcciones RGO, para las que el slot siempre existe. En
// esta sesión se agregaron los parches
// build_factory_ignore_uncivilized_* — ahora un país no civilizado
// PUEDE construir cualquier fábrica, y al civilizarse FUN_005c2ad0
// no encuentra slot para esa construcción, devuelve 0 (no
// encontrado), y el código llamante desreferencia el resultado sin
// verificar: mov esi,[eax+0x40] - EAX=0 -> lectura en 0x40 -> crash.
//
// Se parchea justo el punto después del call a FUN_005c2ad0 (rva
// 0x14248B, 7 bytes - cubre mov esi,[eax+0x40]; dec esi; shl esi,4).
// Si EAX==0 - se saltea la construcción actual entera (salto a rva
// 0x142555, el punto normal de "siguiente iteración" del mismo
// ciclo, ya presente en el código original). Si no - se reproducen
// las tres instrucciones tapadas y se sigue como antes (rva 0x142492).
// ---------------------------------------------------------------

static const DWORD RVA_CIVILIZE_NULLCHECK_HOOK   = 0x14248B;
static const DWORD RVA_CIVILIZE_NULLCHECK_NORMAL = 0x142492;  // add esi,[ebp-0x48]
static const DWORD RVA_CIVILIZE_NULLCHECK_SKIP   = 0x142555;  // mov eax,[ebp-0x18] (siguiente iteración)

static const unsigned char CIVILIZE_NULLCHECK_SIG[7] =
{ 0x8B, 0x70, 0x40, 0x4E, 0xC1, 0xE6, 0x04 };

static bool InstallCivilizeNullCheck()
{
    unsigned char* hook = (unsigned char*)(g_base + RVA_CIVILIZE_NULLCHECK_HOOK);

    if (memcmp(hook, CIVILIZE_NULLCHECK_SIG, sizeof(CIVILIZE_NULLCHECK_SIG)) != 0)
    {
        Log("CivilizeNullCheck: la firma no coincide - no se parchea");
        return false;
    }

    unsigned char* cave = (unsigned char*)VirtualAlloc(
        0, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!cave)
        return false;

    int n = 0;

    cave[n++] = 0x85; cave[n++] = 0xC0;                     // test eax,eax
    int jzAt = n;
    cave[n++] = 0x74; cave[n++] = 0x00;                     // jz null_case (la dirección se completa abajo)

    // EAX != 0: reproducimos los bytes tapados y volvemos.
    cave[n++] = 0x8B; cave[n++] = 0x70; cave[n++] = 0x40;   // mov esi,[eax+0x40]
    cave[n++] = 0x4E;                                       // dec esi
    cave[n++] = 0xC1; cave[n++] = 0xE6; cave[n++] = 0x04;   // shl esi,4

    cave[n++] = 0xE9;                                       // jmp de vuelta (camino normal)
    *(DWORD*)(cave + n) = (g_base + RVA_CIVILIZE_NULLCHECK_NORMAL) - (DWORD)(cave + n + 4);
    n += 4;

    int nullAt = n;
    cave[jzAt + 1] = (unsigned char)(nullAt - (jzAt + 2));

    // EAX == 0: no se encontró slot - se saltea esta construcción
    // entera, a la siguiente iteración del mismo ciclo (punto de
    // salida normal).
    cave[n++] = 0xE9;
    *(DWORD*)(cave + n) = (g_base + RVA_CIVILIZE_NULLCHECK_SKIP) - (DWORD)(cave + n + 4);
    n += 4;

    unsigned char patch[7];
    patch[0] = 0xE9;
    *(DWORD*)(patch + 1) = (DWORD)(DWORD_PTR)cave - ((DWORD)hook + 5);
    patch[5] = 0x90;
    patch[6] = 0x90;

    DWORD oldProtect = 0;
    if (!VirtualProtect(hook, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    memcpy(hook, patch, sizeof(patch));
    VirtualProtect(hook, sizeof(patch), oldProtect, &oldProtect);

    Log("CivilizeNullCheck: instalado en rva %06X, cueva %08X",
        RVA_CIVILIZE_NULLCHECK_HOOK, (DWORD)(DWORD_PTR)cave);
    return true;
}


// ---------------------------------------------------------------
// Desborde del buffer de puntos del gráfico (0xc0000409 - saltó la
// GS-canary del stack - justo después 0xc0000005 en la misma
// dirección).
//
// FUN_009e0ef0 - dibujado del gráfico histórico (se abre junto con
// la ventana de presupuesto). Para cada segmento del historial, el
// código escribe exactamente [ESI] puntos seguidos en un buffer local
// fijo, sin verificar [ESI] contra la capacidad del buffer. Si algún
// segmento tiene una cantidad anormalmente grande de puntos (valores
// económicos que rompen el contador de registros de historial - el
// usuario vio números de aranceles yéndose a negativo antes del
// crash), la escritura se va fuera del buffer y destroza el stack.
//
// Se parchea justo el punto de la primera lectura del contador (rva
// 0x5E0FD6, 13 bytes - cubre cmp dword[esi],1; mov [esp+0x20],esi; jl
// rva 0x5E1159). Antes de esa comparación, limitamos el propio
// contador (dword [esi]) por arriba a un valor seguro
// GRAPH_CLAMP_MAX - es un buffer de UI temporal del gráfico,
// reconstruido en cada actualización de la ventana, así que el
// recorte no afecta las estadísticas económicas reales. Después
// reproducimos el cmp/mov/jl originales sin cambios - ya trabajan
// con el valor recortado.
//
// IMPORTANTE (la versión 2.54 igual se cayó con este mismo
// clamp=150): el cálculo exacto de la capacidad del buffer según el
// marco de pila de la función - SUB ESP,0x9BC en el prólogo, el
// buffer empieza en ESP+0x90 (el primer registro escribe
// [ESI-4]..[ESI+0xB]), 3 push (EBX/ESI/EDI, 0xC bytes) ya se
// restaron de ESP antes de eso. A 0x10 bytes por punto, el máximo
// seguro = ((0x9BC-0xC) - 0x90) / 0x10 = 147 puntos - el valor 150
// desbordaba el buffer justo lo suficiente para pisar el EBP
// guardado/la dirección de retorno/los parámetros de la función
// llamante (justo lo que dio el crash en MOV ECX,[EAX] en rva
// 5E1137, donde EAX = [EBP+0xC] corrupto). Tomé 100 - un margen
// notable respecto al límite matemático 147 por si hay algo
// impreciso en el análisis manual del marco (la alineación AND
// ESP,0xFFFFFFF8 da hasta 7 bytes de incertidumbre).
// ---------------------------------------------------------------

static const DWORD RVA_GRAPH_CLAMP_HOOK   = 0x5E0FD6;
static const DWORD RVA_GRAPH_CLAMP_NORMAL = 0x5E0FE3;  // lea ecx,[esi+4]
static const DWORD RVA_GRAPH_CLAMP_SKIP   = 0x5E1159;  // dec dword ptr[esp+0x28] (siguiente segmento)
static const int   GRAPH_CLAMP_MAX = 100;

static const unsigned char GRAPH_CLAMP_SIG[13] =
{
    0x83, 0x3E, 0x01,                   // cmp dword ptr[esi],1
    0x89, 0x74, 0x24, 0x20,             // mov [esp+0x20],esi
    0x0F, 0x8C, 0x76, 0x01, 0x00, 0x00  // jl rva 0x5E1159
};

static bool InstallGraphPointClamp()
{
    unsigned char* hook = (unsigned char*)(g_base + RVA_GRAPH_CLAMP_HOOK);

    if (memcmp(hook, GRAPH_CLAMP_SIG, sizeof(GRAPH_CLAMP_SIG)) != 0)
    {
        Log("GraphPointClamp: la firma no coincide - no se parchea");
        return false;
    }

    unsigned char* cave = (unsigned char*)VirtualAlloc(
        0, 48, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!cave)
        return false;

    int n = 0;

    cave[n++] = 0x81; cave[n++] = 0x3E;                     // cmp dword ptr[esi], GRAPH_CLAMP_MAX
    *(DWORD*)(cave + n) = (DWORD)GRAPH_CLAMP_MAX; n += 4;

    int jleAt = n;
    cave[n++] = 0x7E; cave[n++] = 0x00;                     // jle skip_clamp (la dirección se completa abajo)

    cave[n++] = 0xC7; cave[n++] = 0x06;                     // mov dword ptr[esi], GRAPH_CLAMP_MAX
    *(DWORD*)(cave + n) = (DWORD)GRAPH_CLAMP_MAX; n += 4;

    int skipClampAt = n;
    cave[jleAt + 1] = (unsigned char)(skipClampAt - (jleAt + 2));

    // Reproducimos los bytes tapados - ahora con el valor limitado
    // por arriba con GRAPH_CLAMP_MAX.
    cave[n++] = 0x83; cave[n++] = 0x3E; cave[n++] = 0x01;   // cmp dword ptr[esi],1
    cave[n++] = 0x89; cave[n++] = 0x74; cave[n++] = 0x24; cave[n++] = 0x20;  // mov [esp+0x20],esi

    int jgeAt = n;
    cave[n++] = 0x7D; cave[n++] = 0x00;                     // jge continue (la dirección se completa abajo)

    cave[n++] = 0xE9;                                       // jmp far_skip (rva GRAPH_CLAMP_SKIP)
    *(DWORD*)(cave + n) = (g_base + RVA_GRAPH_CLAMP_SKIP) - (DWORD)(cave + n + 4);
    n += 4;

    int continueAt = n;
    cave[jgeAt + 1] = (unsigned char)(continueAt - (jgeAt + 2));

    cave[n++] = 0xE9;                                       // jmp far_resume (rva GRAPH_CLAMP_NORMAL)
    *(DWORD*)(cave + n) = (g_base + RVA_GRAPH_CLAMP_NORMAL) - (DWORD)(cave + n + 4);
    n += 4;

    unsigned char patch[13];
    patch[0] = 0xE9;
    *(DWORD*)(patch + 1) = (DWORD)(DWORD_PTR)cave - ((DWORD)hook + 5);
    for (int i = 5; i < 13; ++i)
        patch[i] = 0x90;

    DWORD oldProtect = 0;
    if (!VirtualProtect(hook, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    memcpy(hook, patch, sizeof(patch));
    VirtualProtect(hook, sizeof(patch), oldProtect, &oldProtect);

    Log("GraphPointClamp: instalado en rva %06X, máximo %d puntos, cueva %08X",
        RVA_GRAPH_CLAMP_HOOK, GRAPH_CLAMP_MAX, (DWORD)(DWORD_PTR)cave);
    return true;
}


// ---------------------------------------------------------------
// Diagnóstico del crash de la economía (temporal, a pedido del
// usuario): volcado en vivo de la memoria de state_building para
// regular_clothes_factory y canned_food_factory en Rusia. En Rusia
// justo esas dos instancias de fábricas se van a valores anormales
// de money/pops_paychecks/last_income - el objetivo del volcado es
// atrapar el momento/causa del descarrile con números en vivo.
//
// La primera versión (2.53) colgaba un hook en FUN_004d04b0 ("se
// puede construir este tipo acá") - durante toda la partida (save
// Proebali.v2, ~26 días de juego desde el save anterior) el hook NO
// se disparó ni una vez. Se entendió por qué: los 3 lugares que
// llaman a FUN_004d04b0 son o bien la construcción del texto de
// tooltip "por qué no se puede construir"
// (FUN_0052ca30/FUN_0052cac0/FUN_00858670), o bien la IA eligiendo
// dónde construir una fábrica nueva (FUN_00857530/xref
// FUN_00858670) - y en este save Rusia está bajo el jugador
// (player="RUS"), así que la IA ni evalúa sus estados, y las
// ventanas de tooltip necesarias el jugador no las tenía abiertas.
// La función de recálculo diario del dinero de la fábrica es otra y
// no se encontró (un segundo intento vía la tabla de nombres de
// campos del save FUN_00c381c0 volvió a confirmar un callejón sin
// salida - es solo el registro nombre<->índice para serialización,
// sin desplazamientos/punteros a campos).
//
// Por eso, en vez de un hook - un hilo de fondo que escanea él mismo
// la memoria privada (heap) comprometida del proceso buscando un
// puntero a production_type con el nombre buscado (mismo layout de
// struct que antes: node+0x18 = puntero al tipo, el nombre está en
// OFF_PRODTYPE_NAME dentro del objeto tipo) - sin depender de qué
// función del juego exactamente y cuándo accede al nodo. Los nodos
// encontrados después simplemente se releen cada TRACK_INTERVAL_MS
// sin nuevo escaneo.
// ---------------------------------------------------------------
static const char* const FACTORY_DUMP_NAMES[] = { "regular_clothes_factory", "canned_food_factory" };
static const int FACTORY_DUMP_NAME_COUNT = sizeof(FACTORY_DUMP_NAMES) / sizeof(FACTORY_DUMP_NAMES[0]);
static const int FACTORY_DUMP_MAX_NODES = 8;
static const int FACTORY_DUMP_RANGE = 0x300;
static const DWORD FACTORY_SCAN_INTERVAL_MS = 30000;  // escaneo completo de memoria, hasta juntar nodos
static const DWORD FACTORY_TRACK_INTERVAL_MS = 5000;  // relectura liviana de los nodos ya encontrados
static const DWORD FACTORY_RESCAN_INTERVAL_MS = 300000; // reescaneo completo por si hay fábricas nuevas/desaparecidas

static void* g_factoryNodes[FACTORY_DUMP_MAX_NODES] = { 0 };
static char  g_factoryNodeNames[FACTORY_DUMP_MAX_NODES][64];
static int   g_factoryNodeCount = 0;
static HANDLE g_factoryScanThread = 0;

// Lee el nombre del tipo en typePtr+OFF_PRODTYPE_NAME verificando que
// sea imprimible (si no, es casi seguro que no es un production_type
// sino una coincidencia casual de bits). La llamada en sí está
// protegida por SEH afuera.
static bool ReadPlausibleTypeName(void* typePtr, char* outName, int outSize)
{
    if (!typePtr)
        return false;
    // v2game.exe está compilado con LARGE_ADDRESS_AWARE - bajo WOW64
    // el heap puede legítimamente estar por encima de 2 GB, así que
    // el límite superior está casi al tope del espacio de
    // direcciones de 32 bits, no en 0x7FFE0000.
    UINT_PTR tv = (UINT_PTR)typePtr;
    if (tv < 0x10000 || tv > 0xFFFE0000)
        return false;

    const char* src = (const char*)typePtr + OFF_PRODTYPE_NAME;
    int i = 0;
    for (; i < outSize - 1; ++i)
    {
        char c = src[i];
        if (c == 0)
            break;
        if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7e)
            return false;
        outName[i] = c;
    }
    if (i == 0 || i >= outSize - 1)
        return false;
    outName[i] = 0;
    return true;
}

static bool __cdecl SafeCheckTypeName(void* typePtr, char* outName, int outSize)
{
    __try
    {
        return ReadPlausibleTypeName(typePtr, outName, outSize);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static void DumpFactoryNodeNow(void* node, const char* typeName)
{
    char line[4096];
    int len = sprintf_s(line, sizeof(line), "FactoryDump node=%08X type=%s:",
                        (unsigned)(DWORD_PTR)node, typeName);
    if (len < 0)
        return;

    __try
    {
        for (int off = 0; off < FACTORY_DUMP_RANGE; off += 8)
        {
            if (len >= (int)sizeof(line) - 64)
                break;
            double v = *(double*)((char*)node + off);
            // %e - ver comentario en DumpAnomalyContext: %.3f en un
            // double extremo se despliega en cientos de caracteres y
            // puede hacer que sprintf_s falle (-1), y acumular
            // ciegamente len += -1 en varias iteraciones manda len a
            // negativo y la escritura empieza a pisar antes del
            // comienzo del buffer - justo lo que atrapó /GS. Nos
            // detenemos en el primer fallo, sin adivinar.
            int written = sprintf_s(line + len, sizeof(line) - len, " %03X=%.3e", off, v);
            if (written < 0)
                break;
            len += written;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        if (len >= 0 && len < (int)sizeof(line) - 32)
            sprintf_s(line + len, sizeof(line) - len, " <no se puede seguir leyendo>");
    }

    Log("%s", line);
}

// Rango de valores monetarios "sospechosamente grandes": las
// fábricas rotas en el save mostraban money/pops_paychecks/
// last_income del orden de -1.0e8..+1.2e8 - tomamos un rango con
// margen, pero claramente por encima de cualquier número normal de
// la economía de una fábrica individual.
static const double FACTORY_ANOMALY_MIN = 1000000.0;
static const double FACTORY_ANOMALY_MAX = 1.0e9;
static const int FACTORY_ANOMALY_MAX_HITS = 25;

// Volcado de la ventana ALREDEDOR del número anómalo encontrado (y no
// desde el comienzo del nodo, como DumpFactoryNodeNow - acá no
// sabemos desde qué desplazamiento empieza el objeto en sí, así que
// miramos tanto para atrás como para adelante).
static void DumpAnomalyContext(void* addr)
{
    char line[4096];
    int len = sprintf_s(line, sizeof(line), "FactoryScan-anomaly addr=%08X:", (unsigned)(DWORD_PTR)addr);
    if (len < 0)
        return;

    __try
    {
        for (int off = -0x40; off < FACTORY_DUMP_RANGE; off += 8)
        {
            if (len >= (int)sizeof(line) - 64)
                break;
            double v = *(double*)((char*)addr + off);
            // %e en vez de %f: el ancho del resultado está acotado
            // sin importar la magnitud del número. La ventana
            // alrededor de addr son bytes vecinos cualquiera del
            // heap, NO una estructura verificada (a diferencia de
            // DumpFactoryNodeNow) - entre ellos puede aparecer un
            // patrón de bits salvaje cerca de DBL_MAX, y %.3f en eso
            // despliega una cadena de ~300 dígitos. Justo eso una vez
            // hizo fallar sprintf_s (-1), y después len += -1 varias
            // veces seguidas se fue a negativo y la escritura empezó
            // sola a pisar antes del comienzo del buffer - exactamente
            // lo que atrapó /GS. Ahora tampoco sumamos ciegamente el
            // resultado negativo - en el primer fallo, simplemente
            // paramos.
            int written = sprintf_s(line + len, sizeof(line) - len, " %04X=%.3e", off & 0xFFFF, v);
            if (written < 0)
                break;
            len += written;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        if (len >= 0 && len < (int)sizeof(line) - 32)
            sprintf_s(line + len, sizeof(line) - len, " <no se puede seguir>");
    }

    Log("%s", line);
}

static void RegisterFoundNode(void* node, const char* typeName)
{
    for (int i = 0; i < g_factoryNodeCount; ++i)
        if (g_factoryNodes[i] == node)
            return;
    if (g_factoryNodeCount >= FACTORY_DUMP_MAX_NODES)
        return;

    int slot = g_factoryNodeCount++;
    g_factoryNodes[slot] = node;
    strcpy_s(g_factoryNodeNames[slot], typeName);
    Log("FactoryScan: nodo encontrado node=%08X type=%s (total encontrados %d)",
        (unsigned)(DWORD_PTR)node, typeName, g_factoryNodeCount);
    DumpFactoryNodeNow(node, typeName);
}

// Índice de regiones legibles (cualquier committed+readable, no solo
// MEM_PRIVATE - a diferencia del escaneo principal de abajo, acá
// entran también .data/.rdata etc., ya que un puntero candidato a
// production_type en principio puede apuntar a cualquier lado).
// Hace falta para NO disparar una excepción por cada valor de 4 bytes
// "parecido a puntero" - el manejo de una access violation es un
// orden de magnitud más caro que la propia comparación de rangos.
// VirtualQuery entrega las regiones estrictamente en orden creciente
// de dirección, así que se puede buscar directamente por bisección.
static const int FACTORY_SCAN_MAX_RANGES = 8192;
struct AddrRange { UINT_PTR start, end; };
static AddrRange g_readableRanges[FACTORY_SCAN_MAX_RANGES];
static int g_readableRangeCount = 0;

static void BuildReadableRangeIndex()
{
    g_readableRangeCount = 0;
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = 0;

    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        BYTE* regionEnd = (BYTE*)mbi.BaseAddress + mbi.RegionSize;

        bool readable = (mbi.State == MEM_COMMIT)
        && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY
        | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0
        && (mbi.Protect & PAGE_GUARD) == 0;

        if (readable && g_readableRangeCount < FACTORY_SCAN_MAX_RANGES)
        {
            g_readableRanges[g_readableRangeCount].start = (UINT_PTR)mbi.BaseAddress;
            g_readableRanges[g_readableRangeCount].end = (UINT_PTR)regionEnd;
            g_readableRangeCount++;
        }

        if (regionEnd <= addr)
            break;
        addr = regionEnd;
    }
}

// Búsqueda binaria: ¿está [start, start+len) completamente dentro de
// una región legible ya verificada?
static bool IsRangeReadable(UINT_PTR start, UINT_PTR len)
{
    UINT_PTR endAddr = start + len;
    int lo = 0, hi = g_readableRangeCount - 1, found = -1;
    while (lo <= hi)
    {
        int mid = (lo + hi) / 2;
        if (g_readableRanges[mid].start <= start) { found = mid; lo = mid + 1; }
        else hi = mid - 1;
    }
    if (found < 0)
        return false;
    return g_readableRanges[found].end >= endAddr;
}

// Escaneo completo de la memoria privada read/write del proceso. Cada
// región está protegida por un solo bloque SEH (la página podría
// haber desaparecido mientras se escaneaba, por el trabajo en
// paralelo del juego) - esto es más barato que envolver cada lectura
// de 4 bytes por separado, y las lecturas dentro de la región no se
// salen de sus límites verificados. El puntero candidato primero se
// verifica contra el índice de regiones legibles (IsRangeReadable) -
// una comparación rápida de números sin tocar memoria - y solo si
// pasa, lo leemos (otra vez bajo SEH - el índice podría haber
// quedado desactualizado durante el escaneo, pero ya es un caso raro,
// no casi cada candidato).
static void FullMemoryScan()
{
    DWORD startTick = GetTickCount();
    BuildReadableRangeIndex();
    Log("FactoryScan: índice de regiones legibles construido (%d%s), empiezo el escaneo...",
        g_readableRangeCount,
        g_readableRangeCount >= FACTORY_SCAN_MAX_RANGES ? " - LÍMITE ALCANZADO, parte de las regiones se omitió" : "");

    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = 0;

    // Diagnóstico (temporal): contamos coincidencias contra TODOS los
    // nombres de tipo de producción conocidos (g_productionTypeNames,
    // los 65 - no solo nuestras 2 fábricas objetivo), para entender si
    // el propio mecanismo de búsqueda funciona en principio, o si el
    // problema es justo con estas dos fábricas.
    //
    // IMPORTANTE: las regiones a ESCANEAR (no el índice de legibilidad
    // - ese sigue mirando todo) vuelven a estar limitadas a
    // MEM_PRIVATE. En la 2.58 se sacó esa limitación "por las dudas",
    // y casi enseguida después de eso el usuario tuvo "Failed to
    // create a graphics device" al arrancar el juego - con solo
    // MEM_PRIVATE (versiones 2.55-2.57) eso no pasó nunca en varias
    // corridas. El mecanismo exacto no está probado (probablemente
    // algo como páginas guard/señalización interna del driver de
    // video en sus datos MEM_MAPPED/MEM_IMAGE, perturbado por una
    // lectura desde un hilo ajeno), pero ya que el riesgo está
    // confirmado empíricamente, no salimos del heap del proceso.
    int diagAnyMatches = 0;
    char diagExamples[5][64];
    int diagExampleCount = 0;
    int anomalyHits = 0;

    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        BYTE* regionEnd = (BYTE*)mbi.BaseAddress + mbi.RegionSize;

        bool scannable = (mbi.State == MEM_COMMIT)
        && (mbi.Type == MEM_PRIVATE)
        && (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY)) != 0
        && (mbi.Protect & PAGE_GUARD) == 0;

        if (scannable)
        {
            __try
            {
                BYTE* p = (BYTE*)mbi.BaseAddress;
                BYTE* end = regionEnd - sizeof(void*);
                for (; p < end; p += 4)
                {
                    if (anomalyHits < FACTORY_ANOMALY_MAX_HITS && p + 8 <= regionEnd)
                    {
                        double v = *(double*)p;
                        double av = v < 0 ? -v : v;
                        if (av >= FACTORY_ANOMALY_MIN && av <= FACTORY_ANOMALY_MAX)
                        {
                            anomalyHits++;
                            DumpAnomalyContext(p);
                        }
                    }

                    void* candidate = *(void**)p;
                    UINT_PTR cv = (UINT_PTR)candidate;
                    if (cv < 0x10000 || cv > 0xFFFE0000)
                        continue;
                    if (!IsRangeReadable(cv + OFF_PRODTYPE_NAME, 64))
                        continue;

                    char name[64];
                    if (!SafeCheckTypeName(candidate, name, sizeof(name)))
                        continue;

                    bool anyTypeMatch = false;
                    for (int t = 0; t < g_productionTypeCount; ++t)
                        if (strcmp(g_productionTypeNames[t], name) == 0) { anyTypeMatch = true; break; }
                        if (anyTypeMatch)
                        {
                            diagAnyMatches++;
                            if (diagExampleCount < 5)
                            {
                                strcpy_s(diagExamples[diagExampleCount], name);
                                diagExampleCount++;
                            }
                        }

                        bool match = false;
                        for (int i = 0; i < FACTORY_DUMP_NAME_COUNT; ++i)
                            if (strcmp(FACTORY_DUMP_NAMES[i], name) == 0) { match = true; break; }
                            if (!match)
                                continue;

                    void* node = p - 0x18;
                    RegisterFoundNode(node, name);
                    if (g_factoryNodeCount >= FACTORY_DUMP_MAX_NODES)
                        break;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                // la región desapareció/cambió de protección durante el escaneo - se saltea
            }
        }

        if (g_factoryNodeCount >= FACTORY_DUMP_MAX_NODES)
            break;
        if (regionEnd <= addr)
            break;
        addr = regionEnd;
    }

    char examplesLine[400];
    int el = 0;
    examplesLine[0] = 0;
    for (int i = 0; i < diagExampleCount; ++i)
    {
        int written = sprintf_s(examplesLine + el, sizeof(examplesLine) - el, "%s%s", i ? ", " : "", diagExamples[i]);
        if (written < 0)
            break;
        el += written;
    }

    Log("FactoryScan: escaneo completo terminado en %u ms, nodos totales %d; coincidencias con CUALQUIER tipo de producción conocido: %d (ejemplos: %s); números anómalos (%.0f..%.0f): %d",
        GetTickCount() - startTick, g_factoryNodeCount, diagAnyMatches, examplesLine,
        FACTORY_ANOMALY_MIN, FACTORY_ANOMALY_MAX, anomalyHits);
}

static DWORD WINAPI FactoryScanThreadProc(LPVOID)
{
    Sleep(15000); // dejar que el juego cargue antes del primer escaneo

    DWORD lastFullScan = 0;
    for (;;)
    {
        DWORD now = GetTickCount();
        bool needFullScan = (g_factoryNodeCount < FACTORY_DUMP_MAX_NODES)
        ? (now - lastFullScan >= FACTORY_SCAN_INTERVAL_MS)
        : (now - lastFullScan >= FACTORY_RESCAN_INTERVAL_MS);

        if (needFullScan || lastFullScan == 0)
        {
            FullMemoryScan();
            lastFullScan = GetTickCount();
        }
        else
        {
            for (int i = 0; i < g_factoryNodeCount; ++i)
            {
                char name[64];
                if (!SafeCheckTypeName(*(void**)((char*)g_factoryNodes[i] + 0x18), name, sizeof(name)))
                {
                    Log("FactoryScan: el nodo node=%08X (%s) ya no se puede leer - parece haber sido eliminado",
                        (unsigned)(DWORD_PTR)g_factoryNodes[i], g_factoryNodeNames[i]);
                    continue;
                }
                DumpFactoryNodeNow(g_factoryNodes[i], g_factoryNodeNames[i]);
            }
        }

        Sleep(FACTORY_TRACK_INTERVAL_MS);
    }
    return 0;
}

static bool InstallFactoryDumpScan()
{
    g_factoryScanThread = CreateThread(0, 0, FactoryScanThreadProc, 0, 0, 0);
    if (!g_factoryScanThread)
    {
        Log("FactoryScan: no se pudo crear el hilo");
        return false;
    }
    Log("FactoryScan: hilo iniciado");
    return true;
}


// ---------------------------------------------------------------
// Instalación
// ---------------------------------------------------------------

// Las tablas están en .rdata, así que la escritura solo funciona
// quitando la protección — si no, falla en silencio.
static bool PatchSlot(DWORD rvaVtable, int slotIndex, void* replacement, void** outOriginal)
{
    void** slot = (void**)(g_base + rvaVtable) + slotIndex;

    DWORD oldProtect = 0;
    if (!VirtualProtect(slot, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    if (outOriginal)
        *outOriginal = *slot;

    *slot = replacement;

    VirtualProtect(slot, sizeof(void*), oldProtect, &oldProtect);
    return true;
}



// ---------------------------------------------------------------
// Población total en el indicador del panel superior
//
// El juego guarda en el país en +0x12E8 solo la población adulta
// masculina y la muestra en el panel tal cual. La total se obtiene
// multiplicando por 4 — así lo hace también el tooltip
// TOPBAR_POPULATION_VISUAL, donde la multiplicación está harcodeada
// en la instrucción lea eax,[ebx*4].
//
// Multiplicamos a la salida, no en la fuente: el propio campo
// participa en el cálculo de impuestos, reclutamiento e influencia, y
// no se puede tocar.
//
// El tooltip "Nuestra población adulta masculina actual" se deja
// intencionalmente sin corregir: ahí hace falta el número original.
// ---------------------------------------------------------------

static const int POP_MULTIPLIER_SHIFT = 2;   // shift de 2 = multiplicar por 4

// Lugares de dibujado. Cada uno es una lectura del campo de población
// a un registro, seguida enseguida de formateo del número. Los seis
// bytes de lectura se cambian por un salto a la cueva: ahí se lee, se
// desplaza y se vuelve.
//
// Agregar un lugar nuevo: buscar en Ghidra una lectura de
// [reg+0x12E8] cerca de la inserción en el texto, anotar el RVA y los
// bytes. Registro en la firma: 8B 87 = EAX,[EDI]; 8B 81 = EAX,[ECX];
// 8B 83 = EAX,[EBX].
//
// Importante: corregir solo el dibujado. El campo en sí participa en
// el cálculo de impuestos, reclutamiento e influencia, y no se puede
// tocar.
struct PopSite
{
    const char* name;
    DWORD         rva;
    unsigned char sig[6];
    bool          enabled;
};

static PopSite POP_SITES[] =
{
    { "topbar",    0x310A32, { 0x8B, 0x87, 0xE8, 0x12, 0x00, 0x00 }, true },
    { "diplomacy", 0x22880F, { 0x8B, 0x81, 0xE8, 0x12, 0x00, 0x00 }, true },
    { "lobby",     0x36DFBB, { 0x8B, 0x80, 0xE8, 0x12, 0x00, 0x00 }, true },
};

static const int POP_SITE_COUNT = sizeof(POP_SITES) / sizeof(POP_SITES[0]);


static bool InstallPopSite(const PopSite& site)
{
    unsigned char* hook = (unsigned char*)(g_base + site.rva);

    if (memcmp(hook, site.sig, 6) != 0)
    {
        Log("PopDisplay '%s': la firma no coincide - no se parchea", site.name);
        return false;
    }

    unsigned char* cave = (unsigned char*)VirtualAlloc(
        0, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!cave)
        return false;

    int n = 0;

    // Lectura original del campo — tal cual, junto con el registro.
    memcpy(cave + n, site.sig, 6);
    n += 6;

    // Multiplicación. El destino en todas las firmas es EAX, así que
    // se desplaza él. A nadie le importan las flags: sigue un push.
    cave[n++] = 0xC1; cave[n++] = 0xE0;
    cave[n++] = (unsigned char)POP_MULTIPLIER_SHIFT;   // shl eax, N

    cave[n++] = 0xE9;                                  // jmp de vuelta
    *(DWORD*)(cave + n) = (g_base + site.rva + 6) - (DWORD)(cave + n + 4);
    n += 4;

    // Seis bytes tapados: cinco para el jmp y uno para el nop.
    unsigned char patch[6];
    patch[0] = 0xE9;
    *(DWORD*)(patch + 1) = (DWORD)cave - ((DWORD)hook + 5);
    patch[5] = 0x90;

    DWORD oldProtect = 0;
    if (!VirtualProtect(hook, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    memcpy(hook, patch, sizeof(patch));
    VirtualProtect(hook, sizeof(patch), oldProtect, &oldProtect);

    Log("PopDisplay '%s': rva %06X, cueva %08X",
        site.name, site.rva, (DWORD)(DWORD_PTR)cave);
    return true;
}


static void InstallPopDisplay()
{
    Log("PopDisplay: multiplicador %d", 1 << POP_MULTIPLIER_SHIFT);

    for (int i = 0; i < POP_SITE_COUNT; ++i)
    {
        if (POP_SITES[i].enabled)
            InstallPopSite(POP_SITES[i]);
    }
}




// ---------------------------------------------------------------
// Versión del mod en el subtítulo del menú principal
//
// Verificado en Cheat Engine sobre memoria en vivo (el
// decompilador confundía direcciones — entre los dos push apareció
// un mov edi,0xF, y la dirección de la cadena no coincidía con el
// valor del decompilador):
//
//   233826  6A 08                  push 0x8
//   233828  BF 0F 00 00 00         mov edi, 0xF        (no se toca)
//   23382D  68 4C 76 A0 4C         push dirección "V2 v3.04"
//   233832  8D 4D B0               lea ecx,[ebp-0x50]
//
// Se tapan los 12 bytes (push + mov + push) con un salto a la cueva,
// donde se pushea la longitud y la dirección de nuestra propia
// cadena, se repite el mov edi,0xF tal cual — por si se usa más
// adelante en la función — y se vuelve al lea ecx de 233832.
// ---------------------------------------------------------------

static const DWORD RVA_VERLABEL_HOOK = 0x233826;
static const DWORD RVA_VERLABEL_RESUME = 0x233832;

// Los primeros 8 bytes son constantes, después viene un push de una
// dirección absoluta — no se puede fijar como constante: es
// base+RVA, y la base cambia por ASLR en cada arranque. Se verifica
// aparte, relativo al g_base actual.
static const unsigned char VERLABEL_SIG[8] =
{
    0x6A, 0x08,                          // push 0x8
    0xBF, 0x0F, 0x00, 0x00, 0x00,        // mov edi, 0xF
    0x68                                 // push imm32 (dirección — sigue)
};

static const DWORD RVA_VERLABEL_ORIG_STR = 0xA0764C;

static char g_versionLabel[128];

static bool InstallVersionLabel()
{
    unsigned char* hook = (unsigned char*)(g_base + RVA_VERLABEL_HOOK);

    if (memcmp(hook, VERLABEL_SIG, sizeof(VERLABEL_SIG)) != 0)
    {
        Log("VersionLabel: la firma no coincide (%02X %02X %02X %02X %02X %02X %02X %02X) - no se parchea",
            hook[0], hook[1], hook[2], hook[3], hook[4], hook[5], hook[6], hook[7]);
        return false;
    }

    DWORD origAddr = *(DWORD*)(hook + 8);
    if (origAddr != g_base + RVA_VERLABEL_ORIG_STR)
    {
        Log("VersionLabel: la dirección de la cadena no coincide (%08X, se esperaba %08X) - no se parchea",
            origAddr, g_base + RVA_VERLABEL_ORIG_STR);
        return false;
    }

    sprintf_s(g_versionLabel, sizeof(g_versionLabel),
              "V2 v3.04 + V2DLL v%s", MOD_VERSION);

    unsigned len = (unsigned)strlen(g_versionLabel);

    unsigned char* cave = (unsigned char*)VirtualAlloc(
        0, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!cave)
        return false;

    int n = 0;

    cave[n++] = 0x68;                                  // push imm32 (longitud)
    *(DWORD*)(cave + n) = len; n += 4;

    cave[n++] = 0x68;                                  // push imm32 (dirección)
    *(DWORD*)(cave + n) = (DWORD)(DWORD_PTR)g_versionLabel; n += 4;

    // mov edi, 0xF — se repite tal cual, por si se usa más adelante.
    cave[n++] = 0xBF;
    *(DWORD*)(cave + n) = 0xF; n += 4;

    cave[n++] = 0xE9;                                  // jmp de vuelta
    *(DWORD*)(cave + n) = (g_base + RVA_VERLABEL_RESUME) - (DWORD)(cave + n + 4);
    n += 4;

    unsigned char patch[12];
    memset(patch, 0x90, sizeof(patch));
    patch[0] = 0xE9;
    *(DWORD*)(patch + 1) = (DWORD)cave - ((DWORD)hook + 5);

    DWORD oldProtect = 0;
    if (!VirtualProtect(hook, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    memcpy(hook, patch, sizeof(patch));
    VirtualProtect(hook, sizeof(patch), oldProtect, &oldProtect);

    Log("VersionLabel: '%s' (len=%u), cueva %08X",
        g_versionLabel, len, (DWORD)(DWORD_PTR)cave);
    return true;
}


static bool Install()
{
    LoadSettings();

    g_base = (DWORD)GetModuleHandleA(NULL);
    if (!g_base)
        return false;

    g_fnOnMakeDecision = (void*)(g_base + RVA_ONMAKEDECISION);

    Log("---- Instalación ---- versión %s", MOD_VERSION);
    Log("base = %08X", g_base);

    // Elementos falsos: "POLITICSVIEW_DECISION" + nombre de la decisión.
    memset(g_fakeElem, 0, sizeof(g_fakeElem));

    for (int i = 0; i < BUTTON_COUNT && i < MAX_BUTTONS; ++i)
    {
        strcpy_s(g_decisionText[i], sizeof(g_decisionText[i]),
                 "POLITICSVIEW_DECISION");
        strcat_s(g_decisionText[i], sizeof(g_decisionText[i]),
                 BUTTONS[i].decision);

        *(char**)(g_fakeElem[i] + ELEM_STRDATA) = g_decisionText[i];
        *(unsigned*)(g_fakeElem[i] + ELEM_STRRES) = sizeof(g_decisionText[i]) - 1;
    }

    for (int i = 0; i < VIEW_COUNT && i < MAX_VIEWS; ++i)
    {
        void* thunk = VIEWS[i].tooltipSlot ? TOOLTIP_THUNKS[i] : UPDATE_THUNKS[i];

        bool ok = PatchSlot(VIEWS[i].rvaVtable, VIEWS[i].slot,
                            thunk, &g_origSlot[i]);

        Log("patch %s: slot %d = %d", VIEWS[i].name, VIEWS[i].slot, (int)ok);
    }

    if (g_settings.decisionFilter)
    {
        bool ok = PatchSlot(RVA_VTABLE_DECISION, VT_SLOT_ISVALID,
                            (void*)&MyDecisionIsValid, (void**)&g_origIsValid);
        Log("patch CDecision: slot %d = %d", VT_SLOT_ISVALID, (int)ok);
    }

    // Cada entrada de la tabla respeta su propio BytePatch::enabled
    // (corregido por claves PATCH_<NOMBRE> en el ini), así que la
    // llamada en sí es incondicional.
    InstallExePatches();

    if (g_settings.patchOccupiedReinforceSplit)
        InstallOccupiedReinforceSplit();

    if (g_settings.patchAllyOwnerCheck)
        InstallAllyOwnerCheck();

    if (g_settings.patchCivilizeNullCheck)
        InstallCivilizeNullCheck();

    if (g_settings.patchGraphPointClamp)
        InstallGraphPointClamp();

    if (g_settings.patchFactoryDumpScan)
    {
        // En la 2.58 el escáner atrapaba temporalmente "Failed to
        // create a graphics device" al arrancar - confirmado con
        // prueba A/B (la 2.58 con escaneo amplio de todos los tipos
        // de memoria disparaba el error, la 2.59 sin llamar a esta
        // función, no). La causa se acotó a extender el escaneo más
        // allá de MEM_PRIVATE (el heap del proceso) a
        // MEM_IMAGE/MEM_MAPPED, donde podían vivir datos internos del
        // driver de video - en la 2.60 esa limitación se restauró, de
        // nuevo se escanea solo MEM_PRIVATE, como en las 2.55-2.57
        // que nunca fallaron.
        InstallFactoryDumpScan();
    }

    if (g_settings.patchProdListVisibility)
        InstallProdListVisibilityHook();

    if (g_settings.patchProdTypeGate)
        InstallProdTypeGateHook();

    if (g_settings.priceDelta)
        InstallPriceDelta();

    if (g_settings.popDisplay)
        InstallPopDisplay();

    if (g_settings.versionLabel)
        InstallVersionLabel();

    Log("Install: listo");
    return true;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        Log("DllMain: attach, Install = %d", (int)Install());
    }
    return TRUE;
}
