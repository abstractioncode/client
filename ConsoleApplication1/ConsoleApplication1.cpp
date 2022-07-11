#include "nlohmann/json.hpp"
#include "easywsclient.hpp"
#ifdef _WIN32
#pragma comment( lib, "ws2_32" )
#include <WinSock2.h>
#endif
#include <assert.h>
#include <stdio.h>
#include <string>
#include <fstream>
#include <iostream>
#include <iostream>
#include <fstream>
#include <modes.h>
#include <aes.h>
#include <filters.h>
#include "uuid.h"
#include "hwid.h"
#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "aes.h"
using CryptoPP::AES;

#include "ccm.h"
using CryptoPP::CBC_Mode;

#include "assert.h"
#include "base64.h"
#include "menu.h"

#include "ImGui/ImGui.h"
#include "ImGui/imgui_impl_dx9.h"
#include "ImGui/imgui_impl_win32.h"
#include <d3d9.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <tchar.h>
using easywsclient::WebSocket;

static easywsclient::WebSocket::pointer ws = NULL;

using json = nlohmann::json;

static LPDIRECT3D9              g_pD3D = NULL;
static LPDIRECT3DDEVICE9        g_pd3dDevice = NULL;
static D3DPRESENT_PARAMETERS    g_d3dpp = {};

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void ResetDevice();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
std::string encrypt(const std::string& str_in, const std::string& key, const std::string& iv)
{

    std::string str_out;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption((byte*)key.c_str(), key.length(), (byte*)iv.c_str());
    CryptoPP::StringSource encryptor(str_in, true,
        new CryptoPP::StreamTransformationFilter(encryption,
            new CryptoPP::Base64Encoder(
                new CryptoPP::StringSink(str_out),
                false 
            )
        )
    );
    return str_out;
}
std::string texted = "";

std::string decrypt(const std::string& str_in, const std::string& key, const std::string& iv)
{

    std::string str_out;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption((byte*)key.c_str(), key.length(), (byte*)iv.c_str());

    CryptoPP::StringSource decryptor(str_in, true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StreamTransformationFilter(decryption,
                new CryptoPP::StringSink(str_out)
            )
        )
    );
    return str_out;
}
std::string key = "12345678901234567890123456789012";
std::string IV = "1234567890123456";
json user;
enum typeanswers {
    succauth,
	hwid_err,
	download,
    pass_err,
    decrypty,
    acc_not_found,
    subscriptionerror,
	
};
std::string username = "";
bool notlogged = true;
typeanswers hashit(std::string const& inString) {
    if (inString == "auth") return succauth;
    if (inString == "hwid_err") return hwid_err;
    if (inString == "pass_err") return pass_err;
    if (inString == "download") return download;
	if (inString == "decrypt") return decrypty;
	if (inString == "acc_not_found") return acc_not_found;
	if (inString == "subscriptionerror") return subscriptionerror;
	
}
void handle_message(const std::string& message)
{
    std::cout << "encrypted message: " <<message << std::endl;
    try {
        const std::string obj = decrypt(message, key, IV);
        json j = json::parse(obj);

        switch (hashit(j["type"])) {
        case hwid_err:
            std::cout << "hwid error" << std::endl;
            MessageBoxA(0, "hwid error", 0, MB_OK);

            break;
        case pass_err:
            MessageBoxA(0, "wrong pass", 0, MB_OK);
            break;
        case succauth:
            user = j;
            if (user.contains("username")) {
                notlogged = false;
				username = user["username"].get<std::string>();
            }
            break;
        case subscriptionerror:
			MessageBoxA(0, "subscription error", 0, MB_OK);
			break;
        case decrypty:
            texted = j.dump();
            break;
        case acc_not_found:
            MessageBoxA(0, "account not found", 0, MB_OK);
            break;
       
        case download:
            texted = "downloading";
            std::cout << "text from file: " << j["message"] << std::endl;
            std::ofstream datafile("temp1.dat", std::ios_base::binary | std::ios_base::out);

            char buf[3];
            buf[2] = 0;
            std::string sdf = j["message"];
            std::stringstream input(sdf);
            input.flags(std::ios_base::hex);
            while (input)
            {
                input >> buf[0] >> buf[1];
                long val = strtol(buf, nullptr, 16);
                datafile << static_cast<unsigned char>(val & 0xff);
            }
            break;
        }
    }
    catch (CryptoPP::Exception& ex)
    {
    }
    

}
using std::string;
using std::cout;
#include <d3d9.h>
#pragma comment(lib,"d3d9.lib")
bool doOnce = false;
bool active = false;

bool show_login = true;
bool show_register = false;
class initWindow {
public:
    const char* window_title = "Loader";
    ImVec2 window_size{ 740, 460 };

    DWORD window_flags = ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoTitleBar;
} iw;
int button_opacity = 255;

void load_styles()
{
    ImVec4* colors = ImGui::GetStyle().Colors;
    {
        colors[ImGuiCol_WindowBg] = ImVec4(0.06f, 0.06f, 0.06f, 1.00f);

        colors[ImGuiCol_FrameBg] = ImColor(11, 11, 11, 255);
        colors[ImGuiCol_FrameBgHovered] = ImColor(11, 11, 11, 255);

        colors[ImGuiCol_Button] = ImColor(255, 0, 46, button_opacity);
        colors[ImGuiCol_ButtonActive] = ImColor(255, 0, 46, button_opacity);
        colors[ImGuiCol_ButtonHovered] = ImColor(255, 0, 46, button_opacity);

        colors[ImGuiCol_TextDisabled] = ImVec4(0.37f, 0.37f, 0.37f, 1.00f);
    }

    ImGuiStyle* style = &ImGui::GetStyle();
    {
        style->WindowPadding = ImVec2(4, 4);
        style->WindowBorderSize = 0.f;

        style->FramePadding = ImVec2(8, 6);
        style->FrameRounding = 3.f;
        style->FrameBorderSize = 1.f;
    }
}
char user_name[255] = "typescript";
char pass_word[255] = "123";
void login(WebSocket * ws)
{

    json j;


    j["uuid"] = uuid::generate_uuid_v4();
    j["username"] = user_name;
    j["password"] = pass_word;
    j["type"] = "auth";
    if (j["type"] == "auth")
    {
        j["hwidid"] = get_hwid::hwid();
    }
    ws->send(encrypt(j.dump(),key,IV));
    
}

int main()
{
   
    json j;
#ifdef _WIN32
    INT rc;
    WSADATA wsaData;

    rc = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (rc) {
        printf("WSAStartup Failed.\n");
        return 1;
    }
#endif

    ws = WebSocket::from_url("ws://localhost:8126/foo");

    assert(ws);

    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, _T("Loader"), NULL };
    ::RegisterClassEx(&wc);
    HWND hwnd = ::CreateWindow(wc.lpszClassName, _T("Loader"), WS_OVERLAPPEDWINDOW, 0, 0, 50, 50, NULL, NULL, wc.hInstance, NULL);

    ::ShowWindow(::GetConsoleWindow(), SW_HIDE);

    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        ::UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ::ShowWindow(hwnd, SW_HIDE);
    ::UpdateWindow(hwnd);


    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;       // Enable Keyboard Controls
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;         // Enable Multi-Viewport / Platform Windows

    ImGui::StyleColorsDark();


    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX9_Init(g_pd3dDevice);

    ImFont* mdFont = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\Verdana.ttf", 12.f);

    bool done = false;

   

    while (!done)
    {
        

        MSG msg;
        while (::PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done)
            break;

        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        {
            if (true)
            {
                if (!doOnce)
                {
                    load_styles();
                    doOnce = true;
                }

                ImGui::SetNextWindowSize(iw.window_size);

                ImGui::Begin(iw.window_title, &active, iw.window_flags);
                {
                    ImGui::SetCursorPos(ImVec2(726, 5));
                    ImGui::TextDisabled("X");
                    if (ImGui::IsItemClicked())
                    {
                        active = false;
                    }

                    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.054, 0.054, 0.054, 255));
                    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.082, 0.078, 0.078, 255));
                    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 3.f);
                    {
                        ImGui::SetCursorPos(ImVec2(222, 83));
                        ImGui::BeginChild("##MainPanel", ImVec2(300, 276), true);
                        {
                            if (notlogged) {
                                ImGui::SetCursorPos(ImVec2(118, 20));
                            ImGui::TextDisabled("Welcome Back");

                            ImGui::SetCursorPos(ImVec2(97, 35));
                            ImGui::Text("Log into your account");

                            ImGui::PushItemWidth(260.f);
                            {
                                ImGui::SetCursorPos(ImVec2(22, 79));
                                ImGui::TextDisabled("Username");

                                ImGui::SetCursorPos(ImVec2(20, 95));
                                ImGui::InputText("##Username", user_name, IM_ARRAYSIZE(user_name));
                            }
                            ImGui::PopItemWidth();

                            ImGui::PushItemWidth(260.f);
                            {
                                ImGui::SetCursorPos(ImVec2(22, 130));
                                ImGui::TextDisabled("Password");

                                ImGui::SetCursorPos(ImVec2(188, 130));
                                ImGui::TextDisabled("Forgot password?");

                                ImGui::SetCursorPos(ImVec2(20, 146));
                                ImGui::InputText("##Passowrd", pass_word, IM_ARRAYSIZE(pass_word));
                            }
                            ImGui::PopItemWidth();

                            ImGui::SetCursorPos(ImVec2(22, 190));
                            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 3.f);
                            if (ImGui::Button("Login", ImVec2(260.f, 30.f)))
                            {
                                login(ws);
								
                            }
                            ImGui::PopStyleVar();

                            ImGui::TextDisabled(texted.c_str());
                        }
                            else {
                                ImGui::SetCursorPos(ImVec2(118, 20));
								string s = "Welcome " + username;
                                ImGui::Text(s.c_str());
                            }


                        }
                        ImGui::EndChild();
                    }
                    ImGui::PopStyleColor(2);
                    ImGui::PopStyleVar(1);

                    ImGui::SetCursorPos(ImVec2(5, 445));
                    ImGui::TextDisabled("Loader base, made with <3 by ts");
                }
                ImGui::End();
            }
            else
            {
                exit(0);
            }
        }
        ImGui::EndFrame();
        g_pd3dDevice->SetRenderState(D3DRS_ZENABLE, FALSE);
        g_pd3dDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, FALSE);
        g_pd3dDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, FALSE);
        g_pd3dDevice->Clear(0, NULL, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, NULL, 1.0f, 0);
        if (g_pd3dDevice->BeginScene() >= 0)
        {
            ImGui::Render();
            ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
            g_pd3dDevice->EndScene();
        }

        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }

        HRESULT result = g_pd3dDevice->Present(NULL, NULL, NULL, NULL);

        if (result == D3DERR_DEVICELOST && g_pd3dDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET)
            ResetDevice();
        ws->poll();
        ws->dispatch(handle_message);
    }
  
    delete ws;
#ifdef _WIN32
    WSACleanup();
#endif
    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClass(wc.lpszClassName, wc.hInstance);

    return 0;
}
bool CreateDeviceD3D(HWND hWnd)
{
    if ((g_pD3D = Direct3DCreate9(D3D_SDK_VERSION)) == NULL)
        return false;

    ZeroMemory(&g_d3dpp, sizeof(g_d3dpp));
    g_d3dpp.Windowed = TRUE;
    g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    g_d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
    g_d3dpp.EnableAutoDepthStencil = TRUE;
    g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
    g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;
    if (g_pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hWnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &g_d3dpp, &g_pd3dDevice) < 0)
        return false;

    return true;
}

void CleanupDeviceD3D()
{
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = NULL; }
    if (g_pD3D) { g_pD3D->Release(); g_pD3D = NULL; }
}

void ResetDevice()
{
    ImGui_ImplDX9_InvalidateDeviceObjects();
    HRESULT hr = g_pd3dDevice->Reset(&g_d3dpp);
    if (hr == D3DERR_INVALIDCALL)
        IM_ASSERT(0);
    ImGui_ImplDX9_CreateDeviceObjects();
}

#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0
#endif

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED)
        {
            g_d3dpp.BackBufferWidth = LOWORD(lParam);
            g_d3dpp.BackBufferHeight = HIWORD(lParam);
            ResetDevice();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    case WM_DPICHANGED:
        if (ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_DpiEnableScaleViewports)
        {
            //const int dpi = HIWORD(wParam);
            //printf("WM_DPICHANGED to %d (%.0f%%)\n", dpi, (float)dpi / 96.0f * 100.0f);
            const RECT* suggested_rect = (RECT*)lParam;
            ::SetWindowPos(hWnd, NULL, suggested_rect->left, suggested_rect->top, suggested_rect->right - suggested_rect->left, suggested_rect->bottom - suggested_rect->top, SWP_NOZORDER | SWP_NOACTIVATE);
        }
        break;
    }
    return ::DefWindowProc(hWnd, msg, wParam, lParam);
}