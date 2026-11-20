#include <windows.h>
#include <d3d9.h>

int main()
{
    WNDCLASSEXA wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_OWNDC;
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(nullptr);
    wc.lpszClassName = "testhost";
    RegisterClassExA(&wc);

    HWND hwnd = CreateWindowExA(0, wc.lpszClassName, "testhost", WS_POPUP,
                                0, 0, 256, 256, nullptr, nullptr, wc.hInstance, nullptr);
    ShowWindow(hwnd, SW_HIDE);

    IDirect3D9Ex* d3d = nullptr;
    Direct3DCreate9Ex(D3D_SDK_VERSION, &d3d);

    D3DPRESENT_PARAMETERS pp = {};
    pp.BackBufferWidth = 256;
    pp.BackBufferHeight = 256;
    pp.BackBufferFormat = D3DFMT_A8R8G8B8;
    pp.BackBufferCount = 1;
    pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    pp.hDeviceWindow = hwnd;
    pp.Windowed = TRUE;
    pp.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;

    IDirect3DDevice9Ex* device = nullptr;
    d3d->CreateDeviceEx(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hwnd,
                        D3DCREATE_HARDWARE_VERTEXPROCESSING, &pp, nullptr, &device);

    IDirect3DTexture9* tex = nullptr;
    device->CreateTexture(256, 256, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_DEFAULT, &tex, nullptr);
    device->SetTexture(0, tex);

    // Draw one fullscreen triangle so the driver processes the texture state and
    // populates the resource's inner GPU buffer (hRes+0x48).  Without a real draw
    // the driver never initialises that field and [hRes+0x48]=0 at Release() time,
    // so the hardware watchpoint has nothing to arm on.
    struct Vert { float x, y, z; };
    static const Vert kTri[3] = { {-1,-1,0}, {3,-1,0}, {-1,3,0} };
    device->BeginScene();
    device->DrawPrimitiveUP(D3DPT_TRIANGLELIST, 1, kTri, sizeof(Vert));
    device->EndScene();

    tex->Release();

    for (int i = 0; i < 20; ++i) {
        device->ResetEx(&pp, nullptr);
        device->BeginScene();
        device->EndScene();
        device->Present(nullptr, nullptr, nullptr, nullptr);
    }

    return 0;
}
