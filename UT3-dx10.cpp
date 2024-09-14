#include <windows.h>
#include <strsafe.h>
#include <dxgi.h>

constexpr DWORD offsetD3DX10Check = 0xE7BDC5;
constexpr DWORD offsetDenominatorFix = 0xE7CF51;
constexpr DWORD offsetNumeratorSet = 0xE7CF6D;
constexpr BYTE badDenominator[]{ 0xB8, 0x01, 0x00, 0x00, 0x00, 0x89, 0x44, 0x24, 0x6C };
constexpr BYTE badNumerator[] { 0xC7, 0x44, 0x24, 0x6C, 0x3C, 0x00, 0x00, 0x00 };

#ifdef _UNICODE
int WINAPI wWinMain( _In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nShowCmd )
#else
int WINAPI WinMain( _In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd )
#endif
{
	TCHAR path[4096];
	GetModuleFileName( nullptr, path, MAX_PATH );
	wcsrchr( path, L'\\' )[1] = 0;
	StringCbCat( path, sizeof( path ), TEXT( "UT3_steam.exe" ) );
	StringCbCat( path, sizeof( path ), TEXT(" -d3d10 -msaa") );
	if ( *lpCmdLine )
	{
		StringCbCat( path, sizeof( path ), TEXT( " " ) );
		StringCbCat( path, sizeof( path ), lpCmdLine );
	}

	STARTUPINFOW si{};
	si.cb = sizeof( si );
	PROCESS_INFORMATION pi{};
	if ( !CreateProcess( nullptr, path, nullptr, nullptr, false, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi ) )
		return -1;

	CONTEXT context{};
	context.ContextFlags = CONTEXT_INTEGER;
	GetThreadContext( pi.hThread, &context );

	PBYTE pBaseAddr = nullptr;
	ReadProcessMemory( pi.hProcess, reinterpret_cast<PVOID>( context.Ebx + 8 ), &pBaseAddr, sizeof( pBaseAddr ), nullptr );

	// Patch incorrect check for D3DX10CheckVersion
	if ( BYTE inst = 0; ReadProcessMemory( pi.hProcess, pBaseAddr + offsetD3DX10Check, &inst, sizeof( inst ), nullptr ) && inst == 0x75 /*jnz*/ )
	{
		DWORD old;
		VirtualProtectEx( pi.hProcess, pBaseAddr + offsetD3DX10Check, sizeof( inst ), PAGE_READWRITE, &old );
		inst = 0x74;
		WriteProcessMemory( pi.hProcess, pBaseAddr + offsetD3DX10Check, &inst, sizeof( inst ), nullptr );
		VirtualProtectEx( pi.hProcess, pBaseAddr + offsetD3DX10Check, sizeof( inst ), old, &old );
	}

	// Patch hardcoded 60Hz refresh
	if ( IDXGIFactory1 *pDxgiFactory; SUCCEEDED( CreateDXGIFactory1( IID_PPV_ARGS( &pDxgiFactory ) ) ) )
	{
		IDXGIAdapter* adapter;
		for ( UINT adapterIdx = 0; SUCCEEDED( pDxgiFactory->EnumAdapters( adapterIdx, &adapter ) ); ++adapterIdx )
		{
			DXGI_ADAPTER_DESC adesc;
			adapter->GetDesc( &adesc );
			if ( adesc.VendorId == 0x1414 && adesc.DeviceId == 0x8c ) // skip microsoft basic driver
			{
				adapter->Release();
				continue;
			}

			IDXGIOutput *output = nullptr;
			for ( UINT outputIdx = 0; SUCCEEDED( adapter->EnumOutputs( outputIdx, &output ) ); outputIdx++ )
			{
				// Get desktop's refresh rate
				DXGI_MODE_DESC search {}, monitor {};
				search.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
				DXGI_OUTPUT_DESC desc;
				output->GetDesc( &desc );
				search.Width = desc.DesktopCoordinates.right - desc.DesktopCoordinates.left;
				search.Height = desc.DesktopCoordinates.bottom - desc.DesktopCoordinates.top;
				output->FindClosestMatchingMode( &search, &monitor, nullptr );
				output->Release();

				// There is not enough space to patch denominator inline, create thunk
				if ( BYTE denominator[ARRAYSIZE( badDenominator )]; ReadProcessMemory( pi.hProcess, pBaseAddr + offsetDenominatorFix, denominator, sizeof( denominator ), nullptr ) && !memcmp( denominator, badDenominator, sizeof( denominator ) ) )
				{
					BYTE fix[]{ 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x70, 0x00, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00 };
					*reinterpret_cast<UINT *>( fix + 9 ) = monitor.RefreshRate.Denominator;

					PVOID addr = VirtualAllocEx( pi.hProcess, nullptr, sizeof( fix ), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
					*reinterpret_cast<DWORD *>( fix + 14 ) = reinterpret_cast<DWORD>( pBaseAddr + offsetDenominatorFix + sizeof( denominator ) ) - ( reinterpret_cast<DWORD>( addr ) + sizeof( fix ) );
					WriteProcessMemory( pi.hProcess, addr, fix, sizeof( fix ), nullptr );

					memset( denominator, 0x90, sizeof( denominator ) );
					denominator[0] = 0xE9;
					*reinterpret_cast<DWORD *>( denominator + 1 ) = reinterpret_cast<DWORD>( addr ) - reinterpret_cast<DWORD>( pBaseAddr + offsetDenominatorFix + 5 );
					DWORD old, old2;
					VirtualProtectEx( pi.hProcess, pBaseAddr + offsetDenominatorFix, sizeof( denominator ), PAGE_READWRITE, &old );
					WriteProcessMemory( pi.hProcess, pBaseAddr + offsetDenominatorFix, denominator, sizeof( denominator ), nullptr );
					VirtualProtectEx( pi.hProcess, pBaseAddr + offsetDenominatorFix, sizeof( denominator ), old, &old2 );

					VirtualProtectEx( pi.hProcess, addr, sizeof( fix ), old, &old2 );
				}

				BYTE numerator[ARRAYSIZE( badNumerator )];
				ReadProcessMemory( pi.hProcess, pBaseAddr + offsetNumeratorSet, numerator, sizeof( numerator ), nullptr );
				if ( !memcmp( numerator, badNumerator, sizeof( numerator ) ) )
				{
					*reinterpret_cast<UINT *>( numerator + 4 ) = monitor.RefreshRate.Numerator;

					DWORD old;
					VirtualProtectEx( pi.hProcess, pBaseAddr + offsetNumeratorSet, sizeof( numerator ), PAGE_READWRITE, &old );
					WriteProcessMemory( pi.hProcess, pBaseAddr + offsetNumeratorSet, numerator, sizeof( numerator ), nullptr );
					VirtualProtectEx( pi.hProcess, pBaseAddr + offsetNumeratorSet, sizeof( numerator ), old, &old );
				}

				break; // Grab info from first display only
			}

			adapter->Release();
			break; // UT3 uses first adapter returned from DXGI
		}

		pDxgiFactory->Release();
	}

	ResumeThread( pi.hThread );
	CloseHandle( pi.hProcess );
	CloseHandle( pi.hThread );
	return 0;
}
