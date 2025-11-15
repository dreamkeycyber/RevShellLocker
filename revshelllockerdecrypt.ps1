

function Unprotect-AESFile {
    Param(
        [Byte[]]$FileBytes,
        [String]$Password,
        [Byte[]]$Salt,
        [String]$HashAlgorithm = "SHA512"
    )

    $PasswordBytes = [System.Text.Encoding]::ASCII.GetBytes($Password)

    $SaltBytes = $FileBytes[0..15]
    $EncryptedBytes = $FileBytes[16..($FileBytes.Length - 1)]

    [System.IO.MemoryStream]$MemoryStream = New-Object System.IO.MemoryStream
    [System.Security.Cryptography.Aes]$AES = [System.Security.Cryptography.Aes]::Create()
    $AES.KeySize = 256
    $AES.BlockSize = 128
    [System.Security.Cryptography.Rfc2898DeriveBytes]$Key = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($PasswordBytes, $SaltBytes, 1000, [System.Security.Cryptography.HashAlgorithmName]::$HashAlgorithm)
    $AES.Key = $Key.GetBytes($AES.KeySize / 8)
    $AES.IV = $Key.GetBytes($AES.BlockSize / 8)
    $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($MemoryStream, $AES.CreateDecryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write)

    try {
        $CryptoStream.Write($EncryptedBytes, 0, $EncryptedBytes.Length)
        $CryptoStream.Close()
    } catch {
        Write-Error "Error occurred while decoding file. Password, Salt, or HashAlgorithm incorrect?"
        return $null
    }

    return $MemoryStream.ToArray()
}

function Decrypt-FilesInDirectory {
    Param(
        [string]$DirectoryPath,
        [string]$Password
    )

    Write-Host "Decrypting all files in directory: $DirectoryPath"

    $SecurePassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString -String $Password -AsPlainText -Force)))

    Get-ChildItem -Path $DirectoryPath -File | ForEach-Object {
        $FilePath = $_.FullName
        $FileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        $DecryptedBytes = Unprotect-AESFile -FileBytes $FileBytes -Password $SecurePassword
        if ($DecryptedBytes) {
            [System.IO.File]::WriteAllBytes($FilePath, $DecryptedBytes)
            Write-Host "File decrypted: $FilePath"
        } else {
            Write-Host "Failed to decrypt the file: $FilePath"
        }
    }
}

function Decrypt-File {
    Param(
        [string]$FilePath,
        [string]$Password
    )

    Write-Host "Starting decryption for file: $FilePath"

    $SecurePassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString -String $Password -AsPlainText -Force)))

    $FileBytes = [System.IO.File]::ReadAllBytes($FilePath)
    $DecryptedBytes = Unprotect-AESFile -FileBytes $FileBytes -Password $SecurePassword
    if ($DecryptedBytes) {
        [System.IO.File]::WriteAllBytes($FilePath, $DecryptedBytes)
        Write-Host "File decrypted successfully."
    } else {
        Write-Host "Failed to decrypt the file."
    }
}


