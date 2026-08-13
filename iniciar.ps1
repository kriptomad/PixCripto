<#
    Inicia o PixCripto completo: backend (API/blockchain) + frontend (site React)
    + (opcional) painel de administracao.

    Uso basico (backend + frontend, o suficiente para usar o site):
        cd C:\Users\costabr\PycharmProjects\Teste\PixCripto
        .\iniciar.ps1

    Uso completo (backend + frontend + painel de admin):
        .\iniciar.ps1 -IncluirAdmin

    Se a porta do admin panel (padrao 8600) estiver bloqueada no Windows
    (erro "WinError 10013"), escolha outra porta:
        .\iniciar.ps1 -IncluirAdmin -PortaAdmin 8601

    Cada servico abre em uma janela propria do PowerShell, entao da para ver
    os logs de cada um separadamente. Feche as janelas (ou Ctrl+C dentro
    delas) para parar os servidores.

    O painel do operador (admin_panel) e uma ferramenta manual/sensivel
    (configura rede, sancoes, e dispara o build de distribuicao) - por isso
    fica de fora por padrao e so sobe com -IncluirAdmin.
#>

param(
    [switch]$IncluirAdmin,
    [int]$PortaAdmin = 8600
)

$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$pythonExe = Join-Path $root "..\.venv\Scripts\python.exe"
$nodeBin = "C:\Users\costabr\PycharmProjects\Teste\tools\node2\node-v22.20.0-win-x64"
$frontendDir = Join-Path $root "frontend"

if (-not (Test-Path $pythonExe)) {
    Write-Host "ERRO: python venv nao encontrado em $pythonExe" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $frontendDir)) {
    Write-Host "ERRO: pasta frontend nao encontrada em $frontendDir" -ForegroundColor Red
    exit 1
}

function Test-PortaLivre {
    param([int]$Porta)
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Porta)
        $listener.Start()
        $listener.Stop()
        return $true
    } catch {
        return $false
    }
}

# --- Backend (API + blockchain + node P2P) ---------------------------------
if (-not (Test-PortaLivre -Porta 8000)) {
    Write-Host "AVISO: a porta 8000 ja parece estar em uso (backend ja rodando?)." -ForegroundColor Yellow
}
Write-Host "Iniciando backend (API/blockchain) em http://127.0.0.1:8000 ..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList @(
    "-NoExit", "-Command",
    "cd '$root'; & '$pythonExe' main.py"
)

# --- Frontend (site React) --------------------------------------------------
Write-Host "Iniciando frontend (site) ..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList @(
    "-NoExit", "-Command",
    "cd '$frontendDir'; `$env:PATH = '$nodeBin;' + `$env:PATH; npm run dev"
)

# --- Painel de administracao (opcional) -------------------------------------
if ($IncluirAdmin) {
    if (-not (Test-PortaLivre -Porta $PortaAdmin)) {
        Write-Host ""
        Write-Host "ERRO: a porta $PortaAdmin esta bloqueada ou reservada pelo Windows (isso" -ForegroundColor Red
        Write-Host "causa o 'WinError 10013'). Diagnostico:" -ForegroundColor Red
        Write-Host "  netsh interface ipv4 show excludedportrange protocol=tcp" -ForegroundColor Yellow
        Write-Host "Solucao: rode novamente com outra porta, ex:" -ForegroundColor Yellow
        Write-Host "  .\iniciar.ps1 -IncluirAdmin -PortaAdmin 8601" -ForegroundColor Yellow
        Write-Host "(o painel admin NAO sobe desta vez; backend e frontend continuam ok)" -ForegroundColor Yellow
    } else {
        Write-Host "Iniciando painel de administracao em http://127.0.0.1:$PortaAdmin ..." -ForegroundColor Cyan
        Start-Process powershell -ArgumentList @(
            "-NoExit", "-Command",
            "cd '$root'; `$env:PIXCRIPTO_ADMIN_PANEL_PORT = '$PortaAdmin'; & '$pythonExe' admin_panel\main.py"
        )
    }
}

Write-Host ""
Write-Host "Servicos iniciados:" -ForegroundColor Green
Write-Host "  1) Backend  -> http://127.0.0.1:8000"
Write-Host "  2) Frontend -> a URL exata aparece no console da janela do Vite (normalmente http://127.0.0.1:5173)"
if ($IncluirAdmin) {
    Write-Host "  3) Painel admin -> http://127.0.0.1:$PortaAdmin"
} else {
    Write-Host ""
    Write-Host "Painel de administracao NAO foi iniciado. Para incluir, rode:" -ForegroundColor Yellow
    Write-Host "  .\iniciar.ps1 -IncluirAdmin"
}
