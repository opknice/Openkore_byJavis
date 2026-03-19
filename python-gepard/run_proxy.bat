@echo off
chcp 65001 >nul
echo ========================================
echo   BamBoo Gepard V3 Proxy for OpenKore
echo ========================================
echo.
echo Step 1: This will start the proxy
echo Step 2: Start BamBoo_Client and login
echo Step 3: Start OpenKore (server: 127.0.0.1 port: 24657)
echo.
echo Press Ctrl+C to stop
echo.
python ro_packet_parser_v3_proxy_mitm.py
pause
