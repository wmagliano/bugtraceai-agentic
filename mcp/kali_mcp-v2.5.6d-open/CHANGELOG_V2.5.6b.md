# Kali MCP v2.5.6b

- Assets autocontenidos en `assets/`.
- `scripts/create_assets.sh` regenera `brute.txt` y `benign_phpinfo.php`.
- El servidor ejecuta comandos con su propio directorio como `cwd`, permitiendo rutas relativas `assets/...`.
- `install_kali_assets.sh` sincroniza servidor, wrapper y assets al directorio activo.
- `bootstrap_mcp.sh` genera, instala y valida.
