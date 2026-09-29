# TUI BugTraceAI v2.0.1

## Instalación

```bash
./install_tui.sh
```

## Inicio

```bash
./run_tui.sh
```

Desde la interfaz:

1. Seleccionar configuración.
2. `Verificar`.
3. `Resetear`.
4. `Iniciar`.

Controles: `p` pausa/reanuda, `s` detiene y `q` sale. La pausa usa SIGSTOP/SIGCONT sobre todo el grupo del runtime. Detener usa SIGTERM.

La salida técnica completa se conserva en `logs/tui-runtime.log`; el panel muestra solamente eventos importantes.

## BugTraceAI v2.2

La TUI utiliza los scripts autoritativos de esta versión:

```bash
./install_tui.sh
./run_tui.sh
```

Los botones ejecutan:

- Verificar: `python3 selftest_v220.py`
- Resetear: `./reset_v220.sh <config>`
- Iniciar: `./run_v220_auto.sh 500`

El panel activo muestra por separado:

- estado operativo del Analysis Item;
- veredicto de vulnerabilidad;
- estado de explotación;
- bitácora y último resultado del Executor.

## v2.6.0d

El botón **Iniciar** ejecuta `run_v260d_auto.sh 500` y transmite la configuración elegida mediante `BUGTRACEAI_CONFIG`. El TUI no decide estados ni modifica evidencia; solo inicia/pausa/detiene el proceso y lee `data/knowledge.json` y logs.
