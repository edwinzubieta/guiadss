#!/usr/bin/env bash
# Configura el entorno completo del proyecto en un solo comando.
set -e

# 🔥 Forzar uso de Python 3.11 de Homebrew
PYTHON_BIN="/opt/homebrew/bin/python3.11"

# Verificar que exista
if [ ! -f "$PYTHON_BIN" ]; then
  echo "✗ No se encontró Python 3.11 en $PYTHON_BIN"
  echo "Instálalo con: brew install python@3.11"
  exit 1
fi

# Verificar versión
python_version=$($PYTHON_BIN -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")

if $PYTHON_BIN -c "import sys; exit(0 if sys.version_info >= (3,11) else 1)"; then
  echo "✓ Python $python_version detectado"
else
  echo "✗ Se requiere Python 3.11+. Versión actual: $python_version"
  exit 1
fi

# Crear entorno virtual
if [ ! -d ".venv" ]; then
  echo "→ Creando entorno virtual..."
  $PYTHON_BIN -m venv .venv
fi

# Activar entorno
source .venv/bin/activate
echo "✓ Entorno virtual activado"

# Asegurar pip actualizado
python -m pip install --upgrade pip -q

# Instalar dependencias del servidor
echo "→ Instalando dependencias del servidor..."
pip install -q -r server/requirements.txt

# Instalar dependencias del cliente
echo "→ Instalando dependencias del cliente..."
pip install -q -r client/requirements.txt

# Instalar pytest para tests
echo "→ Instalando pytest..."
pip install -q pytest pytest-asyncio

echo ""
echo "✓ Setup completo."
echo ""
echo "Para iniciar el servidor:"
echo "  source .venv/bin/activate"
echo "  cd server && uvicorn server:app --reload"
echo ""
echo "Para conectar un cliente (nueva terminal):"
echo "  source .venv/bin/activate"
echo "  cd client && python client.py alice"
echo ""
echo "Interfaz web: http://localhost:8000"
echo ""
echo "Para correr los tests:"
echo "  source .venv/bin/activate"
echo "  cd client && python -m pytest tests/ -v"
echo ""