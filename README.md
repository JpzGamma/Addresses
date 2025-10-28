Convierte un FQDN en direcciones IPv4 (/32) y las sube a FortiGate como Firewall Addresses y como miembros de un Address Group.

Incluye:
-Descubrimiento DNS paralelo (sistema, públicos, autoritativos), seguimiento de CNAME.
-Persistencia en ips.txt y ips.csv.
-Push a FortiGate con Bearer Token, rate limit y reintentos.
-Frontend Flask con barra de progreso y logs en vivo (SSE).

Pasos para descargar:
# 1) Clonar el repo
git clone https://github.com/JpzGamma/Addresses.git

cd Addresses

# 2) Crear y activar venv (Linux/Mac)
python3 -m venv .venv

source .venv/bin/activate

# 3) Instalar librerías
pip install --upgrade pip

pip install flask dnspython requests

Ejecutar front:
1) source .venv/bin/activate

2)  python3 front_app.py

Ejecutar solo el back:

python3 ListIp.py \
  -d browser.events.data.microsoft.com \
  --fg-host https://44.221.165.216:10443 \
  --fg-token 'TU_TOKEN_API' \
  --fg-vdom root \
  --fg-group 'MS_BrowserEvents' \
  --workers 60 --reps 4 --bursts 6 --nochange 3 -v \
  --fg-rate-limit 2 --fg-batch-size 10 --fg-batch-delay 5 \
  --fg-insecure

