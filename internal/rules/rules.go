// Package rules describe las señales de riesgo que busca repoguard, linea por linea.
//
// Cada regla apunta a un comportamiento que el malware real usa en repositorios falsos de herramientas:
// descargar y ejecutar codigo, esconderlo, robar credenciales, mandarlas afuera o quedarse instalado.
// Una coincidencia no prueba que el repo sea malicioso: por eso cada regla explica por que importa.
package rules

import (
	"regexp"

	"github.com/ulisespignatelli/repoguard/internal/finding"
)

// Categorias (se usan para agrupar y para correlacionar).
const (
	CatRemoteExec  = "ejecución remota"
	CatObfuscation = "ofuscación"
	CatExfil       = "envío de datos"
	CatCreds       = "acceso a credenciales"
	CatPersistence = "persistencia"
	CatEvasion     = "evasión"
	CatDestructive = "destructivo"
	CatInstall     = "instalación"
	CatBinary      = "binarios"
	CatSupply      = "cadena de suministro"
	CatEditor      = "editor"
	CatUnicode     = "unicode engañoso"
	CatCorrelation = "correlación"
)

// Rule es una señal que se busca en cada linea de texto.
type Rule struct {
	ID       string
	Category string
	Title    string
	Severity finding.Severity
	Keywords []string // en minusculas: filtro rapido antes de la regex
	Pattern  *regexp.Regexp
	Why      string
}

var re = regexp.MustCompile

// All devuelve las reglas de linea.
func All() []Rule {
	return []Rule{
		{ID: "remote-pipe-shell", Category: CatRemoteExec, Severity: finding.Critical,
			Title:    "Descarga un script y lo ejecuta directamente",
			Keywords: []string{"curl", "wget"},
			Pattern:  re(`(?i)\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?python[0-9.]*\b`),
			Why:      "Lo que se ejecuta lo decide el servidor en ese momento, no el código que revisaste: puede cambiar en cualquier descarga."},
		{ID: "powershell-download-exec", Category: CatRemoteExec, Severity: finding.Critical,
			Title:    "PowerShell descarga código y lo ejecuta en memoria",
			Keywords: []string{"iex", "invoke-expression"},
			Pattern:  re(`(?i)(\biex\b|invoke-expression).{0,120}(downloadstring|downloaddata|invoke-webrequest|\biwr\b|net\.webclient|invoke-restmethod|\birm\b)|(downloadstring|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b).{0,160}\|\s*(iex|invoke-expression)\b`),
			Why:      "Es la técnica más común de los cargadores de malware en Windows: nada queda en disco para revisar."},
		{ID: "code-download-exec", Category: CatRemoteExec, Severity: finding.Critical,
			Title:    "Ejecuta como código lo que descarga de internet",
			Keywords: []string{"exec", "eval"},
			Pattern:  re(`(?i)\b(exec|eval)\s*\(\s*(await\s+)?(requests\.(get|post)|urllib\.request\.urlopen|urlopen|httpx\.get|fetch|axios\.get|https?\.get)\s*\(`),
			Why:      "El código real no está en el repositorio: se baja y se ejecuta al momento."},
		{ID: "decode-exec", Category: CatObfuscation, Severity: finding.Critical,
			Title:    "Decodifica texto oculto y lo ejecuta",
			Keywords: []string{"exec", "eval", "function("},
			Pattern:  re(`(?i)\b(exec|eval|new\s+function)\s*\(\s*(__import__\(\s*['"](base64|zlib|codecs|marshal)['"]\s*\)|base64\.(b64|b32|b85|a85)?decode|codecs\.decode|bytes\.fromhex|zlib\.decompress|marshal\.loads|binascii\.(a2b|unhexlify)|atob\s*\(|buffer\.from\s*\()`),
			Why:      "Esconder código detrás de base64, zlib o marshal y ejecutarlo es la marca típica del malware en Python y JavaScript."},
		{ID: "powershell-encoded", Category: CatObfuscation, Severity: finding.High,
			Title:    "PowerShell con comando codificado",
			Keywords: []string{"powershell", "pwsh", "frombase64string"},
			Pattern:  re(`(?i)\b(powershell|pwsh)(\.exe)?\b.{0,60}\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}|\[convert\]::frombase64string\(`),
			Why:      "Un comando codificado oculta lo que hace: hay que decodificarlo para saberlo."},
		{ID: "exfil-discord", Category: CatExfil, Severity: finding.High,
			Title:    "Envía datos a un webhook de Discord",
			Keywords: []string{"discord"},
			Pattern:  re(`(?i)discord(app)?\.com/api/webhooks/\d+/`),
			Why:      "Los webhooks de Discord son el canal favorito de los ladrones de credenciales: gratis, anónimos y difíciles de bloquear."},
		{ID: "exfil-telegram", Category: CatExfil, Severity: finding.High,
			Title:    "Usa la API de bots de Telegram",
			Keywords: []string{"api.telegram.org"},
			Pattern:  re(`(?i)api\.telegram\.org/bot`),
			Why:      "Muy usado para mandar datos robados a un chat del atacante. Puede ser legítimo en una herramienta de notificaciones: revisá qué se envía."},
		{ID: "exfil-paste", Category: CatExfil, Severity: finding.High,
			Title:    "Usa un servicio de pegado o de captura de peticiones",
			Keywords: []string{"pastebin", "paste.ee", "hastebin", "transfer.sh", "webhook.site", "requestbin", "pipedream", "ngrok"},
			Pattern:  re(`(?i)(pastebin\.com/(raw/)?[a-z0-9]{6,}|paste\.ee/[rp]/|hastebin\.com|transfer\.sh/|webhook\.site/|requestbin|\.pipedream\.net|ngrok(-free)?\.(io|app|dev))`),
			Why:      "Sirven para bajar cargas que cambian sin tocar el repo, o para sacar datos de la máquina."},
		{ID: "raw-ip-url", Category: CatExfil, Severity: finding.Medium,
			Title:    "Se conecta a una dirección IP pública escrita en el código",
			Keywords: []string{"http"},
			Pattern:  re(`(?i)\bhttps?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?`),
			Why:      "El software legítimo suele usar dominios; una IP fija es común en servidores de control de malware."},
		{ID: "creds-ssh", Category: CatCreds, Severity: finding.High,
			Title:    "Accede a claves SSH del usuario",
			Keywords: []string{".ssh", "id_rsa", "id_ed25519"},
			Pattern:  re(`(?i)\.ssh[/\\](id_[a-z0-9]+|authorized_keys)|\bid_(rsa|ed25519|ecdsa)\b`),
			Why:      "Con tus claves SSH un atacante entra a tus servidores y repositorios."},
		{ID: "creds-cloud", Category: CatCreds, Severity: finding.High,
			Title:    "Accede a credenciales de nube o de desarrollo",
			Keywords: []string{".aws", ".azure", "gcloud", ".kube", ".docker", ".git-credentials", ".npmrc", ".pypirc", ".netrc"},
			Pattern:  re(`(?i)\.aws[/\\](credentials|config)|\.azure[/\\]|gcloud[/\\](credentials|application_default|legacy_credentials)|\.kube[/\\]config|\.docker[/\\]config\.json|\.git-credentials|\.npmrc|\.pypirc|\.netrc`),
			Why:      "Son las credenciales más buscadas por el malware que apunta a desarrolladores y equipos de seguridad."},
		{ID: "creds-browser", Category: CatCreds, Severity: finding.High,
			Title:    "Accede a datos guardados del navegador",
			Keywords: []string{"login data", "local state", "cookies", "user data", "firefox", "key4.db", "logins.json"},
			Pattern:  re(`(?i)['"/\\](login data|local state|cookies)['"]|user data[/\\]|mozilla[/\\]firefox[/\\]profiles|key4\.db|logins\.json`),
			Why:      "Ahí están las contraseñas, cookies de sesión y tarjetas guardadas en el navegador."},
		{ID: "creds-wallet", Category: CatCreds, Severity: finding.High,
			Title:    "Busca billeteras de criptomonedas",
			Keywords: []string{"wallet", "exodus", "electrum", "metamask", "nkbihfbeogaeaoehlefnkodbefgpgknn", "phantom"},
			Pattern:  re(`(?i)wallet\.dat|exodus[/\\]|electrum[/\\]wallets|nkbihfbeogaeaoehlefnkodbefgpgknn|metamask.{0,20}(vault|local storage|extension)|phantom.{0,20}(local storage|extension)`),
			Why:      "Robar billeteras es uno de los objetivos más comunes de los infostealers."},
		{ID: "env-dump", Category: CatCreds, Severity: finding.Medium,
			Title:    "Copia todas las variables de entorno",
			Keywords: []string{"environ", "process.env", "printenv"},
			Pattern:  re(`(?i)(dict|json\.dumps|str)\s*\(\s*os\.environ\s*\)|json\.stringify\s*\(\s*process\.env\s*\)|\bprintenv\b\s*(>|\|)|os\.environ\.copy\(\)\s*$`),
			Why:      "Las variables de entorno suelen tener tokens y claves; copiarlas todas solo tiene sentido si se van a guardar o enviar."},
		{ID: "persistence-cron", Category: CatPersistence, Severity: finding.High,
			Title:    "Se programa para ejecutarse solo (cron)",
			Keywords: []string{"crontab", "/etc/cron"},
			Pattern:  re(`(?i)\(\s*crontab\s+-l|crontab\s+-\s*$|crontab\s+[^-\s]|/etc/cron\.(d|hourly|daily)|>>\s*/etc/crontab`),
			Why:      "Una herramienta no necesita reinstalarse sola: es una forma clásica de que el malware sobreviva a un reinicio."},
		{ID: "persistence-windows", Category: CatPersistence, Severity: finding.High,
			Title:    "Se agrega al inicio de Windows o macOS",
			Keywords: []string{"currentversion", "schtasks", "startup", "launchagents", "launchdaemons"},
			Pattern:  re(`(?i)currentversion\\+run|schtasks(\.exe)?\s+/create|start menu\\+programs\\+startup|launchagents/|launchdaemons/`),
			Why:      "Hace que el programa arranque solo con el sistema."},
		{ID: "persistence-shellrc", Category: CatPersistence, Severity: finding.Medium,
			Title:    "Modifica el perfil del shell",
			Keywords: []string{"bashrc", "zshrc", ".profile"},
			Pattern:  re(`(?i)>>\s*\S*\.(bashrc|zshrc|bash_profile|profile)\b`),
			Why:      "Puede ser legítimo (agregar algo al PATH), pero también sirve para ejecutar código en cada terminal nueva. Revisá qué agrega."},
		{ID: "evasion", Category: CatEvasion, Severity: finding.High,
			Title:    "Desactiva protecciones o borra rastros",
			Keywords: []string{"mppreference", "history", "histfile", "wevtutil", "setenforce", "ufw"},
			Pattern:  re(`(?i)set-mppreference\s+.*-disable|add-mppreference\s+-exclusion|disablerealtimemonitoring|\bhistory\s+-c\b|unset\s+histfile|histfile=/dev/null|wevtutil(\.exe)?\s+cl\b|setenforce\s+0|ufw\s+disable`),
			Why:      "Una herramienta legítima no necesita apagar el antivirus ni borrar el historial."},
		{ID: "destructive", Category: CatDestructive, Severity: finding.High,
			Title:    "Comando destructivo",
			Keywords: []string{"rm ", "mkfs", "dd ", "format "},
			Pattern:  re(`(?i)\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(--no-preserve-root\s+)?(/|~|\$home)(\s|$|/\*)|\bmkfs\.[a-z0-9]+\s+/dev/|\bdd\s+if=/dev/(zero|urandom)\s+of=/dev/(sd|nvme|hd)|\bformat\s+c:`),
			Why:      "Puede borrar el sistema o el directorio personal."},
		{ID: "dep-remote", Category: CatSupply, Severity: finding.Medium,
			Title:    "Instala una dependencia desde una URL o un repo git",
			Keywords: []string{"git+", "http"},
			Pattern:  re(`(?i)^\s*(-e\s+)?(git\+|https?://)\S+`),
			Why:      "No pasa por el registro de paquetes: el contenido puede cambiar sin versión ni control."},
	}
}
