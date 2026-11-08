# Sichere lokale Anmeldung

CCVM unterstützt eine lokale Anmeldung mit Benutzername, Passwort und verpflichtendem
sechsstelligen Authenticator-Code. Nach der Aktivierung schützt sie sämtliche
`/api/v1`-Funktionen. Die bisherigen Operator-Bearer-Tokens werden dann auch an den
Host-Inventur-Endpunkten abgewiesen. `/health` bleibt für die Betriebsüberwachung erreichbar.

Eine Sitzung hält höchstens acht Stunden und endet nach 30 Minuten ohne API-Aktivität.
Ein Neuladen der Seite stellt eine gültige Sitzung wieder her. „Abmelden“ widerruft sie
serverseitig. Das Cookie ist `Secure`, `HttpOnly`, `SameSite=Strict` und auf den aktuellen
Host beschränkt. Es gibt keine Speicherung von Passwörtern, Sitzungsschlüsseln oder
Operator-Tokens in Local Storage oder Session Storage. Mutierende API-Aufrufe benötigen
zusätzlich den CSRF-Wert und den exakten konfigurierten HTTPS-Ursprung.

## Veröffentlichung auf dem bestehenden Neptun

Voraussetzung ist eine vollständig verifizierte Host-Workspace-Veröffentlichung samt ihren
sechs erhaltenen Vorgänger-Journalen. Der neue Updater verlangt einen untätigen Worker,
prüft ein privates PostgreSQL-Backup und erhält sämtliche vorhandenen Datensätze,
verschlüsselten Scan-Zugangsdaten, Schlüssel, Container-IDs und HTTPS-Einstellungen.
Die additive Migration ergänzt ausschließlich `auth_users`, `auth_sessions` und
`auth_login_limits`. Es werden keine Host-Anmeldung und kein Scan ausgeführt.

Den vollständigen geprüften Merge-SHA verwenden:

```bash
cd /opt/ccvm
CCVM_LOGIN_TARGET='<REVIEWED_MERGE_SHA>'
git fetch origin sprint-1.0.2-feature-architecture
sudo -v
git show "${CCVM_LOGIN_TARGET}:scripts/update-secure-login.py" |
  python3 - --target "$CCVM_LOGIN_TARGET" --host neptun --apply
```

Ohne `--apply` erfolgt ausschließlich die Vorprüfung. Nach einer Unterbrechung denselben
SHA mit `--apply --resume` ausführen und das angegebene private Backup behalten. Der
Updater ersetzt keine laufenden Container und verändert weder den Gateway-Socket noch
die HAProxy-Konfiguration. Docker-Laufzeitfehler müssen anhand der privaten Diagnose
behoben werden; eine erneute Ausführung setzt die erhaltene Journalphase fort.

## Erstes Konto und Authenticator einrichten

Nach `VERIFIED` diesen Befehl **einzeln im privaten interaktiven Terminal auf Neptun**
ausführen. Nicht in einen Here-Document-Block oder eine Pipe einbauen:

```bash
sudo docker exec -it --user 0 --workdir /app ccvm-backend \
  python -m app.auth_admin bootstrap --origin https://ccvm.cloudcollab.de
```

Das Werkzeug fragt einen frei gewählten CCVM-Benutzernamen und ein Passwort mit
15–128 Zeichen ab. Der angezeigte Einrichtungsschlüssel wird einmalig in einer
Authenticator-App angelegt und anschließend durch einen aktuellen Code bestätigt.
Passwort, Einrichtungsschlüssel, URI und Authenticator-Codes nicht in Chats oder
Diagnoseausgaben kopieren. Es gibt kein Standardpasswort und keine öffentliche
Registrierung. Dieses CCVM-Konto ist unabhängig von den Windows-/SSH-Scan-Zugangsdaten.

Erst nach erfolgreicher Einrichtung und Speicherung aktiviert die CLI die lokale
Anmeldung. Danach die CCVM-Seite neu laden und für die erste Anmeldung den **nächsten
neuen Authenticator-Code** verwenden. Der beim Einrichten bestätigte Code kann nicht
noch einmal zur Anmeldung verwendet werden.

Die Aktivierungsdatei liegt auf dem Host unter
`/opt/ccvm/backend/.ccvm-auth/auth-policy.json` und im Container unter
`/app/.ccvm-auth/auth-policy.json`. Sie ist eine reguläre root-Datei mit Modus `0600`
in einem eigenen root-Verzeichnis. Vorhandene Scanner-Daten unter `.scanner-data`
bleiben unberührt. Eine vorhandene ungültige Aktivierungsdatei führt zu `503` und
niemals zu einem stillen Rückfall auf den Token-Zugang.

Die Veröffentlichung und der lokale Bootstrap sind bewusst getrennt: Bis die
Kontoeinrichtung abgeschlossen ist, bleibt die vorherige Token-Freischaltung erhalten.
Nach der Aktivierung gibt es keinen Token-Fallback im Browser. Eine erneute Prüfung
des Updaters erkennt den aktiven Anmeldemodus und erhält Konto, MFA, Sitzungen und
Aktivierungsdatei unverändert.

## Lokale Wiederherstellung

Bei vergessenem Passwort oder verlorenem Authenticator kann ein Administrator mit
root-Zugriff das bestehende Konto im privaten Terminal erneuern:

```bash
sudo docker exec -it --user 0 --workdir /app ccvm-backend \
  python -m app.auth_admin reset --username '<CCVM-BENUTZERNAME>'
```

Der Vorgang verlangt ein neues Passwort und eine neue bestätigte Authenticator-Einrichtung
und widerruft alle Sitzungen. Die HTTP-API bietet keinen Reset-Endpunkt. Bei einer seltenen
Unterbrechung zwischen Kontospeicherung und Richtlinienaktivierung dient ausschließlich
folgender lokaler Befehl zur Fortsetzung:

```bash
sudo docker exec -it --user 0 --workdir /app ccvm-backend \
  python -m app.auth_admin activate --origin https://ccvm.cloudcollab.de
```

Bestehende Vault-Schlüssel müssen erhalten bleiben: Mit ihnen werden weiterhin die
gespeicherten Scan-Zugangsdaten und mit getrennt abgeleitetem Schlüssel die MFA-Secrets
entschlüsselt. Passwort-Hashes und Sitzungsschlüssel-Verifier liegen in PostgreSQL;
roh verwendbare Sitzungsschlüssel werden dort nicht gespeichert. Die Anmeldung
verwendet Argon2id, zeitlich begrenzte Anmeldebremsen und atomaren Schutz vor der
erneuten Verwendung desselben TOTP-Zeitschritts.

## Prüfung

`backend/integration/authenticated_deployment.py --secure-login-update` führt die echte
Veröffentlichungskette auf einem leeren, kurzlebigen CI-Runner aus. Sie prüft die
additive Migration auf vorhandenen Kunden-/Inventur-/Befunddaten, gestoppte Dienste
mit `--resume`, native TLS-/PROXY-/nginx-Routen, Passwort plus MFA, Cookie-Eigenschaften,
Sitzungswiederherstellung, CSRF, fremde Origins, Abmeldung, abgewiesene alte Tokens und
eine unverändernde Wiederholungsprüfung nach der Aktivierung. Die dort erzeugten Konten
und Geheimnisse sind ausschließlich synthetische CI-Daten.
