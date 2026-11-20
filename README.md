# NEXUS Cyber Account Web

## Starten
1. Node.js 18+ installieren.
2. Im Projektordner ausführen:
   node server.js
3. Browser öffnen:
   http://localhost:3000

Die App nutzt nur Node.js-Bordmittel. Benutzer werden lokal in `users.json` gespeichert.
Passwörter werden mit Node.js `scrypt` gehasht und nicht im Klartext gespeichert.

Für echtes öffentliches Hosting sollte zusätzlich HTTPS, ein Reverse Proxy und eine echte Produktionsdatenbank verwendet werden.
