Co se 15. září 2026 stalo s AI roboty na evropském webu: data a podklady
==========================================================================

Tento repozitář obsahuje všechna data, výstupy, předpovědi zapsané před měřením, skripty a snímky citovaných stránek ke článku „Co se 15. září stalo s AI roboty na evropském webu" (torumata.com, Hatteria labs s.r.o.). Článek je ve složce clanek/ (česky a anglicky).

Co bylo měřeno
- 22 846 nejnavštěvovanějších domén deseti evropských zemí (žebříček Tranco), z jedné domácí internetové přípojky v Česku.
- 14. 9. 2026 dvakrát (před změnou Cloudflare, druhé měření jako odhad běžného rozptylu), 16. 9. a 22. 9. (po změně).
- U každého webu: soubor robots.txt (blok pravidel vkládaný Cloudflare), domovská stránka s různými jmény návštěvníka (prohlížeč, vlastní jména, jména známých robotů), a další soubory.
- 23. 9. replikace chování sítě Cloudflare na 1 000 webech ze dvou dalších sítí jiných poskytovatelů.

Jak se v tom vyznat
- ZDROJE.txt: každé tvrzení z článku a soubor, který ho dokládá.
- metodika/: definice studie (RFC), prahy hypotéz, slovník.
- predpovedi/: předpovědi tří členů týmu zapsané a zapečetěné před každým měřením (commit-reveal); verdikty jsou ve vysledky/reveal-*.
- vysledky/: odhalení výsledků (reveal), plné reporty běhů, rozdíly před/po, chování sítě (Q8), replikace.
- data/: tabulky a JSON pro vlastní přepočet.
- zdroje/: citované externí zdroje (blogy Cloudflare, měření SeenSure, databáze hlášení) se snímky a otisky SHA-256.
- skripty/: měřidlo (cfprobe.py), statistiky (cfstats.py), denní sonda (mprobe.py), kontrola aditivity, skript replikace z jiné sítě.

Meze měření jsou popsané v článku (část „Jak jsme měřili a co měření neumí") a v každém reveal. Měříme program, který si jméno robota jen nastaví v hlavičce; jak Cloudflare zachází se skutečnými roboty firem OpenAI nebo Anthropic, se zvenčí změřit nedá.

Redakce: jména poskytovatelů připojení a hostingu jsou nahrazena označením „poskytovatel A/B/C", vlastní IP adresy a osobní údaje odstraněny. Zdrojová databáze měření (SQLite s uloženými těly odpovědí) není součástí repozitáře kvůli velikosti; na vyžádání.

Licence: LICENSE.txt. Kontakt: torumata.com.
