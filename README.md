# Virologie &amp; Malware - Projet Yharnam - École 2600 <!-- omit in toc -->

> *“Wretched outsider! Tryin’ to fool me to open this door?”*

- [Objectif](#objectif)
- [Fonctionnalités](#fonctionnalités)
- [Limitations](#limitations)
- [Compilation](#compilation)
  - [Prérequis](#prérequis)
  - [Compilation](#compilation-1)
  - [Cibles Makefile](#cibles-makefile)
    - [Cibles principales (.exe)](#cibles-principales-exe)
    - [Cibles “phony”](#cibles-phony)
  - [Flags de compilation](#flags-de-compilation)
  - [Exemples](#exemples)
- [Comportement du malware](#comportement-du-malware)
  - [Injection](#injection)
  - [Payload](#payload)
    - [Structure](#structure)
    - [Mesures de protection](#mesures-de-protection)
    - [Anti-debug](#anti-debug)

## Objectif

Le but principal de ce projet était de créer un programme permettant d'injecter un code malveillant dans un exécutable Windows (fichier PE x64). Pour nos besoins, la payload injectée est une simple MessageBox.

## Fonctionnalités

En plus de la simple injection de code, notre projet permet d'infecter tous les fichiers .exe du répertoire courant.
Il obfusque également les chaînes de caractères utilisées par le malware, de manière à ce qu'elles ne soient pas directement visibles dans le code.
De plus, le malware détecte si l'exécutable est déjà infecté, et ne l'infecte pas une seconde fois, grâce à une signature placée au début du payload. Il évite aussi de s'infecter lui-même.
Enfin, il tente de détecter s'il est exécuté dans un environnement de debug, et ne s'exécute pas dans ce cas, laissant directement la main à l'exécutable original.

Des flags de compilation permettent de changer le comportement du malware :

- Activer le mode debug (affiche des informations supplémentaires à l'exécution du payload)
- Limiter l'infection aux fichiers dont le nom commence par “`!`”, pour éviter d'infecter des exécutables importants par erreur
- Désactiver la vérification de l'infection, pour tester le malware sur un fichier déjà infecté
- Désactiver l'anti-debug, pour faciliter le développement

Une attention particulière a été portée à la taille du payload, pour qu'elle soit la plus petite possible, grâce à de nombreux tests sur le code C++, et des options de compilation privilégiant une taille de code minimale (`/O2`, `/Ob3`, `/GS-`, `/Os`, `/Oi`, `/Zl`).

## Limitations

Le malware ne fonctionne que sur des fichiers .exe 64 bits (PE32+) qui ne vérifient pas leur intégrité (par exemple, les exécutables du système Windows ne peuvent pas être infectés, car ils crashent à l'exécution lors du chargement par le loader PE, avant même que le point d'entrée soit atteint).

## Compilation

Le projet utilise un Makefile et est compilé avec `nmake`, qui est inclus dans Visual Studio Build Tools.

### Prérequis

La compilation du projet a été testée avec les outils suivants :

- Développement desktop en C++ de Microsoft Visual Studio 2022
  - MSVC v143
  - Windows SDK 10.0.22621.0

### Compilation

Pour compiler le projet, il faut tout d'abord ouvrir une console *x64 Native Tools Command Prompt for VS 2022*. Ensuite, il suffit de se rendre dans le répertoire du projet et de lancer la commande suivante :

```batch
nmake
```

Cela va créer un programme `inject.exe`, qui permet d'injecter le malware dans le .exe passé en argument.

### Cibles Makefile

#### Cibles principales (.exe)

- `inject` : Compile l'injecteur (`inject.exe`)
- `payload` : Compile un programme de test (`payload.exe`) pour lancer directement le payload en mode non-injecté, avec un mode debug activé (trace les appels à `GetDll`/`GetFunc`)
- `readpe` : Compile un programme (`readpe.exe`) pour afficher les informations d'un fichier PE
- `hello` : Compile un simple programme Hello World (`hello.exe`) pour tester l'infection

#### Cibles “phony”

- `all` : Compile l'injecteur (cible par défaut) [alias de `inject`]
- `clean` : Supprime les fichiers de compilation (.obj, .pdb, .ilk)
- `fclean` : Supprime les fichiers de compilation et les .exe [dépend de `clean`]
- `dummy` : Compile `hello.exe` et le copie plusieurs fois (`dummy.exe`, `!dummy.exe`, `!1dummy.exe`, `!2dummy.exe`) pour tester l'infection sur plusieurs fichiers [dépend de `hello`]
- `run` : Compile l'injecteur et le lance sur `dummy.exe` [dépend de `inject`, `dummy`]
- `run_payload` : Compile `payload.exe` et le lance [dépend de `payload`, `dummy`]
- `run_readpe` : Compile l'injecteur et le lance sur `dummy.exe`, puis compile `readpe.exe` et le lance sur le `dummy.exe` infecté [dépend de `run`, `readpe`]
- `check` : Compile l'injecteur et le lance sur `dummy.exe`, puis exécute `dummy.exe` pour vérifier que le malware fonctionne correctement [dépend de `run`]

### Flags de compilation

Les flags de compilation disponibles sont :

- `PL_DEBUG=1` : Active le mode debug du payload (affiche les fichiers en cours d'infection)
- `NEED_BANG=1` : Limite l'infection aux fichiers dont le nom commence par “`!`”
- `SKIP_SIGN=1` : Désactive la vérification de l'infection (permet les infections multiples)
- `NO_ANTIDBG=1` : Désactive l'anti-debug

Il est possible de les combiner pour activer plusieurs options en même temps, et de noter `=0` pour désactiver un flag (comme s'il n'était pas défini).

### Exemples

- Compiler l'injecteur, le lancer sur `dummy.exe` et exécuter `dummy.exe`, avec le mode debug du payload et la limitation aux fichiers commençant par “`!`”, la vérification de l'infection et l'anti-debug activés :

  ```batch
  nmake check PL_DEBUG=1 NEED_BANG=1 SKIP_SIGN=0 NO_ANTIDBG=0
  ```

  Les exécutables suivants seront créés et potentiellement infectés :

  - `inject.exe` (pas infecté)
  - `hello.exe` (pas infecté)
  - `dummy.exe` (infecté en premier par `inject.exe`, ignoré par lui-même)
  - `!dummy.exe` (infecté par la suite par `dummy.exe`)
  - `!1dummy.exe` (infecté par la suite par `dummy.exe`)
  - `!2dummy.exe` (infecté par la suite par `dummy.exe`)

- Compiler l'injecteur et `readpe.exe`, lancer l'injecteur sur `dummy.exe` et exécuter `readpe.exe` sur `dummy.exe` infecté, sans le mode debug du payload ni la limitation aux fichiers commençant par “`!`”, mais avec la vérification de l'infection et l'anti-debug activés :

  ```batch
  nmake run_readpe
  ```

## Comportement du malware

Le code malveillant (payload) est stocké dans une section à part (`injected`), avec ses variables statiques. Cela permet de facilement le rendre indépendant de sa position en mémoire, et de le copier pour l'infection.

### Injection

Pour infecter un exécutable, l'injecteur ouvre d'abord le fichier en lecture pour vérifier s'il s'agit bien d'un PE 64 bits, et qu'il n'a pas déjà été infecté (grâce à la constante `0xBAADC0DE` placée au début du payload, juste avant son point d'entrée).

Ensuite, il rouvre le fichier en lecture/écriture pour injecter le payload à la fin de la dernière section.
Les valeurs de la taille du payload et de l'offset de son point d'entrée, ainsi que l'offset du point d'entrée original, sont définis dans les variables globales du payload. La dernière section est rendue exécutable et marquée comme contenant du code, et son flag `DISCARDABLE` est retiré pour éviter qu'elle soit déchargée par le loader.

Enfin, il modifie le point d'entrée (`AddressOfEntryPoint`) pour qu'il pointe sur le début du payload, et met à jour différents champs du header pour que le fichier reste valide (`VirtualSize`, `SizeOfRawData`, `SizeOfCode`, `SizeOfImage`).
La taille finale du fichier, ainsi que la nouvelle taille de la section infectée, sont alignées sur la valeur `FileAlignment` du header (généralement 512 octets), tandis que la valeur de `SizeOfImage` est alignée sur `SectionAlignment` (généralement 4096 octets, correspondant à la taille d'une page mémoire).

### Payload

#### Structure

Le payload est composé de trois parties : deux *stubs* en assembleur, et le code malveillant en C++.
Le stub d'entrée (`payload_begin.asm`) est mis en premier, et se charge de mettre en place les adresses relatives et de créer la pile pour appeler le code C++. Une fois le code C++ terminé, il appelle le point d'entrée original du programme.
Le stub de sortie (`payload_end.asm`) contient simplement un symbole pour calculer la taille du payload.

Le code C++, une fois compilé en .obj, est placé en sandwich entre les deux *stubs*.

Il a deux fonctions : répandre le malware dans les autres exécutables du répertoire courant, et exécuter la charge malveillante.
Dans notre cas, les exécutables infectés affichent simplement une MessageBox avec le titre “`Yharnam`” et le message “`~ Fear the Old Blood ~`”.

#### Mesures de protection

Tous les appels à des fonctions de l'API Win32 sont effectués de manière dynamique, en récupérant les adresses des DLL et fonctions à l'exécution. Cela permet d'être indépendant des adresses en mémoire, et de ne pas avoir de table d'imports suspecte.
Afin de limiter les chaînes de caractères dans le code, les noms des DLL et fonctions sont hashés, et les adresses sont récupérées à partir de ces hash à l'exécution.
Le hashing dans le code est effectué à la compilation (grâce à une *template* et au mot-clé `constexpr` de C++), de sorte que le code compilé ne contienne que des valeurs numériques pour les appels à l'API.

Les autres chaînes de caractères utilisées par le malware sont obfusquées, pour éviter qu'elles soient directement visibles avec des outils comme `strings`. Elles sont déchiffrées à l'exécution, et stockées dans des variables statiques dans la section `injected`.
Pour des raisons de simplicité, le chiffrement est basique : chaque caractère est XORé avec la valeur 0x42, puis ses bits sont décalés de 5 vers la gauche de façon circulaire (ROTL).

Le chiffrement est effectué à la compilation, grâce à des *templates* C++, des structures, et les mots-clés `constexpr` et `consteval`. Ainsi, le code compilé ne contient que les chaînes obfusquées.

#### Anti-debug

Avant d'exécuter quoi que ce soit, le malware essaie de déterminer s'il est en train d'être debuggé. Pour cela, il utilise plusieurs valeurs présentes dans le *Process Environment Block* (PEB) :

- `BeingDebugged` : Indique si le processus est en train d'être debuggé, mais peut facilement être modifié par un debugger
- `NumberOfProcessors` : Nombre de processeurs logiques ; s'il est inférieur ou égal à 2, le processus est probablement en train d'être debuggé, ou exécuté dans une machine virtuelle
- `NtGlobalFlag` : Les debuggers définissent souvent les flags `FLG_HEAP_ENABLE_TAIL_CHECK` (0x10), `FLG_HEAP_ENABLE_FREE_CHECK` (0x20), et `FLG_HEAP_VALIDATE_PARAMETERS` (0x40), mais cela peut varier

Si le malware détecte qu'il est en train d'être debuggé, il ne fait rien et va directement au point d'entrée original du programme.
Il y a également la possibilité de faire crasher le programme, dans des lignes commentées du code au début de `payload.cpp` :

- `__debugbreak();` : Insère un `int 3` (0xCC) dans le code, qui est une instruction de breakpoint pour les debuggers
- `__fastfail(FAST_FAIL_FATAL_APP_EXIT);` : Provoque un arrêt brutal du programme (instruction `int 0x29`)
- `((PVOID(*)())NULL)();` : Appelle `NULL` comme une fonction, provoquant un segfault

On pourrait aussi imaginer d'autres méthodes pour détecter un environnement de debug, comme la présence de certains processus ou drivers, ou la modification de certaines valeurs en mémoire.
De plus, au lieu de ne rien faire ou de crasher, le payload pourrait induire en erreur le debugger, en adoptant un comportement différent.
