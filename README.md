                                     _____  _____  _____  _      ___    _____  _    _ 
                                    (_   _)(  _  )(  _  )( )    (  _`\ (  _  )( )  ( )
                                      | |  | ( ) || ( ) || |    | (_) )| ( ) |`\`\/'/'
                                      | |  | | | || | | || |  _ |  _ <'| | | |  >  <  
                                      | |  | (_) || (_) || |_( )| (_) )| (_) | /'/\`\ 
                                      (_)  (_____)(_____)(____/'(____/'(_____)(_)  (_)



# 🛠 Introduction

La Société X, avec son équipe composée de Simon ICHARD, Melvin MORIN et Marc Cibrian ZARA, est heureuse de présenter sa **toolbox automatisée pour Application WEB**. Cet outil est notre réponse aux besoins croissants de solutions de cybersécurité intelligentes et efficaces, conçu pour renforcer les défenses des systèmes informatiques contre les attaques malveillantes.

## 🌟 Fonctionnalités de la Toolbox

Structurée autour de deux sections centrales, `Scans` et `PenTest`, notre toolbox est équipée pour mener à bien un audit de sécurité :

### 🔍 Section Scans
- **Scan Hôte** : Identifie les hôtes actifs et collecte des données vitales.
- **Scan Réseau** : Dresse un plan détaillé du réseau, soulignant les services et dispositifs à risque.
- **Scan Répertoire** : Explore les serveurs web pour découvrir des répertoires cachés et des fichiers sensibles.

### 🛡 Section PenTest
- **Brute Force RDP** : Teste la résistance des systèmes contre les attaques par force brute sur le protocole RDP.
- **Web Crawler** : Inventorie systématiquement les ressources web pour préparer les tests de vulnérabilité.
- **Scan Sous Domain** : Détecte les sous-domaines dissimulés qui peuvent exposer des vulnérabilités.
- **Exploitations CVE** : Intègre des stratégies d'exploitation pour des vulnérabilités spécifiques répertoriées dans les CVE mentionnés.
- **HTTP Verb Tampering** : Teste la conformité des serveurs web aux méthodes HTTP et révèle d'éventuelles configurations défaillantes.

## ⚙️ Installation et Configuration

### Prérequis

- Installer Docker et Docker Compose, nécessaires pour exécuter l'application :

```bash
sudo apt update
sudo apt install docker.io docker-compose
```
Ajouter votre utilisateur au groupe docker pour exécuter Docker sans sudo :

```bash
sudo usermod -aG docker $USER
newgrp docker
```

- 📦 Clonage du dépôt Github
    - Utilisez la commande git clone pour télécharger le contenu du dépôt Github à l’adresse spécifiée. Cela crée une copie locale du projet sur votre machine.

```bash
git clone https://github.com/Sleeper14/Projet-Toolbox.git
```

- 📂 Accès au dossier du projet
    - En utilisant la commande “cd Projet/Application”, vous vous rendez dans le dossier de notre Toolbox.

```bash
cd Projet-Toolbox/Application
```

- 🐳 Exécution de Docker
    - La commande “docker-compose up -d —build” permet de construire à partir de notre fichier "docker-compose.yml" et du dockerfile notre conteneur ou sera éxecuter notre Toolbox.
    - Ensuite, la commande “docker-compose exec webapp python manage.py createsuperuser” crée un superutilisateur pour l’application Django qui va nou permettre de nous connecter à l'interface de la Toolbox.
    - ⚠️ Attention l'application peut prendre un peu plus de 5min à s'installer

```bash
docker-compose up -d --build
```
```bash
docker-compose exec webapp
```
```bash
docker-compose exec webapp python manage.py createsuperuser
```

🌐 Accès à l’interface web de la Toolbox
    - Pour accéder à l’interface web, vous devez ouvrir un navigateur et saisir l’URL ci-dessous

```bash
http://127.0.0.1
```

## 📚 Documentation Complémentaire

Notre projet est accompagné d'une documentation détaillée pour faciliter son utilisation, son installation, et la compréhension de ses composants. 

Vous trouverez un fichier `README` spécifique dans chaque sous-dossier correspondant, qui fournit des informations et des instructions détaillées pour les aspects suivants du projet :

- 📖 [**Tuto Utilisation**](https://github.com/Sleeper14/Projet-Toolbox/tree/main/Doc%20d'utilisation): Ce dossier contient des instructions détaillées sur comment utiliser la toolbox, avec des exemples et des explications pour chaque outil.

- 🛠 [**Outil Utilisé**](https://github.com/Sleeper14/Projet-Toolbox/tree/main/Outil%20Utilis%C3%A9): Ici, vous trouverez des détails sur les outils et les bibliothèques utilisés dans le cadre du projet.
- 📋 [**Gestion Projet**](https://github.com/Sleeper14/Projet-Toolbox/tree/main/Gestion%20de%20Projet): Ce dossier offre un aperçu de la gestion de projet, son organisation.

  
