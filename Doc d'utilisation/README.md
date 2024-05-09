# 🛠️ Description

Ce projet est une toolbox pour le pentest d'**Applications WEB**. Il comprend deux sections principales : **Scans** et **Pentest**.

## 🔍 Scans

Cette section comprend les fonctionnalités suivantes :

1. **Scan Hôte** : Cette fonction permet de scanner un hôte spécifique pour identifier les ports ouverts, les services en cours d'exécution, etc.
2. **Scan Réseau** : Cette fonction permet de scanner un réseau entier pour identifier les hôtes actifs, les ports ouverts, etc.
3. **Scan Répertoire** : Cette fonction permet de scanner les répertoires d'un site web pour identifier les fichiers et répertoires cachés.

## 🛡️ Pentest

Cette section comprend les fonctionnalités suivantes :

1. **Brute Force RDP** : Cette fonction permet d'effectuer une attaque par force brute sur le protocole RDP pour identifier les identifiants valides.
2. **Web Crawler (Robot d'indexation)** : Cette fonction permet d'explorer un site web pour identifier les liens, les formulaires, etc.
3. **Scan Sous Domaine** : Cette fonction permet d'identifier les sous-domaines d'un domaine spécifique.
4. **Exploitation F5 BIG-IP RCE : CVE-2022-1388** : Cette fonction permet de tester la vulnérabilité CVE-2022-1388 sur un hôte spécifique.
5. **Exploitation Apache Path Traversal : CVE-2021-41773** : Cette fonction permet de tester la vulnérabilité CVE-2021-41773 sur un hôte spécifique disposant d'un apache 2.4.49 ou anterieur.
6. **HTTP Verb Tampering** : Cette fonction permet de tester les vulnérabilités associées au changement de verbes HTTP.

## 📖 Utilisation

#### ⚠️ L'utilisation de certains outils peut prendre un certain temps lors de l'exécution.


Pour utiliser cette toolbox, suivez les étapes ci-dessous :

1. Tout d'abord il faudra se connecter à l'application avec les identifiants créé lors de l'installation de la toolbox

![Images](Images/login.png)

2. Scan Hôte (⚠️ Attention ce scan peut prendre un certain temps il ne faut donc pas quitter la page avant qu'il soit fini !!)

![Images](Images/Scan_hote.png)

  - Résultat : on peut télécharger le rapport en pdf de notre scan
    
![Images](Images/rapport.png)

3. Scan Réseau

![Images](Images/Scan_reseau.png)

  - Résultat : on peut télécharger le rapport en pdf de notre scan
    
![Images](Images/rapport.png)


4. Scan Répertoire

![Images](Images/Scan_repertoire.png)

- Résultat(sur chrome) : On récupère les dossiers du site ciblé
    
![Images](Images/scan_dir.png)

5. Brute Force RDP

![Images](Images/Brute_force_rdp.png)


6. Web Crawler (Robot d'indexation)

![Images](Images/web_crawler.png)

- Résultat : On récupère les URLs indéxées du site ciblé
    
![Images](Images/web_crawler_result.png)


7. Scan Sous Domaine

![Images](Images/domain.png)

- Résultat : on récupère les sous domains disponibles
    
![Images](Images/domain_result.png)


8. Exploitation F5 BIG IP RCE

![Images](Images/Exploitation_F5_BIG_IP_RCE.png)


9. Exploitation Apache Path Traversal

![Images](Images/apache.png)

- Résultat : on récupère bien le fichier `passwd` de notre machine vulnérable
    
![Images](Images/apache_result.png)


10. HTTP Verb tampering 

![Images](Images/verb_tampering.png)

- Résultat : on récupère les requêtes http autorisées
    
![Images](Images/verb_tampering_result.png)
