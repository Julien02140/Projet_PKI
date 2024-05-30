Pour exécuter et tester les différents scénarios du projet, il faut lancer les commandes suivantes dans 3 terminaux différents, 
à la racine du projet :

Terminal 1 : cd CA
Terminal 2 : cd vendeur
Terminal 3 : cd client

Ensuite pour chaque scénario lancer dans les terminaux et dans l’ordre des terminaux donné ci-dessus (terminal 1 puis 2 puis 3), 
numéro_scénario à remplacer par le numéro du scénario. La CA n’a besoin que d’être lancée une fois, 
et il faut stopper client et vendeur avec CTRL + C pour passer au prochain scénario. 
Ne pas lancer plusieurs clients ou plusieurs vendeurs en même temps ça fait des problèmes avec la file MQTT.

Terminal 1 : python ca.py
Terminal 2 : python vendeur numéro_scénario
Terminal 3 : python client numéro_scénario

Il y aura différents messages sur les terminaux qui permettent de comprendre les messages qui transitent.
