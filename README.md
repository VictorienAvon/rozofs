# rozofs
Plugin créé par deux étudiants de Polytech Nantes en département informatique : Victorien Avon et Marine Garandeau qui ont été encadré par Monsieur Dimitri Pertin
Installer Wireshark sur sa machine.

Copier l'ensemble des fichiers présents sur le GitHub dans un dossier nommé RozoFS dans le dossier plugin de Wireshark.

Lancer l'ensemble des commandes suivantes :
./autogen.sh 
./configure // Crée automatiquement le makefile
make
sudo make install
sudo ldconfig
WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1
wireshark-gtk&




