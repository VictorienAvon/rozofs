#READ ME
Ce plugin a été créé par deux étudiants de l'école d'ingénieurs Polytech Nantes, département informatique : 
Victorien Avon et Marine Garandeau qui ont été encadrés par Monsieur Dimitri Pertin.

## Installer Wireshark sur sa machine.\
sudo apt-get update\
sudo apt-get install git\
sudo apt-get install autoconf\
sudo apt-get install libtool\
sudo apt-get install pkg-config\
sudo apt-get install bison\
sudo apt-get install flex\
sudo apt-get install g++\
sudo apt-get install qt5-default\
sudo apt-get install libgtk-3-dev\
sudo apt-get install libcap-dev\
git clone git://github.com/wireshark/wireshark\
cd wireshark\
\

./autogen.sh\ 
./configure\ 
make\
sudo make install\
sudo ldconfig\
WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1\
wireshark-gtk&\
\
Ici nous compilons le logiciel Wireshark, sans l'ajout de notre plugin RozoFS. Nous n'avons que descendu les sources de Wireshark.

## Création du dossier
mkdir wireshark/plugins/rozofs
Copier l'ensemble des sources présentes sur GitHub dans ce dossier, à l'exception des fichiers 
- Custum.m4
- Custum.make
- Custum.nmake\
qui seront copiés directement dans le dossier wireshark/plugins afin d'indiquer la nature non permanente de notre plugin. Celui-ci sera en effet utilisé en interne
mais ne sera pas récupéré lors de l'installation de Wireshark.

## Lancer l'ensemble des commandes suivantes afin d'intégrer le plugin à Wireshark: 
make\
sudo make install\
sudo ldconfig\
WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1\
wireshark-gtk&\
\

En cas de création de nouveau fichier, y apporter en amont les commandes suivantes :\
./autogen.sh \
./configure\




